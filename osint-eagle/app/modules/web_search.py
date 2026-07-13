"""
web_search — OSINT Eagle
Recherche web via SearXNG auto-hébergé (métamoteur local, API JSON).

On interroge une API JSON locale légitime (SearXNG dans Docker) qui agrège
plusieurs moteurs (Google, Bing, DuckDuckGo, Brave, Mojeek). Aucun scraping ni
contournement de captcha : SearXNG gère ses propres moteurs. L'URL de base est
lue dans l'env SEARXNG_URL (défaut http://localhost:8888).

(L'ancien canal de scraping Bing/Playwright, qui se faisait servir un challenge
anti-bot Cloudflare, a été retiré : ce module ne dépend plus de Playwright.)
"""

import asyncio
import os
from typing import Callable

import httpx

from app.core.logger import logger
from app.models.result import ModuleType, OsintResult, ResultCategory, RiskLevel
from app.models.search import NameProfile

__all__ = ["run_all_dorks", "run_manual_dork"]

_SENSITIVE_KEYWORDS = [
    "email", "@", "phone", "téléphone", "adresse", "mobile", "numéro",
]

_CATEGORY_MAP = {
    "identity": ResultCategory.IDENTITY,
    "contact": ResultCategory.CONTACT,
    "professional": ResultCategory.PROFESSIONAL,
    "social": ResultCategory.SOCIAL,
    "technical": ResultCategory.TECHNICAL,
    "documents": ResultCategory.DOCUMENT,
    "news": ResultCategory.IDENTITY,
    "academic": ResultCategory.PROFESSIONAL,
}

_MAX_RESULTS_PER_DORK = 5
_MAX_CONCURRENT_DORKS = 2
_RATE_LIMIT_DELAY = 2.0
# Garde-fou par dork : on n'attend jamais indéfiniment une requête SearXNG.
_DORK_TIMEOUT = 90  # secondes

# Dorks toujours prioritaires (identité, email, PDF) : exécutés en premier
# quoi qu'il arrive. S'ils ne ramènent presque rien, l'empreinte web est
# faible et les dorks secondaires (souvent à 0 résultat) sont coûteux pour
# rien : on les saute.
_FIXED_PRIORITY_DORK_KEYS = {("identity", 0), ("contact", 0), ("documents", 0)}

# Dorks "site:plateforme" : prioritaires uniquement si social_checker a
# confirmé un compte sur cette plateforme en amont (cf. confirmed_platforms).
# Sans confirmation disponible (None/vide), on retombe sur github+linkedin
# en dur pour ne pas changer le comportement par défaut.
_PLATFORM_DORK_KEYS = {
    "github.com": ("technical", 0),
    "linkedin.com": ("professional", 0),
    "instagram.com": ("social", 1),
    "twitter.com": ("social", 0),
    "x.com": ("social", 0),
    "facebook.com": ("social", 2),
}
_DEFAULT_PLATFORM_DOMAINS = ("github.com", "linkedin.com")

_MIN_PRIORITY_RESULTS = 3


def _resolve_priority_keys(confirmed_platforms: list[str] | None) -> set[tuple[str, int]]:
    """Combine les dorks fixes avec les dorks plateforme confirmés par social_checker."""
    keys = set(_FIXED_PRIORITY_DORK_KEYS)

    if not confirmed_platforms:
        domains = _DEFAULT_PLATFORM_DOMAINS
        logger.info("web_search : confirmed_platforms vide/absent, dorks plateformes par défaut = github+linkedin")
    else:
        domains = {p.lower() for p in confirmed_platforms}
        logger.info(f"web_search : plateformes confirmées reçues = {sorted(domains)}")

    for domain in domains:
        key = _PLATFORM_DORK_KEYS.get(domain)
        if key:
            keys.add(key)

    logger.info(f"web_search : dorks prioritaires résolus = {sorted(keys)}")
    return keys


def _evaluate_risk(category: ResultCategory, snippet: str) -> tuple[RiskLevel, bool]:
    snippet_lower = (snippet or "").lower()
    if any(keyword in snippet_lower for keyword in _SENSITIVE_KEYWORDS):
        return RiskLevel.HIGH, True
    if category in (ResultCategory.PROFESSIONAL, ResultCategory.SOCIAL):
        return RiskLevel.MEDIUM, False
    return RiskLevel.LOW, False


# ─────────────────────────────────────────────────────────────────────────────
# CANAL ACTIF : SearXNG auto-hébergé (métamoteur local, API JSON).
# ─────────────────────────────────────────────────────────────────────────────
_SEARXNG_URL = os.environ.get("SEARXNG_URL", "http://localhost:8888").rstrip("/")
_SEARXNG_TIMEOUT = 15.0
# Moteurs généralistes fiables interrogés (redondance = robustesse). Doivent être
# activés côté settings.yml. Jeu figé pour limiter la variance entre deux runs.
_SEARXNG_ENGINES = "google,bing,duckduckgo,brave,mojeek"


async def _search_searxng(query: str, max_results: int) -> list[dict]:
    """Interroge l'API JSON de SearXNG et renvoie une liste de dicts
    {title, href, body}.

    Ne lève jamais : en cas de problème (injoignable, HTML au lieu de JSON,
    statut inattendu), logge un WARNING clair et renvoie une liste vide.
    """
    params = {"q": query, "format": "json", "engines": _SEARXNG_ENGINES}
    search_url = f"{_SEARXNG_URL}/search"

    try:
        async with httpx.AsyncClient(timeout=_SEARXNG_TIMEOUT) as client:
            resp = await client.get(search_url, params=params)
    except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout) as e:
        logger.warning(
            f"web_search : SearXNG injoignable sur {_SEARXNG_URL} — "
            f"vérifier que le conteneur Docker tourne ({type(e).__name__})"
        )
        return []
    except httpx.HTTPError as e:
        logger.warning(f"web_search : erreur HTTP SearXNG pour '{query}' : {e}")
        return []

    # 429 : un moteur amont (ou le limiter) a throttlé. On ne crashe pas ; on
    # tente quand même de récupérer ce que SearXNG a pu agréger.
    if resp.status_code == 429:
        logger.warning(
            f"web_search : SearXNG a renvoyé 429 (rate limit amont) pour '{query}', "
            "récupération partielle"
        )
    elif resp.status_code != 200:
        logger.warning(f"web_search : SearXNG statut {resp.status_code} pour '{query}'")
        return []

    # Format JSON pas activé dans settings.yml → SearXNG sert du HTML.
    content_type = resp.headers.get("content-type", "")
    if "application/json" not in content_type:
        logger.warning(
            "web_search : SearXNG a renvoyé du HTML, le format JSON n'est pas activé "
            "dans settings.yml (section search.formats : ajouter 'json')"
        )
        return []

    try:
        data = resp.json()
    except Exception as e:
        logger.warning(f"web_search : réponse SearXNG illisible pour '{query}' : {e}")
        return []

    raw_results = data.get("results") or []
    items: list[dict] = []
    seen: set[str] = set()
    for entry in raw_results:
        href = entry.get("url")
        title = entry.get("title")
        if not href or not title or href in seen:
            continue
        seen.add(href)
        items.append({"title": title, "href": href, "body": entry.get("content")})
        if len(items) >= max_results:
            break
    return items


async def _run_single_dork(
    semaphore: asyncio.Semaphore,
    category_key: str,
    query: str,
    search_id: str,
    callback: Callable,
    seen_urls: set,
    results: list,
):
    category = _CATEGORY_MAP.get(category_key, ResultCategory.IDENTITY)

    async with semaphore:
        try:
            raw_results = await asyncio.wait_for(
                _search_searxng(query, _MAX_RESULTS_PER_DORK),
                timeout=_DORK_TIMEOUT,
            )
        except asyncio.TimeoutError:
            logger.warning(f"web_search : timeout sur le dork '{query}'")
            raw_results = []
        except Exception as e:
            logger.warning(f"web_search : erreur sur le dork '{query}' : {e}")
            raw_results = []

        for item in raw_results:
            url = item.get("href")
            if not url or url in seen_urls:
                continue
            seen_urls.add(url)

            snippet = (item.get("body") or "")[:500]
            risk_level, is_sensitive = _evaluate_risk(category, snippet)

            result = OsintResult(
                search_id=search_id,
                module=ModuleType.WEB_SEARCH,
                category=category,
                title=item.get("title") or url,
                url=url,
                snippet=snippet,
                raw_data={"dork": query, "dork_category": category_key},
                risk_level=risk_level,
                is_sensitive=is_sensitive,
            )
            results.append(result)
            try:
                callback(result)
            except Exception as e:
                logger.warning(f"web_search : erreur callback : {e}")

        await asyncio.sleep(_RATE_LIMIT_DELAY)


async def run_all_dorks(
    profile: NameProfile,
    search_id: str,
    callback: Callable,
    priority_only: bool = False,
    city_override: str | None = None,
    confirmed_platforms: list[str] | None = None,
    browser=None,
    semaphore: asyncio.Semaphore | None = None,
) -> list[OsintResult]:
    """Exécute tous les dorks générés par name_engine via SearXNG (API JSON locale).

    `semaphore` peut être partagé par l'orchestrateur pour plafonner la concurrence
    web globale d'une recherche. `browser` est conservé pour rétrocompatibilité de
    signature (l'orchestrateur le passe encore) mais n'est plus utilisé : le canal
    web ne dépend plus de Playwright.
    """
    semaphore = semaphore or asyncio.Semaphore(_MAX_CONCURRENT_DORKS)
    seen_urls: set = set()
    results: list[OsintResult] = []

    priority_keys = _resolve_priority_keys(confirmed_platforms)

    def _apply_city(query: str) -> str:
        return f'{query} "{city_override}"' if city_override else query

    priority_specs: list[tuple[str, str]] = []
    secondary_specs: list[tuple[str, str]] = []
    for category_key, queries in profile.search_queries.items():
        for idx, query in enumerate(queries):
            target = priority_specs if (category_key, idx) in priority_keys else secondary_specs
            target.append((category_key, _apply_city(query)))

    priority_tasks = [
        _run_single_dork(semaphore, category_key, query, search_id, callback, seen_urls, results)
        for category_key, query in priority_specs
    ]
    logger.info(f"web_search : exécution de {len(priority_tasks)} dorks prioritaires pour '{profile.full_name}'")
    await asyncio.gather(*priority_tasks)

    if priority_only:
        logger.info("web_search : priority_only=True, dorks secondaires ignorés")
    elif len(results) >= _MIN_PRIORITY_RESULTS:
        secondary_tasks = [
            _run_single_dork(semaphore, category_key, query, search_id, callback, seen_urls, results)
            for category_key, query in secondary_specs
        ]
        logger.info(f"web_search : exécution de {len(secondary_tasks)} dorks secondaires pour '{profile.full_name}'")
        await asyncio.gather(*secondary_tasks)
    else:
        logger.warning("web_search : Aucun résultat web trouvé, empreinte faible")

    logger.info(f"web_search : {len(results)} résultats uniques trouvés")
    return results


async def run_manual_dork(
    query: str,
    search_id: str,
    callback: Callable,
    category_key: str = "identity",
    browser=None,
    semaphore: asyncio.Semaphore | None = None,
) -> list[OsintResult]:
    """Exécute un unique dork manuel (ex: numéro de téléphone, employeur) via SearXNG.

    `semaphore` peut être partagé par l'orchestrateur (voir run_all_dorks).
    `browser` est conservé pour rétrocompatibilité de signature mais inutilisé
    (le canal web ne dépend plus de Playwright).
    """
    semaphore = semaphore or asyncio.Semaphore(1)
    seen_urls: set = set()
    results: list[OsintResult] = []

    await _run_single_dork(semaphore, category_key, query, search_id, callback, seen_urls, results)

    return results
