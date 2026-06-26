"""
web_search — OSINT Eagle
Recherche web via scraping Bing avec navigateur headless (Playwright).

Bing bloque les requêtes HTTP classiques (httpx/requests) en leur servant une
page vide ou mal localisée : un vrai navigateur est nécessaire pour obtenir le
HTML réel des résultats. Même avec Playwright, Bing applique une détection
anti-bot intermittente (page de défi resservie de façon aléatoire) : on
retente donc plusieurs fois avec une page fraîche avant d'abandonner un dork.
"""

import asyncio
import os
import random
import urllib.parse
from pathlib import Path
from typing import Callable

import httpx
from playwright.async_api import Browser, Error as PlaywrightError, async_playwright

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

# Dorks toujours prioritaires (identité, email, PDF) : exécutés en premier
# quoi qu'il arrive. S'ils ne ramènent presque rien, l'empreinte web est
# faible et les dorks secondaires (souvent à 0 résultat) sont coûteux pour
# rien (3 tentatives x 30s chacun) : on les saute.
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

_BING_URL = "https://www.bing.com/search"
_MAX_ATTEMPTS = 3
_RETRY_DELAY = 2.5
_GOTO_TIMEOUT = 20000  # ms
_RESULT_WAIT_TIMEOUT = 5000  # ms
_DORK_TIMEOUT = 90  # secondes, couvre toutes les tentatives d'un dork

# Sélecteur d'extraction des résultats organiques Bing (centralisé pour que le
# mode debug puisse logguer celui réellement utilisé).
_BING_RESULT_SELECTOR = ".b_algo"

# ─────────────────────────────────────────────────────────────────────────────
# MODE DEBUG TEMPORAIRE — diagnostic Bing/Playwright (0 résultat en headless).
# À RETIRER une fois la cause confirmée. Se déclenche pour la SEULE requête de
# test contenant à la fois "bouzekri" et "ilyes" (la recherche en phrase exacte
# "bouzekri ilyes"). Produit : URL finale, debug_bing.html, debug_bing.png,
# nombre d'éléments matchés par le sélecteur, et détection de wall/captcha.
# ─────────────────────────────────────────────────────────────────────────────
_DEBUG_BING_ENABLED = True
_DEBUG_OUTPUT_DIR = Path(__file__).resolve().parents[2]  # racine du projet osint-eagle
_DEBUG_WALL_TERMS = (
    "consent", "accept", "j'accepte", "cookie", "avant de continuer",
    "captcha", "verifying", "are you a robot", "blocked",
)
# Garde-fou : ne dumper qu'UNE fois (la 1re tentative) même si le dork est retenté.
_debug_dumped = False

# ─────────────────────────────────────────────────────────────────────────────
# ⚠️ CODE BING/PLAYWRIGHT DÉPRÉCIÉ — CONSERVÉ TEMPORAIREMENT POUR ROLLBACK.
# Plus appelé par run_all_dorks / run_manual_dork (qui passent par SearXNG).
# Inclut le mode debug Bing. À SUPPRIMER (avec _DEBUG_BING_ENABLED et les fichiers
# debug_bing.*) lors de l'étape de nettoyage, UNE FOIS SearXNG validé.
# ─────────────────────────────────────────────────────────────────────────────
_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
]


def _random_ua() -> str:
    return random.choice(_USER_AGENTS)


def _build_bing_url(query: str, count: int) -> str:
    # setlang/cc forcent le résultat en anglais US : sans ça, Bing localise
    # parfois la recherche selon la géolocalisation IP et renvoie des
    # résultats hors-sujet.
    params = {"q": query, "count": count, "setlang": "en-US", "cc": "US"}
    return f"{_BING_URL}?{urllib.parse.urlencode(params)}"


def _is_debug_query(query: str) -> bool:
    """True pour la SEULE requête de diagnostic ("bouzekri ilyes", tout ordre)."""
    if not _DEBUG_BING_ENABLED:
        return False
    q = (query or "").lower()
    return "bouzekri" in q and "ilyes" in q


async def _debug_dump_bing(page, query: str, url: str) -> None:
    """Produit les artefacts de diagnostic pour une page Bing : URL réelle, HTML
    complet, screenshot pleine page, nombre d'éléments matchés et détection wall.

    Absorbe toute erreur : le diagnostic ne doit jamais casser la recherche.
    """
    global _debug_dumped
    if _debug_dumped:
        return
    _debug_dumped = True

    # Attente de chargement réelle (networkidle si possible) avant capture.
    try:
        await page.wait_for_load_state("networkidle", timeout=8000)
    except PlaywrightError:
        logger.warning("[DEBUG bing] networkidle non atteint (timeout), capture quand même")
    await page.wait_for_timeout(3000)

    logger.warning(f"[DEBUG bing] query de test : {query!r}")
    logger.warning(f"[DEBUG bing] URL construite : {url}")
    try:
        logger.warning(f"[DEBUG bing] URL réelle (après redirections) : {page.url}")
        logger.warning(f"[DEBUG bing] <title> : {(await page.title())!r}")
    except Exception as e:
        logger.warning(f"[DEBUG bing] lecture url/title impossible : {e}")

    html = ""
    try:
        html = await page.content()
        html_path = _DEBUG_OUTPUT_DIR / "debug_bing.html"
        html_path.write_text(html, encoding="utf-8")
        logger.warning(f"[DEBUG bing] HTML sauvegardé ({len(html)} octets) → {html_path}")
    except Exception as e:
        logger.warning(f"[DEBUG bing] échec sauvegarde HTML : {e}")

    try:
        png_path = _DEBUG_OUTPUT_DIR / "debug_bing.png"
        await page.screenshot(path=str(png_path), full_page=True)
        logger.warning(f"[DEBUG bing] screenshot sauvegardé → {png_path}")
    except Exception as e:
        logger.warning(f"[DEBUG bing] échec screenshot : {e}")

    try:
        count = await page.locator(_BING_RESULT_SELECTOR).count()
        logger.warning(f"[DEBUG bing] sélecteur d'extraction : '{_BING_RESULT_SELECTOR}' → {count} élément(s) matché(s)")
    except Exception as e:
        logger.warning(f"[DEBUG bing] comptage sélecteur impossible : {e}")

    lowered = html.lower()
    found = [term for term in _DEBUG_WALL_TERMS if term in lowered]
    logger.warning(f"[DEBUG bing] indices wall/consent/captcha présents dans le HTML : {found or 'aucun'}")


async def _scrape_bing_once(browser: Browser, query: str, max_results: int) -> list[dict]:
    page = await browser.new_page(user_agent=_random_ua())
    raw_items: list[dict] = []
    debug = _is_debug_query(query)
    try:
        url = _build_bing_url(query, max_results)
        await page.goto(url, timeout=_GOTO_TIMEOUT, wait_until="load")
        await page.wait_for_timeout(1200)
        # Diagnostic : capturer la page (HTML + screenshot) AVANT le wait_for_selector,
        # qui lève si '.b_algo' est absent — on veut justement voir ce que Bing sert.
        if debug:
            await _debug_dump_bing(page, query, url)
        await page.wait_for_selector(_BING_RESULT_SELECTOR, timeout=_RESULT_WAIT_TIMEOUT)
        raw_items = await page.eval_on_selector_all(
            _BING_RESULT_SELECTOR,
            """els => els.map(el => {
                const a = el.querySelector("h2 a");
                const cap = el.querySelector(".b_caption p") || el.querySelector("p");
                return {
                    title: a ? a.innerText : null,
                    href: a ? a.href : null,
                    body: cap ? cap.innerText : null,
                };
            })""",
        )
    except PlaywrightError:
        raw_items = []
    finally:
        await page.close()

    return [it for it in raw_items if it.get("title") and it.get("href")][:max_results]


async def _scrape_bing(browser: Browser, query: str, max_results: int) -> list[dict]:
    """Scrape Bing via navigateur headless, avec plusieurs tentatives (anti-bot intermittent)."""
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        items = await _scrape_bing_once(browser, query, max_results)
        if items:
            return items
        if attempt < _MAX_ATTEMPTS:
            logger.warning(
                f"web_search : tentative {attempt}/{_MAX_ATTEMPTS} sans résultat pour '{query}', nouvel essai..."
            )
            await asyncio.sleep(_RETRY_DELAY)

    logger.warning(f"web_search : aucun résultat Bing après {_MAX_ATTEMPTS} tentatives pour '{query}'")
    return []


def _evaluate_risk(category: ResultCategory, snippet: str) -> tuple[RiskLevel, bool]:
    snippet_lower = (snippet or "").lower()
    if any(keyword in snippet_lower for keyword in _SENSITIVE_KEYWORDS):
        return RiskLevel.HIGH, True
    if category in (ResultCategory.PROFESSIONAL, ResultCategory.SOCIAL):
        return RiskLevel.MEDIUM, False
    return RiskLevel.LOW, False


# ─────────────────────────────────────────────────────────────────────────────
# CANAL ACTIF : SearXNG auto-hébergé (métamoteur local, API JSON).
# Remplace le scraping Bing/Playwright (qui se faisait servir un challenge
# anti-bot Cloudflare). On ne consomme qu'une API JSON locale légitime ; aucun
# contournement de captcha n'est codé ici (SearXNG gère ses propres moteurs).
# L'URL de base est lue dans l'env SEARXNG_URL (défaut http://localhost:8888).
# ─────────────────────────────────────────────────────────────────────────────
_SEARXNG_URL = os.environ.get("SEARXNG_URL", "http://localhost:8888").rstrip("/")
_SEARXNG_TIMEOUT = 15.0
# Moteurs généralistes fiables interrogés (redondance = robustesse). Doivent être
# activés côté settings.yml.
_SEARXNG_ENGINES = "google,bing,duckduckgo,brave,mojeek"
# Drapeau de debug temporaire : logge l'URL appelée et le nombre de résultats
# bruts reçus. Retirable après validation.
_DEBUG_SEARXNG = True


async def _search_searxng(query: str, max_results: int) -> list[dict]:
    """Interroge l'API JSON de SearXNG et renvoie une liste de dicts
    {title, href, body} — MÊME contrat que l'ancien scraping Bing.

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

    if _DEBUG_SEARXNG:
        logger.info(f"[DEBUG searxng] GET {resp.url} → HTTP {resp.status_code}")

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
    if _DEBUG_SEARXNG:
        logger.info(f"[DEBUG searxng] '{query}' → {len(raw_results)} résultats bruts reçus")

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


async def _with_browser(browser: Browser | None, runner: Callable) -> None:
    """Exécute `runner(browser)` avec un navigateur partagé fourni par l'appelant.

    Si `browser` est None (appel autonome / rétrocompatibilité), on lance puis
    ferme un navigateur dédié. Sinon on réutilise le navigateur partagé sans le
    fermer : sa fermeture incombe au propriétaire (l'orchestrateur).
    """
    if browser is not None:
        await runner(browser)
        return

    async with async_playwright() as p:
        own_browser = await p.chromium.launch()
        try:
            await runner(own_browser)
        finally:
            await own_browser.close()


async def run_all_dorks(
    profile: NameProfile,
    search_id: str,
    callback: Callable,
    priority_only: bool = False,
    city_override: str | None = None,
    confirmed_platforms: list[str] | None = None,
    browser: Browser | None = None,
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
    browser: Browser | None = None,
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
