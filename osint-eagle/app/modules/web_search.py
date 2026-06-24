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
import random
import urllib.parse
from typing import Callable

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


async def _scrape_bing_once(browser: Browser, query: str, max_results: int) -> list[dict]:
    page = await browser.new_page(user_agent=_random_ua())
    raw_items: list[dict] = []
    try:
        await page.goto(_build_bing_url(query, max_results), timeout=_GOTO_TIMEOUT, wait_until="load")
        await page.wait_for_timeout(1200)
        await page.wait_for_selector(".b_algo", timeout=_RESULT_WAIT_TIMEOUT)
        raw_items = await page.eval_on_selector_all(
            ".b_algo",
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


async def _run_single_dork(
    semaphore: asyncio.Semaphore,
    browser: Browser,
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
                _scrape_bing(browser, query, _MAX_RESULTS_PER_DORK),
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
    """Exécute tous les dorks générés par name_engine via scraping Bing (Playwright).

    `browser` et `semaphore` peuvent être partagés par l'orchestrateur pour
    mutualiser un unique navigateur Chromium et plafonner la concurrence Bing
    globale d'une recherche. À défaut, chaque appel reste autonome.
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

    async def _runner(active_browser: Browser):
        priority_tasks = [
            _run_single_dork(semaphore, active_browser, category_key, query, search_id, callback, seen_urls, results)
            for category_key, query in priority_specs
        ]
        logger.info(f"web_search : exécution de {len(priority_tasks)} dorks prioritaires pour '{profile.full_name}'")
        await asyncio.gather(*priority_tasks)

        if priority_only:
            logger.info("web_search : priority_only=True, dorks secondaires ignorés")
        elif len(results) >= _MIN_PRIORITY_RESULTS:
            secondary_tasks = [
                _run_single_dork(semaphore, active_browser, category_key, query, search_id, callback, seen_urls, results)
                for category_key, query in secondary_specs
            ]
            logger.info(f"web_search : exécution de {len(secondary_tasks)} dorks secondaires pour '{profile.full_name}'")
            await asyncio.gather(*secondary_tasks)
        else:
            logger.warning("web_search : Aucun résultat web trouvé, empreinte faible")

    await _with_browser(browser, _runner)

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
    """Exécute un unique dork Bing manuel (ex: numéro de téléphone, employeur) hors profil.

    `browser` et `semaphore` peuvent être partagés par l'orchestrateur (voir
    run_all_dorks). À défaut, l'appel lance son propre navigateur.
    """
    semaphore = semaphore or asyncio.Semaphore(1)
    seen_urls: set = set()
    results: list[OsintResult] = []

    async def _runner(active_browser: Browser):
        await _run_single_dork(semaphore, active_browser, category_key, query, search_id, callback, seen_urls, results)

    await _with_browser(browser, _runner)

    return results
