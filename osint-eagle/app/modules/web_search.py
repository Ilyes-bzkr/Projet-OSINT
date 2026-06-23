"""
web_search — OSINT Eagle
Recherche web via DuckDuckGo dorks.
"""

import asyncio
from typing import Callable

from duckduckgo_search import DDGS

from app.core.config import settings
from app.core.logger import logger
from app.models.result import ModuleType, OsintResult, ResultCategory, RiskLevel
from app.models.search import NameProfile

__all__ = ["run_all_dorks"]

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
_MAX_CONCURRENT_DORKS = 5


def _run_dork_sync(query: str, max_results: int) -> list[dict]:
    with DDGS() as ddgs:
        return list(ddgs.text(query, max_results=max_results))


def _evaluate_risk(category: ResultCategory, snippet: str) -> tuple[RiskLevel, bool]:
    snippet_lower = (snippet or "").lower()
    if any(keyword in snippet_lower for keyword in _SENSITIVE_KEYWORDS):
        return RiskLevel.HIGH, True
    if category in (ResultCategory.PROFESSIONAL, ResultCategory.SOCIAL):
        return RiskLevel.MEDIUM, False
    return RiskLevel.LOW, False


async def _run_single_dork(
    semaphore: asyncio.Semaphore,
    loop: asyncio.AbstractEventLoop,
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
                loop.run_in_executor(None, _run_dork_sync, query, _MAX_RESULTS_PER_DORK),
                timeout=10,
            )
        except asyncio.TimeoutError:
            logger.warning(f"web_search : timeout sur le dork '{query}'")
            raw_results = []
        except Exception as e:
            logger.warning(f"web_search : erreur sur le dork '{query}' : {e}")
            raw_results = []

        for item in raw_results:
            url = item.get("href") or item.get("url")
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

        await asyncio.sleep(settings.rate_limit_delay)


async def run_all_dorks(profile: NameProfile, search_id: str, callback: Callable) -> list[OsintResult]:
    """Exécute tous les dorks générés par name_engine via DuckDuckGo."""
    semaphore = asyncio.Semaphore(_MAX_CONCURRENT_DORKS)
    loop = asyncio.get_event_loop()
    seen_urls: set = set()
    results: list[OsintResult] = []

    tasks = []
    for category_key, queries in profile.search_queries.items():
        for query in queries:
            tasks.append(
                _run_single_dork(
                    semaphore, loop, category_key, query, search_id, callback, seen_urls, results
                )
            )

    logger.info(f"web_search : exécution de {len(tasks)} dorks pour '{profile.full_name}'")
    await asyncio.gather(*tasks)
    logger.info(f"web_search : {len(results)} résultats uniques trouvés")
    return results
