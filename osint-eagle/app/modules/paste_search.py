"""
paste_search — OSINT Eagle
Recherche sur les sites de paste publics.
"""

import asyncio
from typing import Callable

import httpx
from duckduckgo_search import DDGS

from app.core.config import settings
from app.core.logger import logger
from app.models.result import ModuleType, OsintResult, ResultCategory, RiskLevel
from app.models.search import NameProfile

__all__ = ["search_pastes"]

_PSBDMP_URL = "https://psbdmp.ws/api/v3/search/{query}"
_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; OSINT-Eagle/1.0)"}
_TIMEOUT = 8.0

_PASTE_SITES = ["pastebin.com", "paste.ee", "ghostbin.com", "controlc.com"]
_MAX_RESULTS_PER_DORK = 5


def _run_dork_sync(query: str, max_results: int) -> list[dict]:
    with DDGS() as ddgs:
        return list(ddgs.text(query, max_results=max_results))


async def _search_psbdmp(profile: NameProfile, search_id: str, callback: Callable, results: list):
    try:
        async with httpx.AsyncClient(headers=_HEADERS, timeout=_TIMEOUT) as client:
            resp = await client.get(_PSBDMP_URL.format(query=profile.full_name))
    except Exception as e:
        logger.warning(f"paste_search : erreur psbdmp.ws : {e}")
        return

    if resp.status_code != 200:
        logger.warning(f"paste_search : psbdmp.ws a retourné {resp.status_code}")
        return

    try:
        data = resp.json()
    except Exception as e:
        logger.warning(f"paste_search : réponse psbdmp.ws invalide : {e}")
        return

    for item in data.get("data", []) or []:
        paste_id = item.get("id")
        result = OsintResult(
            search_id=search_id,
            module=ModuleType.PASTE,
            category=ResultCategory.BREACH,
            title=f"Paste trouvé (psbdmp) : {paste_id}",
            url=f"https://pastebin.com/{paste_id}" if paste_id else None,
            snippet=item.get("text", "")[:500] if item.get("text") else None,
            raw_data={"source": "psbdmp", "item": item},
            risk_level=RiskLevel.HIGH,
            is_sensitive=True,
        )
        results.append(result)
        _safe_callback(callback, result)


async def _search_paste_dorks(profile: NameProfile, search_id: str, callback: Callable, results: list):
    loop = asyncio.get_event_loop()

    for site in _PASTE_SITES:
        query = f'site:{site} "{profile.full_name}"'
        try:
            raw_results = await asyncio.wait_for(
                loop.run_in_executor(None, _run_dork_sync, query, _MAX_RESULTS_PER_DORK),
                timeout=10,
            )
        except asyncio.TimeoutError:
            logger.warning(f"paste_search : timeout sur le dork '{query}'")
            raw_results = []
        except Exception as e:
            logger.warning(f"paste_search : erreur sur le dork '{query}' : {e}")
            raw_results = []

        for item in raw_results:
            url = item.get("href") or item.get("url")
            if not url:
                continue

            result = OsintResult(
                search_id=search_id,
                module=ModuleType.PASTE,
                category=ResultCategory.BREACH,
                title=item.get("title") or url,
                url=url,
                snippet=(item.get("body") or "")[:500],
                raw_data={"source": "ddg_dork", "dork": query},
                risk_level=RiskLevel.HIGH,
                is_sensitive=True,
            )
            results.append(result)
            _safe_callback(callback, result)

        await asyncio.sleep(settings.rate_limit_delay)


async def search_pastes(profile: NameProfile, search_id: str, callback: Callable) -> list[OsintResult]:
    """Cherche le nom sur les sites de paste publics (psbdmp.ws + dorks DuckDuckGo)."""
    results: list[OsintResult] = []

    await _search_psbdmp(profile, search_id, callback, results)
    await _search_paste_dorks(profile, search_id, callback, results)

    logger.info(f"paste_search : {len(results)} pastes trouvés")
    return results


def _safe_callback(callback: Callable, result: OsintResult):
    try:
        callback(result)
    except Exception as e:
        logger.warning(f"paste_search : erreur callback : {e}")
