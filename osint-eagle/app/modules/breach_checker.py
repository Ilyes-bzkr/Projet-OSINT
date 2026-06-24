"""
breach_checker — OSINT Eagle
Vérification de fuites via LeakCheck Public API et BreachDirectory (RapidAPI).
"""

import asyncio
import os
from typing import Callable

import httpx

from app.core.logger import logger
from app.models.result import ModuleType, OsintResult, ResultCategory, RiskLevel

__all__ = ["check_breaches"]

_LEAKCHECK_URL = "https://leakcheck.io/api/public"
_BREACHDIRECTORY_URL = "https://breachdirectory.p.rapidapi.com"
_HEADERS = {"User-Agent": "OSINT-Eagle/1.0"}
_TIMEOUT = 10.0
_RATE_LIMIT_DELAY = 1.0


async def check_breaches(
    emails: list[str], usernames: list[str], search_id: str, callback: Callable
) -> list[OsintResult]:
    """Vérifie les fuites associées à des emails et usernames via LeakCheck + BreachDirectory."""
    results: list[OsintResult] = []

    if not emails and not usernames:
        logger.warning("breach_checker : aucun email ni username à vérifier, recherche ignorée")
        return results

    seen_sources: set[str] = set()

    api_key = os.getenv("RAPIDAPI_KEY", "")
    if not api_key and emails:
        logger.warning("breach_checker : RAPIDAPI_KEY absente, BreachDirectory ignoré")

    async with httpx.AsyncClient(headers=_HEADERS, timeout=_TIMEOUT) as client:
        for email in emails:
            await _check_leakcheck(client, email, "email", search_id, callback, results, seen_sources)
            await asyncio.sleep(_RATE_LIMIT_DELAY)

            if api_key:
                await _check_breachdirectory(client, email, api_key, search_id, callback, results, seen_sources)
                await asyncio.sleep(_RATE_LIMIT_DELAY)

        for username in usernames:
            await _check_leakcheck(client, username, "username", search_id, callback, results, seen_sources)
            await asyncio.sleep(_RATE_LIMIT_DELAY)

    logger.info(f"breach_checker : {len(results)} fuites trouvées")
    return results


async def _check_leakcheck(
    client: httpx.AsyncClient,
    query: str,
    query_type: str,
    search_id: str,
    callback: Callable,
    results: list,
    seen_sources: set,
):
    params = {"check": query}
    if query_type == "username":
        params["type"] = "username"

    try:
        resp = await client.get(_LEAKCHECK_URL, params=params)
    except Exception as e:
        logger.warning(f"breach_checker : erreur LeakCheck pour '{query}' : {e}")
        return

    if resp.status_code == 429:
        logger.warning(f"breach_checker : LeakCheck rate limite pour '{query}'")
        return
    if resp.status_code != 200:
        logger.warning(f"breach_checker : LeakCheck a retourné {resp.status_code} pour '{query}'")
        return

    try:
        data = resp.json()
    except Exception as e:
        logger.warning(f"breach_checker : réponse LeakCheck invalide pour '{query}' : {e}")
        return

    if not data.get("success"):
        return

    fields = data.get("fields", [])
    for source in data.get("sources", []):
        name = source.get("name")
        if not name or name in seen_sources:
            continue
        seen_sources.add(name)

        date = source.get("date") or "date inconnue"
        result = OsintResult(
            search_id=search_id,
            module=ModuleType.BREACH,
            category=ResultCategory.BREACH,
            title=f"Fuite : {name} ({date})",
            url=None,
            snippet=f"Données exposées : {', '.join(fields)}" if fields else None,
            raw_data={
                "source": name,
                "date": date,
                "query": query,
                "service": "leakcheck",
            },
            risk_level=RiskLevel.CRITICAL,
            is_sensitive=True,
        )
        results.append(result)
        _safe_callback(callback, result)


async def _check_breachdirectory(
    client: httpx.AsyncClient,
    email: str,
    api_key: str,
    search_id: str,
    callback: Callable,
    results: list,
    seen_sources: set,
):
    headers = {
        "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com",
        "X-RapidAPI-Key": api_key,
    }

    try:
        resp = await client.get(
            _BREACHDIRECTORY_URL,
            params={"func": "auto", "term": email},
            headers=headers,
        )
    except Exception as e:
        logger.warning(f"breach_checker : erreur BreachDirectory pour '{email}' : {e}")
        return

    if resp.status_code == 429:
        logger.warning(f"breach_checker : BreachDirectory rate limite pour '{email}'")
        return
    if resp.status_code != 200:
        logger.warning(f"breach_checker : BreachDirectory a retourné {resp.status_code} pour '{email}'")
        return

    try:
        data = resp.json()
    except Exception as e:
        logger.warning(f"breach_checker : réponse BreachDirectory invalide pour '{email}' : {e}")
        return

    for item in data.get("result", []) or []:
        sources = item.get("sources")
        name = sources[0] if isinstance(sources, list) and sources else "BreachDirectory"
        if name in seen_sources:
            continue
        seen_sources.add(name)

        result = OsintResult(
            search_id=search_id,
            module=ModuleType.BREACH,
            category=ResultCategory.BREACH,
            title=f"Fuite : {name} (date inconnue)",
            url=None,
            snippet=f"Données exposées : {item.get('line', '')}" if item.get("line") else None,
            raw_data={
                "source": name,
                "date": None,
                "query": email,
                "service": "breachdirectory",
            },
            risk_level=RiskLevel.CRITICAL,
            is_sensitive=True,
        )
        results.append(result)
        _safe_callback(callback, result)


def _safe_callback(callback: Callable, result: OsintResult):
    try:
        callback(result)
    except Exception as e:
        logger.warning(f"breach_checker : erreur callback : {e}")
