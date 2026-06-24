"""
social_checker — OSINT Eagle
Vérification de présence sur les réseaux sociaux.
"""

import asyncio
import json
from pathlib import Path
from typing import Callable

import httpx

from app.core.logger import logger
from app.models.result import ModuleType, OsintResult, ResultCategory, RiskLevel
from app.models.search import NameProfile

__all__ = ["check_all_platforms"]

_PLATFORMS_PATH = Path(__file__).parent.parent.parent / "data" / "platforms.json"
_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; OSINT-Eagle)"}
_TIMEOUT = 8.0
_MAX_CONCURRENT = 20


def _load_platforms() -> list[dict]:
    with open(_PLATFORMS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _get_nested_field(data: dict, dotted_path: str) -> bool:
    current = data
    for part in dotted_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return False
        current = current[part]
    return current is not None


async def _check_platform_username(
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    platform: dict,
    username: str,
    search_id: str,
    callback: Callable,
    results: list,
):
    url = platform["url"].format(username=username)

    async with semaphore:
        try:
            resp = await client.get(url, timeout=_TIMEOUT)
        except Exception as e:
            logger.warning(f"social_checker : erreur sur {url} : {e}")
            return

        found = False
        if platform["check_method"] == "status_code":
            found = resp.status_code == platform.get("found_code", 200)
        elif platform["check_method"] == "json_field":
            if resp.status_code == 200:
                try:
                    found = _get_nested_field(resp.json(), platform["found_field"])
                except Exception:
                    found = False

        if not found:
            return

        result = OsintResult(
            search_id=search_id,
            module=ModuleType.SOCIAL,
            category=ResultCategory.SOCIAL,
            title=f"{platform['name']} — @{username}",
            url=url,
            snippet=None,
            raw_data={
                "platform": platform["name"],
                "username": username,
                "category_platform": platform.get("category"),
            },
            risk_level=RiskLevel.MEDIUM,
        )
        results.append(result)
        try:
            callback(result)
        except Exception as e:
            logger.warning(f"social_checker : erreur callback : {e}")


async def check_all_platforms(
    profile: NameProfile,
    search_id: str,
    callback: Callable,
    max_variants: int | None = None,
    username_override: str | None = None,
) -> list[OsintResult]:
    """Vérifie l'existence de comptes sur les plateformes listées dans platforms.json."""
    platforms = _load_platforms()
    semaphore = asyncio.Semaphore(_MAX_CONCURRENT)
    results: list[OsintResult] = []

    if username_override:
        usernames = [username_override]
    elif max_variants is not None:
        usernames = profile.username_variants[:max_variants]
    else:
        usernames = profile.username_variants

    async with httpx.AsyncClient(headers=_HEADERS, follow_redirects=True) as client:
        tasks = [
            _check_platform_username(client, semaphore, platform, username, search_id, callback, results)
            for platform in platforms
            for username in usernames
        ]
        logger.info(f"social_checker : vérification de {len(tasks)} combinaisons plateforme/username")
        await asyncio.gather(*tasks)

    logger.info(f"social_checker : {len(results)} comptes trouvés")
    return results
