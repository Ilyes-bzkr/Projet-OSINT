"""
gravatar_checker — OSINT Eagle
Récupération du profil Gravatar associé à un email (hash MD5).
"""

import hashlib

import httpx

from app.core.logger import logger
from app.models.result import ModuleType, OsintResult, ResultCategory, RiskLevel

__all__ = ["check_gravatar"]

_GRAVATAR_URL = "https://www.gravatar.com/profiles/{hash}.json"
_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; OSINT-Eagle/1.0)"}
_TIMEOUT = 10.0
_SNIPPET_MAX_LEN = 150


async def check_gravatar(email: str, search_id: str) -> list[OsintResult]:
    """Récupère le profil Gravatar public associé à un email, s'il existe."""
    results: list[OsintResult] = []
    email_hash = hashlib.md5(email.lower().strip().encode("utf-8")).hexdigest()
    url = _GRAVATAR_URL.format(hash=email_hash)

    try:
        async with httpx.AsyncClient(headers=_HEADERS, timeout=_TIMEOUT, follow_redirects=True) as client:
            resp = await client.get(url)
    except Exception as e:
        logger.warning(f"gravatar_checker : erreur réseau pour '{email}' : {e}")
        return results

    if resp.status_code == 404:
        return results
    if resp.status_code != 200:
        logger.warning(f"gravatar_checker : statut {resp.status_code} pour '{email}'")
        return results

    try:
        data = resp.json()
        entry = data["entry"][0]
    except Exception as e:
        logger.warning(f"gravatar_checker : réponse invalide pour '{email}' : {e}")
        return results

    display_name = entry.get("displayName", "")
    profile_url = entry.get("profileUrl", "")
    thumbnail = entry.get("thumbnailUrl", "")
    about_me = entry.get("aboutMe", "")

    result = OsintResult(
        search_id=search_id,
        module=ModuleType.WEB_SEARCH,
        category=ResultCategory.IDENTITY,
        title=f"Profil Gravatar : {display_name}" if display_name else "Profil Gravatar",
        url=profile_url or None,
        snippet=about_me[:_SNIPPET_MAX_LEN] if about_me else None,
        raw_data={"email": email, "photo_url": thumbnail, "display_name": display_name},
        risk_level=RiskLevel.MEDIUM,
        is_sensitive=False,
    )
    results.append(result)

    logger.info(f"gravatar_checker : profil trouvé pour '{email}'")
    return results
