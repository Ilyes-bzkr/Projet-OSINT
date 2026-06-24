"""
holehe_checker — OSINT Eagle
Détection des comptes en ligne enregistrés avec un email donné, via holehe.

Holehe est construit sur trio (pas asyncio) : on l'exécute donc dans un
thread séparé via asyncio.to_thread, piloté par trio.run en interne.
"""

import asyncio

from app.core.logger import logger
from app.models.result import ModuleType, OsintResult, ResultCategory, RiskLevel

__all__ = ["check_email"]

_TIMEOUT = 120.0
_HOLEHE_TIMEOUT = 10


def _run_holehe_sync(email: str) -> list[dict]:
    """Exécute tous les modules holehe pour un email, de façon synchrone (trio.run)."""
    import trio
    import httpx
    from holehe.core import get_functions, import_submodules, launch_module

    async def _run() -> list[dict]:
        modules = import_submodules("holehe.modules")
        websites = get_functions(modules)
        out: list[dict] = []
        client = httpx.AsyncClient(timeout=_HOLEHE_TIMEOUT)
        try:
            async with trio.open_nursery() as nursery:
                for website in websites:
                    nursery.start_soon(launch_module, website, email, client, out)
        finally:
            await client.aclose()
        return out

    return trio.run(_run)


async def check_email(email: str, search_id: str) -> list[OsintResult]:
    """Vérifie sur quelles plateformes un email est enregistré via holehe."""
    results: list[OsintResult] = []

    try:
        entries = await asyncio.wait_for(asyncio.to_thread(_run_holehe_sync, email), timeout=_TIMEOUT)
    except asyncio.TimeoutError:
        logger.warning(f"holehe_checker : timeout après {_TIMEOUT}s pour '{email}'")
        return results
    except ImportError:
        logger.warning("holehe_checker : librairie holehe non installée, module ignoré")
        return results
    except Exception as e:
        logger.error(f"holehe_checker : erreur pour '{email}' : {e}")
        return results

    for entry in entries:
        if not entry.get("exists"):
            continue

        name = entry.get("name", "inconnu")
        domain = entry.get("domain", "")
        result = OsintResult(
            search_id=search_id,
            module=ModuleType.SOCIAL,
            category=ResultCategory.SOCIAL,
            title=f"Compte {name} associé à {email}",
            url=f"https://{domain}" if domain else None,
            snippet=f"Email {email} enregistré sur {name}",
            raw_data={"email": email, "platform": name, "domain": domain, "username": None},
            risk_level=RiskLevel.MEDIUM,
            is_sensitive=True,
        )
        results.append(result)

    logger.info(f"holehe_checker : {len(results)} comptes trouvés pour '{email}'")
    return results
