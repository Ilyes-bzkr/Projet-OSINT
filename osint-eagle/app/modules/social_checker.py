"""
social_checker — OSINT Eagle
Vérification de présence sur les réseaux sociaux via Maigret.

Remplace l'ancien moteur "HTTP 200" (qui produisait des dizaines de faux
positifs : tout code 200 était compté comme un compte) par Maigret, qui
vérifie le CONTENU réel des pages et n'accepte qu'un compte au statut CLAIMED.
La signature publique et le format de sortie (OsintResult) sont conservés à
l'identique pour ne rien casser en aval (intelligence_engine, websocket).
"""

import asyncio
import logging
from typing import Callable, Optional

from app.core.logger import logger
from app.models.result import ModuleType, OsintResult, ResultCategory, RiskLevel
from app.models.search import NameProfile

try:
    from maigret.checking import maigret as _maigret_search
    from maigret.db_updater import BUNDLED_DB_PATH
    from maigret.result import MaigretCheckStatus
    from maigret.sites import MaigretDatabase

    _MAIGRET_AVAILABLE = True
    _MAIGRET_IMPORT_ERROR: Optional[Exception] = None
except Exception as _exc:  # pragma: no cover - dépendance optionnelle
    _MAIGRET_AVAILABLE = False
    _MAIGRET_IMPORT_ERROR = _exc

__all__ = ["check_all_platforms"]

# --- Réglages Maigret -------------------------------------------------------
# Sous-ensemble des sites les mieux classés. La base Maigret compte ~3000 sites ;
# en scanner trop d'un coup déclenche du rate-limiting (les sites importants
# retombent alors en statut "unknown") ET allonge énormément le scan.
# Défaut couche 1 (ancrage) : top 100 -> couvre les réseaux majeurs et les
# plateformes dev connues, ~3x plus rapide que 300. La couche 2 passe top=50.
_TOP_SITES_DEFAULT = 100
# Connexions simultanées vers les sites, internes à un scan Maigret.
_MAX_CONNECTIONS = 20
# Timeout par requête HTTP individuelle (secondes).
_REQUEST_TIMEOUT = 10
# Garde-fou global par username : on n'attend jamais indéfiniment un scan.
_PER_USERNAME_TIMEOUT = 120.0
# Concurrence entre usernames d'un MÊME appel (1 = séquentiel).
_MAX_CONCURRENT_USERNAMES = 1
# Cap GLOBAL sur le nombre de scans Maigret simultanés pour TOUTE la recherche
# (couches 1 et 2 confondues). Empêche le cas observé où la couche 2 lançait dix
# scans Maigret en parallèle (surcharge de la base SQLite + throttling réseau).
_GLOBAL_MAX_CONCURRENT_SCANS = 2

# Champs d'ids_data jugés utiles pour le snippet (aide au filtrage IA en aval),
# par ordre de priorité d'affichage. Le reste des ids est ajouté ensuite.
_SNIPPET_PRIORITY_FIELDS = (
    "fullname", "name", "username", "location", "is_company", "occupation",
    "job", "description", "bio", "follower_count", "created_at",
)
# Champs volumineux / inutiles au filtrage, exclus du snippet.
_SNIPPET_SKIP_FIELDS = {"image", "avatar", "image_url", "avatar_url"}
_SNIPPET_MAX_LEN = 300

# Logger silencieux passé à Maigret (il exige un logging.Logger standard).
_maigret_logger = logging.getLogger("maigret")
_maigret_logger.addHandler(logging.NullHandler())
_maigret_logger.propagate = False

# Cache module : la base (~1.2 Mo JSON) n'est chargée qu'une fois.
_db = None  # type: Optional[MaigretDatabase]
_sites_cache: dict[int, dict] = {}
_db_lock = asyncio.Lock()

# Sémaphore global (lié à la boucle asyncio courante) plafonnant le nombre de
# scans Maigret simultanés sur l'ensemble de la recherche.
_global_semaphore: Optional[asyncio.Semaphore] = None
_global_semaphore_loop = None


def _global_scan_semaphore() -> asyncio.Semaphore:
    """Retourne le sémaphore global, (re)créé s'il est lié à une autre boucle.

    L'app tourne sur une boucle unique (uvicorn) ; le re-test de boucle protège
    seulement les contextes de test où plusieurs boucles se succèdent.
    """
    global _global_semaphore, _global_semaphore_loop
    loop = asyncio.get_event_loop()
    if _global_semaphore is None or _global_semaphore_loop is not loop:
        _global_semaphore = asyncio.Semaphore(_GLOBAL_MAX_CONCURRENT_SCANS)
        _global_semaphore_loop = loop
    return _global_semaphore


async def _get_sites(top: int) -> dict:
    """Charge (et met en cache) la base Maigret et le sous-ensemble de sites top.

    Le chargement du JSON (~1.2 Mo) est déporté dans un thread pour ne pas
    bloquer la boucle asyncio.
    """
    global _db
    if _db is None:
        async with _db_lock:
            if _db is None:
                loop = asyncio.get_event_loop()
                _db = await loop.run_in_executor(
                    None, lambda: MaigretDatabase().load_from_path(BUNDLED_DB_PATH)
                )
    if top not in _sites_cache:
        _sites_cache[top] = _db.ranked_sites_dict(top=top)
    return _sites_cache[top]


def _build_snippet(ids_data: Optional[dict], tags: Optional[list]) -> Optional[str]:
    """Concatène les métadonnées exposées par Maigret pour aider le filtrage IA.

    Retourne None si aucune information exploitable n'est disponible (comportement
    historique : snippet=None).
    """
    parts: list[str] = []
    if ids_data:
        for key in _SNIPPET_PRIORITY_FIELDS:
            value = ids_data.get(key)
            if value:
                parts.append(f"{key}: {value}")
        for key, value in ids_data.items():
            if key in _SNIPPET_PRIORITY_FIELDS or key in _SNIPPET_SKIP_FIELDS or not value:
                continue
            parts.append(f"{key}: {value}")
    if tags:
        parts.append("tags: " + ", ".join(str(t) for t in tags))
    if not parts:
        return None
    return " | ".join(str(p) for p in parts)[:_SNIPPET_MAX_LEN]


async def _scan_username(
    username: str,
    search_id: str,
    callback: Callable,
    results: list[OsintResult],
    top: int,
) -> None:
    """Scanne un username avec Maigret et n'émet que les comptes CLAIMED.

    Le scan réseau est plafonné par le sémaphore global (jamais plus de
    _GLOBAL_MAX_CONCURRENT_SCANS scans Maigret en parallèle sur la recherche).
    """
    sites = await _get_sites(top)

    async with _global_scan_semaphore():
        try:
            maigret_results = await asyncio.wait_for(
                _maigret_search(
                    username=username,
                    site_dict=sites,
                    logger=_maigret_logger,
                    # query_notify laissé à None (défaut Maigret) : passer une
                    # instance QueryNotify() de base casse silencieusement la
                    # détection (tous les comptes retombent à "non trouvé").
                    timeout=_REQUEST_TIMEOUT,
                    is_parsing_enabled=True,  # extrait les ids/métadonnées des pages
                    no_progressbar=True,
                    max_connections=_MAX_CONNECTIONS,
                ),
                timeout=_PER_USERNAME_TIMEOUT,
            )
        except asyncio.TimeoutError:
            logger.warning(
                f"social_checker : timeout Maigret pour '{username}' (>{_PER_USERNAME_TIMEOUT:.0f}s)"
            )
            return
        except Exception as e:
            logger.warning(f"social_checker : erreur Maigret pour '{username}' : {e}")
            return

    found = 0
    for site_name, info in maigret_results.items():
        status = info.get("status")
        # Cœur de la correction des faux positifs : on n'accepte QUE CLAIMED.
        # On ignore AVAILABLE / UNKNOWN / ILLEGAL.
        if status is None or getattr(status, "status", None) != MaigretCheckStatus.CLAIMED:
            continue

        url = info.get("url_user") or info.get("url_main")
        ids_data = getattr(status, "ids_data", None) or {}
        tags = list(getattr(status, "tags", None) or [])

        result = OsintResult(
            search_id=search_id,
            module=ModuleType.SOCIAL,
            category=ResultCategory.SOCIAL,
            title=f"{site_name} — @{username}",
            url=url,
            snippet=_build_snippet(ids_data, tags),
            raw_data={
                "platform": site_name,
                "username": username,
                "category_platform": tags[0] if tags else None,
                "tags": tags,
                "ids_data": ids_data,
            },
            risk_level=RiskLevel.MEDIUM,
        )
        results.append(result)
        found += 1
        try:
            callback(result)
        except Exception as e:
            logger.warning(f"social_checker : erreur callback : {e}")

    logger.info(f"social_checker : '{username}' → {found} compte(s) confirmé(s) (Maigret)")


async def check_all_platforms(
    profile: NameProfile,
    search_id: str,
    callback: Callable,
    max_variants: int | None = None,
    username_override: str | None = None,
    usernames: list[str] | None = None,
    top_sites: int | None = None,
) -> list[OsintResult]:
    """Vérifie l'existence de comptes sociaux via Maigret.

    Sélection des usernames (priorité décroissante) :
      * username_override fourni  -> uniquement celui-là
      * sinon usernames fourni    -> exactement cette liste (couche 2 ciblée)
      * sinon max_variants fourni -> les N premiers username_variants
      * sinon                     -> tous les username_variants

    top_sites permet de restreindre le nombre de sites scannés (défaut couche 1 :
    _TOP_SITES_DEFAULT ; la couche 2 passe une valeur plus basse pour aller vite).
    """
    if not _MAIGRET_AVAILABLE:
        logger.error(
            f"social_checker : Maigret indisponible ({_MAIGRET_IMPORT_ERROR}), aucun scan social"
        )
        return []

    top = top_sites or _TOP_SITES_DEFAULT

    if username_override:
        targets = [username_override]
    elif usernames is not None:
        targets = list(usernames)
    elif max_variants is not None:
        targets = profile.username_variants[:max_variants]
    else:
        targets = profile.username_variants

    # Déduplication défensive (insensible à la casse) en conservant l'ordre.
    seen: set[str] = set()
    targets = [
        u for u in targets
        if u and not (u.lower() in seen or seen.add(u.lower()))
    ]

    results: list[OsintResult] = []
    if not targets:
        return results

    semaphore = asyncio.Semaphore(_MAX_CONCURRENT_USERNAMES)

    async def _guarded(u: str) -> None:
        async with semaphore:
            await _scan_username(u, search_id, callback, results, top)

    logger.info(
        f"social_checker : scan Maigret de {len(targets)} username(s) sur les "
        f"top {top} sites"
    )
    await asyncio.gather(*[_guarded(u) for u in targets])

    logger.info(f"social_checker : {len(results)} comptes confirmés (Maigret)")
    return results
