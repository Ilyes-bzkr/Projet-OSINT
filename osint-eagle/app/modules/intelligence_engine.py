"""
intelligence_engine — OSINT Eagle
Orchestrateur principal en 3 couches séquentielles :
  Couche 1 (ancrage)            : web_search (dorks prioritaires), github, social (5 variants)
  Couche 2 (approfondissement)  : enrichissements ciblés à partir des identifiants confirmés en couche 1
  Couche 3 (consolidation)      : filtrage IA + profil IA + rapport (réutilise _run_ai_pipeline)

Remplace l'appel à run_search() dans websocket.py, qui reste disponible
mais n'est plus utilisé.
"""

import asyncio
import json
import urllib.parse
from tempfile import TemporaryDirectory
from typing import Optional

from anthropic import AsyncAnthropic
from playwright.async_api import async_playwright

from app.ai.analyzer import filter_results
from app.core.config import settings
from app.core.logger import logger
from app.models.result import ConfidenceLevel, ModuleType, OsintResult, WebSocketMessage
from app.models.search import NameProfile, SearchAnchors, SearchRequest
from app.modules import evidence_engine, exif_extractor, gravatar_checker, holehe_checker, reverse_image
from app.modules.account_enricher import enrich_accounts
from app.modules.breach_checker import check_breaches
from app.modules.github_search import search_github
from app.modules.name_engine import generate_anchored_dorks, generate_search_profile
from app.modules.paste_search import search_pastes
from app.modules.social_checker import check_all_platforms
from app.modules.web_search import run_all_dorks, run_manual_dork

__all__ = ["run_intelligence_engine"]

_MODEL = "claude-sonnet-4-6"
_LAYER1_MAX_TOKENS = 500
_LAYER1_TIMEOUT = 60.0
_LAYER1_MAX_RESULTS = 80
_LAYER1_SOCIAL_VARIANTS = 5
# Couche 2 : on n'approfondit Maigret que sur les usernames les plus pertinents,
# en série et sur un sous-ensemble de sites réduit (approfondissement, pas besoin
# d'un large scan). Évite le cas observé de dix scans Maigret lancés en parallèle.
_LAYER2_MAX_SOCIAL_USERNAMES = 2
_LAYER2_SOCIAL_TOP_SITES = 50
_VIDEO_FRAME_COUNT = 3
# Plafonds durs couche 2 : la recherche d'image inversée (Yandex/Lens via navigateur)
# est l'étape la plus coûteuse/lente. On borne le nombre de photos/vidéos
# approfondies pour maîtriser coût et latence (les avatars confirmés d'abord).
_LAYER2_MAX_IMAGES = 3
_LAYER2_MAX_VIDEOS = 2

# Concurrence Bing maximale pour TOUS les dorks web d'une recherche, partagée
# via un unique sémaphore (miroir de web_search._MAX_CONCURRENT_DORKS) afin de
# ne pas se faire détecter quand plusieurs dorks tournent sur le browser partagé.
_WEB_MAX_CONCURRENT = 2

_LAYER1_SYSTEM_PROMPT = (
    "Tu es un extracteur de données OSINT. Réponds UNIQUEMENT en JSON pur "
    "sans markdown. Extrais uniquement les identifiants CONFIRMÉS par au "
    "moins une source fiable."
)

_LAYER1_SCHEMA = """{
  "emails": ["email1", "email2"],
  "usernames_confirmed": [{"value": str, "platform": str}],
  "phone_numbers": ["tel1"],
  "photo_urls": ["url1"],
  "video_urls": ["url1"],
  "city": str ou null,
  "employer": str ou null
}"""

_EMPTY_IDENTIFIERS = {
    "emails": [],
    "usernames_confirmed": [],
    "phone_numbers": [],
    "photo_urls": [],
    "video_urls": [],
    "city": None,
    "employer": None,
}


async def _safe_run(coro, label: str) -> list[OsintResult]:
    """Exécute un module en isolant ses erreurs des autres."""
    try:
        return await coro
    except Exception as e:
        logger.error(f"[intelligence_engine] Erreur module {label} : {e}")
        return []


async def _start_shared_browser():
    """Démarre un unique Playwright + Chromium partagé pour tous les dorks web.

    En cas d'échec, retourne (None, None) : les modules non-web (github, social,
    breach) continuent normalement et les dorks web retombent sur un navigateur
    dédié par appel (browser=None).
    """
    try:
        playwright_ctx = await async_playwright().start()
        browser = await playwright_ctx.chromium.launch()
        logger.info("[intelligence_engine] Navigateur Chromium partagé démarré pour les dorks web")
        return playwright_ctx, browser
    except Exception as e:
        logger.error(
            f"[intelligence_engine] Échec du navigateur partagé ({e}) : "
            "repli sur un navigateur dédié par dork"
        )
        return None, None


async def _close_shared_browser(playwright_ctx, browser) -> None:
    """Ferme proprement le navigateur partagé puis le contexte Playwright."""
    try:
        if browser is not None:
            await browser.close()
    except Exception as e:
        logger.warning(f"[intelligence_engine] Erreur fermeture navigateur partagé : {e}")
    try:
        if playwright_ctx is not None:
            await playwright_ctx.stop()
    except Exception as e:
        logger.warning(f"[intelligence_engine] Erreur arrêt Playwright : {e}")


def _make_callback(pending_tasks: list[asyncio.Task], websocket, search_id: str):
    """Callback générique : diffuse un résultat au frontend puis le persiste en base."""
    from app.api.websocket import _handle_result

    def callback(result: OsintResult):
        task = asyncio.create_task(
            _handle_result(websocket, search_id, result.module.value, result)
        )
        pending_tasks.append(task)
    return callback


async def _dispatch(coro, callback) -> list[OsintResult]:
    """Pour les modules qui ne prennent pas de callback (holehe, gravatar, exif,
    reverse_image) : on les exécute puis on diffuse chaque résultat manuellement."""
    results = await coro
    for result in results:
        try:
            callback(result)
        except Exception as e:
            logger.warning(f"[intelligence_engine] Erreur callback : {e}")
    return results


def _noop_callback(_result: OsintResult) -> None:
    """Callback neutre : bufferise sans diffuser (les comptes de couche 1A ne sont
    diffusés qu'APRÈS classification par le moteur de preuves)."""
    return None


def _build_anchor_reference(
    profile: NameProfile,
    anchors: Optional[SearchAnchors],
) -> evidence_engine.ConfirmedReference:
    """Référence de DÉPART du moteur de preuves : UNIQUEMENT les ancres fournies par
    l'utilisateur (seuls identifiants fiables d'office). Les profils GitHub n'y
    entrent PAS automatiquement : ils doivent d'abord prouver leur appartenance."""
    emails: set[str] = set()
    usernames: set[str] = set()
    employer: Optional[str] = None
    city: Optional[str] = None

    if anchors is not None:
        if anchors.email:
            emails.add(anchors.email)
        if anchors.username:
            usernames.add(anchors.username.lstrip("@"))
        employer = anchors.employer
        city = anchors.city

    return evidence_engine.ConfirmedReference(
        first_name=profile.first_name,
        last_name=profile.last_name,
        full_name=profile.full_name,
        emails=emails,
        usernames=usernames,
        links=set(),
        employer=employer,
        city=city,
    )


def _github_account_raw(raw: dict) -> dict:
    """Adapte un profil GitHub au format attendu par le moteur de preuves."""
    content = {
        "fullname": raw.get("name"),
        "location": raw.get("location"),
        "occupation": raw.get("company"),
        "bio": raw.get("bio"),
        "email": raw.get("email"),
        "links": [raw["blog"]] if raw.get("blog") else [],
    }
    return {
        "platform": "GitHub",
        "username": raw.get("login"),
        "content": {key: value for key, value in content.items() if value},
        "ids_data": {},
    }


def _github_profile_confidence(
    raw: dict,
    anchors: Optional[SearchAnchors],
    base_reference: evidence_engine.ConfirmedReference,
) -> tuple[str, list[str]]:
    """Niveau de confiance d'un profil GitHub.

    GitHub n'est PLUS fiable d'office (search/users renvoie des homonymes). Un
    profil est "confirmed" UNIQUEMENT s'il matche une ancre utilisateur (pseudo,
    email, employeur ou ville). Sinon il passe par le MÊME moteur de preuves que
    les autres comptes (→ corroborated / guessed).
    """
    login = raw.get("login") or ""
    if anchors is not None:
        if anchors.username and evidence_engine.norm(login) and \
                evidence_engine.norm(login) == evidence_engine.norm(anchors.username.lstrip("@")):
            return ConfidenceLevel.CONFIRMED.value, ["login == ancre pseudo"]
        if anchors.email and raw.get("email") and \
                evidence_engine.norm_email(raw["email"]) == evidence_engine.norm_email(anchors.email):
            return ConfidenceLevel.CONFIRMED.value, ["email == ancre email"]
        if anchors.employer and evidence_engine.loose_contains(raw.get("company"), anchors.employer):
            return ConfidenceLevel.CONFIRMED.value, [f"employeur == ancre ({anchors.employer})"]
        if anchors.city and evidence_engine.loose_contains(raw.get("location"), anchors.city):
            return ConfidenceLevel.CONFIRMED.value, [f"ville == ancre ({anchors.city})"]

    # Aucun match d'ancre direct : on prouve l'appartenance comme une source ordinaire.
    return evidence_engine.evaluate_account(
        _github_account_raw(raw), raw.get("bio"), login, base_reference
    )


def _classify_github_results(
    github_results: list[OsintResult],
    anchors: Optional[SearchAnchors],
    base_reference: evidence_engine.ConfirmedReference,
) -> dict[str, str]:
    """Classe les profils GitHub (tag raw_data["confidence"]) et logge la
    répartition. Retourne {login: niveau}."""
    counts = {
        ConfidenceLevel.CONFIRMED.value: 0,
        ConfidenceLevel.CORROBORATED.value: 0,
        ConfidenceLevel.GUESSED.value: 0,
    }
    login_confidence: dict[str, str] = {}

    # Niveau calculé sur les entrées "profil" (celles portant un avatar).
    for result in github_results:
        raw = result.raw_data or {}
        login = raw.get("login")
        if not login or not raw.get("avatar_url") or login in login_confidence:
            continue
        level, reasons = _github_profile_confidence(raw, anchors, base_reference)
        login_confidence[login] = level
        counts[level] = counts.get(level, 0) + 1
        proof = f" — preuves : {'; '.join(reasons)}" if reasons else ""
        logger.info(f"[evidence] GitHub @{login} → {level}{proof}")

    # Propagation à tous les résultats partageant ce login (emails profil / commit).
    for result in github_results:
        raw = result.raw_data or {}
        login = raw.get("login")
        if login and login in login_confidence:
            raw["confidence"] = login_confidence[login]

    if login_confidence:
        logger.info(
            f"[evidence] GitHub : {counts[ConfidenceLevel.CONFIRMED.value]} confirmed, "
            f"{counts[ConfidenceLevel.CORROBORATED.value]} corroborated, "
            f"{counts[ConfidenceLevel.GUESSED.value]} guessed"
        )
    return login_confidence


def _augment_reference_with_confirmed_github(
    reference: evidence_engine.ConfirmedReference,
    github_results: list[OsintResult],
    login_confidence: dict[str, str],
) -> None:
    """Ajoute à la référence les identifiants des profils GitHub CONFIRMÉS seulement.

    Les emails/usernames de profils GitHub non confirmés (corroborated/guessed) ne
    doivent JAMAIS servir de référence : ils contamineraient la corroboration des
    autres comptes.
    """
    for result in github_results:
        raw = result.raw_data or {}
        login = raw.get("login")
        if not login or login_confidence.get(login) != ConfidenceLevel.CONFIRMED.value:
            continue
        reference.usernames.add(login)
        if raw.get("email"):
            reference.emails.add(raw["email"])
        if raw.get("blog"):
            reference.links.add(raw["blog"])
        if result.url:
            reference.links.add(result.url)


def _classify_social_accounts(
    social_results: list[OsintResult],
    reference: evidence_engine.ConfirmedReference,
) -> set[str]:
    """Étiquette chaque compte social deviné (raw_data["confidence"]) via le moteur
    de preuves, logge la répartition et la/les preuve(s), et retourne l'ensemble
    des usernames promus 'corroborated'.
    """
    counts = {
        ConfidenceLevel.CONFIRMED.value: 0,
        ConfidenceLevel.CORROBORATED.value: 0,
        ConfidenceLevel.GUESSED.value: 0,
    }
    corroborated: set[str] = set()

    for result in social_results:
        raw = result.raw_data or {}
        username = raw.get("username") or ""
        level, reasons = evidence_engine.evaluate_account(raw, result.snippet, username, reference)
        raw["confidence"] = level
        if reasons:
            raw["confidence_evidence"] = reasons
        counts[level] = counts.get(level, 0) + 1
        proof = f" — preuves : {'; '.join(reasons)}" if reasons else ""
        logger.info(f"[evidence] {raw.get('platform') or '?'} @{username} → {level}{proof}")
        if level == ConfidenceLevel.CORROBORATED.value:
            corroborated.add(username)

    logger.info(
        f"[evidence] Couche 1A : {counts[ConfidenceLevel.CONFIRMED.value]} confirmed, "
        f"{counts[ConfidenceLevel.CORROBORATED.value]} corroborated, "
        f"{counts[ConfidenceLevel.GUESSED.value]} guessed"
    )
    return corroborated


def _member_in_target(
    key: str,
    social_by_key: dict[str, OsintResult],
    github_results: list[OsintResult],
) -> bool:
    """True si le compte identifié par `key` est dans la grappe-cible (tag
    in_target_cluster posé par _assign_identity_clusters, qui doit tourner AVANT)."""
    if key.startswith("s"):
        result = social_by_key.get(key)
        return bool(result and (result.raw_data or {}).get("in_target_cluster") is True)
    if key.startswith("g"):
        login = key[1:]
        for result in github_results:
            raw = result.raw_data or {}
            if raw.get("login") == login and raw.get("in_target_cluster") is True:
                return True
    return False


def _run_convergence(
    social_results: list[OsintResult],
    github_results: list[OsintResult],
    github_login_confidence: dict[str, str],
    profile: NameProfile,
    require_target_link: bool = False,
) -> set[str]:
    """Convergence inter-comptes (Piste A) : promeut des clusters de comptes guessed
    cohérents en corroborated. Réécrit raw_data["confidence"] des comptes promus et
    retourne l'ensemble des USERNAMES sociaux promus (pour la couche 2).

    GitHub guessed participe comme les autres (jamais promu du seul fait d'être
    GitHub — il suit les mêmes règles). Aucune promotion en confirmed.

    `require_target_link` (mode A, ancre présente) : un cluster COHÉRENT n'est promu
    que s'il est rattaché à la cible (au moins un membre dans la grappe-cible). La
    cohérence interne prouve « même personne entre eux », JAMAIS « c'est la cible » :
    sans ce garde-fou, une grappe d'homonymes se promeut elle-même et envahit le
    profil. Suppose que _assign_identity_clusters a déjà tourné.
    """
    guessed = ConfidenceLevel.GUESSED.value
    descriptors: list[dict] = []
    social_by_key: dict[str, OsintResult] = {}

    for idx, result in enumerate(social_results):
        raw = result.raw_data or {}
        username = raw.get("username")
        if raw.get("confidence") != guessed or not username:
            continue
        key = f"s{idx}"
        descriptors.append({
            "key": key, "username": username,
            "content": evidence_engine.account_content_view(raw),
            "first_name": profile.first_name, "last_name": profile.last_name,
        })
        social_by_key[key] = result

    seen_logins: set[str] = set()
    for result in github_results:
        raw = result.raw_data or {}
        login = raw.get("login")
        if not login or login in seen_logins:
            continue
        if github_login_confidence.get(login) != guessed:
            continue
        seen_logins.add(login)
        descriptors.append({
            "key": f"g{login}", "username": login,
            "content": evidence_engine.account_content_view(raw),
            "first_name": profile.first_name, "last_name": profile.last_name,
        })

    if len(descriptors) < 2:
        return set()

    clusters = evidence_engine.converge_accounts(descriptors)

    promoted_social: set[str] = set()
    promoted_logins: set[str] = set()
    for cluster in clusters:
        members = cluster["members"]
        decision = "promu corroborated" if cluster["promoted"] else "laissé guessed"
        logger.info(
            f"[convergence] cluster {members} | signaux : {cluster['signals'] or ['aucun']} | {decision}"
        )
        if not cluster["promoted"]:
            continue
        # Mode A : un cluster cohérent mais non rattaché à la cible est un homonyme
        # → jamais promu (il restera guessed et sera isolé en « à vérifier »).
        if require_target_link and not any(
            _member_in_target(key, social_by_key, github_results) for key in members
        ):
            logger.info(
                f"[convergence] cluster {members} cohérent mais NON rattaché à l'ancre "
                "(mode A) → laissé guessed (homonyme isolé)"
            )
            continue
        for key in members:
            if key.startswith("s"):
                result = social_by_key.get(key)
                if result is None:
                    continue
                result.raw_data["confidence"] = ConfidenceLevel.CORROBORATED.value
                result.raw_data.setdefault("confidence_evidence", []).append(
                    "convergence : " + ", ".join(cluster["signals"])
                )
                if result.raw_data.get("username"):
                    promoted_social.add(result.raw_data["username"])
            elif key.startswith("g"):
                promoted_logins.add(key[1:])

    # Propage la promotion GitHub à toutes les entrées partageant un login promu.
    if promoted_logins:
        for result in github_results:
            raw = result.raw_data or {}
            if raw.get("login") in promoted_logins:
                raw["confidence"] = ConfidenceLevel.CORROBORATED.value
                raw.setdefault("confidence_evidence", []).append("convergence inter-comptes")
        logger.info(f"[convergence] GitHub promus corroborated : {sorted(promoted_logins)}")

    logger.info(
        f"[convergence] {len(promoted_social)} compte(s) social/aux promu(s), "
        f"{len(promoted_logins)} profil(s) GitHub promu(s)"
    )
    return promoted_social


def _assign_identity_clusters(
    social_results: list[OsintResult],
    github_results: list[OsintResult],
    profile: NameProfile,
    anchors: Optional[SearchAnchors],
    reference: evidence_engine.ConfirmedReference,
) -> None:
    """Phase A — grappes d'identité : regroupe les comptes (social + GitHub) par
    cohérence STRICTE et, si des ancres existent, injecte un nœud-ancre dont la
    grappe devient la « grappe-cible ». Tag PUREMENT ADDITIF de raw_data :
        - raw_data["cluster_id"]        : identifiant de grappe (c0, c1, …)
        - raw_data["in_target_cluster"] : bool, présent seulement en mode A (ancres)

    Aucune décision de routage ici (c'est la phase B qui exploitera ces tags).
    """
    descriptors: list[dict] = []
    social_by_key: dict[str, OsintResult] = {}

    for idx, result in enumerate(social_results):
        raw = result.raw_data or {}
        username = raw.get("username")
        if not username:
            continue
        key = f"s{idx}"
        descriptors.append({
            "key": key, "username": username,
            "content": evidence_engine.account_content_view(raw),
            "first_name": profile.first_name, "last_name": profile.last_name,
        })
        social_by_key[key] = result

    github_logins: list[str] = []
    for result in github_results:
        raw = result.raw_data or {}
        login = raw.get("login")
        if not login or login in github_logins:
            continue
        github_logins.append(login)
        descriptors.append({
            "key": f"g{login}", "username": login,
            "content": evidence_engine.account_content_view(raw),
            "first_name": profile.first_name, "last_name": profile.last_name,
        })

    # Nœud-ancre (mode A) : agrège les identifiants fiables fournis par l'utilisateur.
    anchor_key: Optional[str] = None
    if anchors is not None and not anchors.is_empty():
        content: dict = {}
        if reference.emails:
            content["email"] = sorted(reference.emails)[0]
        if anchors.city:
            content["location"] = anchors.city
        if anchors.employer:
            content["occupation"] = anchors.employer
        if profile.full_name:
            content["fullname"] = profile.full_name
        if reference.links:
            content["links"] = sorted(reference.links)
        anchor_key = "anchor"
        descriptors.append({
            "key": anchor_key, "username": (anchors.username or "").lstrip("@"),
            "content": content,
            "first_name": profile.first_name, "last_name": profile.last_name,
        })

    if len(descriptors) < 2:
        return

    clusters = evidence_engine.converge_accounts(descriptors, strict_edges=True)

    key_to_cid: dict[str, str] = {}
    target_cid: Optional[str] = None
    for i, cluster in enumerate(clusters):
        cid = f"c{i}"
        if anchor_key and anchor_key in cluster["members"]:
            target_cid = cid
        for key in cluster["members"]:
            key_to_cid[key] = cid

    def _tag(result: OsintResult, key: str) -> None:
        cid = key_to_cid.get(key)
        if not cid:
            return
        result.raw_data["cluster_id"] = cid
        if target_cid is not None:
            result.raw_data["in_target_cluster"] = (cid == target_cid)

    for key, result in social_by_key.items():
        _tag(result, key)
    login_to_cid = {login: key_to_cid.get(f"g{login}") for login in github_logins}
    for result in github_results:
        raw = result.raw_data or {}
        login = raw.get("login")
        if login and login_to_cid.get(login):
            _tag(result, f"g{login}")

    sizes: dict[str, int] = {}
    for key, cid in key_to_cid.items():
        if key == anchor_key:
            continue
        sizes[cid] = sizes.get(cid, 0) + 1
    mode = f"grappe-cible={target_cid}" if target_cid is not None else "aucune ancre (mode B)"
    logger.info(f"[clusters] {len(sizes)} grappe(s) d'identité ; tailles={sizes} ; {mode}")


def _doc_anchor_linked(
    result: OsintResult,
    anchors: Optional[SearchAnchors],
    reference: evidence_engine.ConfirmedReference,
    profile: NameProfile,
    extra_usernames: Optional[set[str]] = None,
) -> bool:
    """P5 — un document/web est rattaché à la cible s'il référence un identifiant
    ÉTABLI : pseudo distinctif (ancre, GitHub confirmé, ou compte corroboré), email
    ou URL confirmés (FORT), ou nom complet + employeur/ville d'ancre (MOYEN). Le nom
    seul ne suffit JAMAIS. Fonctionne aussi sans ancre (mode B) : on recoupe alors
    contre les identifiants prouvés durant la recherche."""
    text = " ".join(p for p in (result.title, result.snippet, result.url) if p).lower()
    if not text:
        return False
    norm_text = evidence_engine.norm(text)

    # Handles distinctifs établis : ancre pseudo + usernames confirmés (reference)
    # + usernames corroborés passés par l'orchestrateur.
    handles: set[str] = set(reference.usernames)
    if anchors is not None and anchors.username:
        handles.add(anchors.username.lstrip("@"))
    if extra_usernames:
        handles.update(extra_usernames)
    for handle in handles:
        nh = evidence_engine.norm(handle)
        if (len(nh) >= 4
                and evidence_engine.classify_pseudo(handle, profile.first_name, profile.last_name) == "distinctive"
                and nh in norm_text):
            return True

    for email in reference.emails:
        if email and email.lower() in text:
            return True

    for link in reference.links:
        parsed = urllib.parse.urlparse(link)
        token = (parsed.netloc + parsed.path).strip("/").lower()
        if len(token) >= 4 and token in text:
            return True

    if anchors is not None:
        name_present = (evidence_engine.loose_contains(text, profile.first_name, 2)
                        and evidence_engine.loose_contains(text, profile.last_name, 2))
        if name_present:
            if anchors.employer and evidence_engine.loose_contains(text, anchors.employer, 3):
                return True
            if anchors.city and evidence_engine.loose_contains(text, anchors.city, 3):
                return True

    return False


def _gate_web_documents(
    web_results: list[OsintResult],
    anchors: Optional[SearchAnchors],
    reference: evidence_engine.ConfirmedReference,
    profile: NameProfile,
    extra_usernames: Optional[set[str]] = None,
) -> None:
    """P5 — tag additif des résultats web/documents : in_target_cluster=True s'ils
    recoupent un identifiant établi, False sinon (= écartés du profil principal,
    routés en « à vérifier »).

    Précision maximale : actif AUSSI en mode B (sans ancre). Sans identifiant établi
    (ni ancre, ni GitHub confirmé, ni compte corroboré), un document au nom seul ne
    prouve pas l'appartenance → écarté du profil principal (jamais supprimé : il
    reste visible dans le flux brut).
    """
    linked = 0
    for result in web_results:
        is_linked = _doc_anchor_linked(result, anchors, reference, profile, extra_usernames)
        result.raw_data = result.raw_data or {}
        result.raw_data["in_target_cluster"] = is_linked
        linked += int(is_linked)
    logger.info(
        f"[documents] {linked}/{len(web_results)} document(s) rattaché(s) à un identifiant établi ; "
        f"{len(web_results) - linked} écarté(s) (nom seul → à vérifier)"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Phase C — checkpoint interactif de validation (plomberie pure)
# Entre couche 1 et couche 2 : si un canal de validation est armé (mode
# interactif), on présente les candidats et on SUSPEND l'orchestration jusqu'à
# une réponse humaine (ou un repli sur timeout/déconnexion). AUCUNE logique
# métier ici : la sélection est seulement journalisée. Le ré-ancrage et la
# relance ciblée viendront en Phase D. No-op total hors mode interactif.
# ─────────────────────────────────────────────────────────────────────────────
def _account_photo(raw: dict) -> Optional[str]:
    """URL d'avatar d'un compte, toutes sources confondues (social : photo_url ;
    GitHub : avatar_url). Sert de repère visuel à la validation humaine (P6)."""
    return raw.get("photo_url") or raw.get("avatar_url") or None


def _build_validation_candidates(results_l1: list[OsintResult]) -> dict:
    """Aperçu déterministe des comptes candidats à valider (social/github).

    Ne retient que les résultats porteurs d'un compte (username/login) : ce sont
    les éléments désambiguïsants qu'un humain peut cocher. Chaque candidat porte
    son avatar (P6 — repère visuel). Pur, sans appel IA.
    """
    candidates = []
    for result in results_l1:
        raw = result.raw_data or {}
        username = raw.get("username") or raw.get("login")
        if not username:
            continue
        candidates.append({
            "id": str(result.id),
            "platform": raw.get("platform") or result.module.value,
            "username": username,
            "url": result.url,
            "photo_url": _account_photo(raw),
            "confidence": raw.get("confidence"),
            "cluster_id": raw.get("cluster_id"),
            "in_target_cluster": raw.get("in_target_cluster"),
        })
    return {"candidates": candidates}


async def _interactive_checkpoint(
    websocket,
    search_id: str,
    results_l1: list[OsintResult],
) -> Optional[object]:
    """Point de pause/reprise entre couche 1 et couche 2 (Phase C).

    Si aucun canal n'est armé (mode non-interactif) ou s'il est désactivé, rend
    `None` immédiatement → l'orchestrateur poursuit comme aujourd'hui. Sinon,
    émet les candidats, attend la décision (ou un repli), et la journalise.
    """
    state = getattr(websocket, "state", None)
    channel = getattr(state, "validation_channel", None) if state is not None else None
    if channel is None or not getattr(channel, "enabled", False):
        return None

    payload = _build_validation_candidates(results_l1)
    logger.info(
        f"[checkpoint] validation interactive : {len(payload['candidates'])} candidat(s) "
        f"proposé(s), orchestration suspendue"
    )
    selection = await channel.request_validation(payload)
    if selection is None:
        logger.info("[checkpoint] aucune validation reçue (repli) — poursuite normale")
    else:
        logger.info(f"[checkpoint] validation reçue : {selection!r}")
    return selection


def _parse_validation_selection(selection) -> set:
    """Extrait l'ensemble des IDs de comptes validés depuis la réponse frontend.

    Tolérant : accepte `{"selected": [...]}`, `{"ids": [...]}` ou une liste brute.
    Tout le reste rend un ensemble vide (repli = aucune validation).
    """
    if selection is None:
        return set()
    if isinstance(selection, dict):
        ids = selection.get("selected") or selection.get("ids") or []
    elif isinstance(selection, (list, tuple, set)):
        ids = list(selection)
    else:
        return set()
    return {str(i) for i in ids if i}


def _apply_validation(
    selection,
    results_l1: list[OsintResult],
    identifiers: dict,
    profile: NameProfile,
) -> dict:
    """Phase D — applique une validation humaine entre couche 1 et couche 2.

    Les comptes COCHÉS deviennent des ancres CONFIRMÉES (signal le plus fort :
    décision humaine). On re-clusterise strictement tous les comptes ; toute
    grappe contenant un compte validé devient grappe-cible, ce qui RATTACHE
    AUTOMATIQUEMENT les comptes fortement/moyennement liés (P2) sans les avoir
    cochés. Les comptes hors-cible restent visibles (pool « non confirmé »,
    jamais supprimés). Enfin, on augmente les identifiants pour que la couche 2
    approfondisse l'identité confirmée (usernames confirmés + corroborés).

    Mutation IN PLACE de raw_data (cluster_id / in_target_cluster / confidence) :
    ces objets alimentent ensuite la couche 3 (profil IA). Rend les identifiants
    augmentés ; rend `identifiers` inchangé si rien n'est validé.
    """
    validated_ids = _parse_validation_selection(selection)
    if not validated_ids:
        return identifiers

    descriptors: list[dict] = []
    by_id: dict[str, OsintResult] = {}
    for result in results_l1:
        raw = result.raw_data or {}
        username = raw.get("username") or raw.get("login")
        if not username:
            continue
        key = str(result.id)
        descriptors.append({
            "key": key, "username": username,
            "content": evidence_engine.account_content_view(raw),
            "first_name": profile.first_name, "last_name": profile.last_name,
        })
        by_id[key] = result

    if not by_id:
        return identifiers

    clusters = evidence_engine.converge_accounts(descriptors, strict_edges=True)
    target_members: set = set()
    for cluster in clusters:
        members = set(cluster["members"])
        if validated_ids & members:
            target_members |= members

    confirmed_usernames: set = set()
    corroborated_usernames: set = set()
    validated_photos: list = []
    auto_attached = 0
    for i, cluster in enumerate(clusters):
        cid = f"c{i}"
        for key in cluster["members"]:
            result = by_id.get(key)
            if result is None:
                continue
            raw = result.raw_data
            raw["cluster_id"] = cid
            in_target = key in target_members
            raw["in_target_cluster"] = in_target
            if not in_target:
                continue
            uname = raw.get("username") or raw.get("login")
            if key in validated_ids:
                raw["confidence"] = ConfidenceLevel.CONFIRMED.value
                if uname:
                    confirmed_usernames.add(uname)
                # P6 — l'avatar du compte confirmé devient une image à corroborer
                # (reverse image + EXIF en couche 2). Décision finale = humaine.
                photo = _account_photo(raw)
                if photo and photo not in validated_photos:
                    validated_photos.append(photo)
            else:
                # Auto-rattaché à une ancre validée (signal FORT/MOYEN, P2).
                if raw.get("confidence") == ConfidenceLevel.GUESSED.value:
                    raw["confidence"] = ConfidenceLevel.CORROBORATED.value
                    auto_attached += 1
                if uname:
                    corroborated_usernames.add(uname)

    identifiers = dict(identifiers)
    identifiers["confirmed_social_usernames"] = sorted(
        set(identifiers.get("confirmed_social_usernames") or []) | confirmed_usernames
    )
    identifiers["corroborated_social_usernames"] = sorted(
        set(identifiers.get("corroborated_social_usernames") or []) | corroborated_usernames
    )
    # P6 — alimente la recherche d'image inversée de couche 2 avec les avatars
    # confirmés, sans jamais retirer les photos déjà extraites par l'IA.
    existing_photos = list(identifiers.get("photo_urls") or [])
    identifiers["photo_urls"] = existing_photos + [
        p for p in validated_photos if p not in existing_photos
    ]
    logger.info(
        f"[validation] {len(validated_ids)} compte(s) validé(s) → ancres confirmées ; "
        f"{auto_attached} compte(s) auto-rattaché(s) ; grappe-cible = "
        f"{len(target_members)} membre(s) ; {len(validated_photos)} avatar(s) à corroborer"
    )
    return identifiers


def _clean_json_text(raw_text: str) -> str:
    text = raw_text.strip()
    if text.startswith("```"):
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]
    return text.strip()


def _result_to_extraction_payload(result: OsintResult) -> dict:
    return {
        "title": result.title,
        "url": result.url,
        "snippet": (result.snippet or "")[:200],
        "module": result.module.value,
        "raw_data": result.raw_data,
    }


async def _extract_identifiers(results: list[OsintResult], profile: NameProfile, search_id: str) -> dict:
    """Appelle Claude pour extraire les identifiants confirmés à partir des résultats couche 1."""
    if not settings.anthropic_api_key:
        logger.warning("[intelligence_engine] ANTHROPIC_API_KEY absente, extraction d'identifiants ignorée")
        return dict(_EMPTY_IDENTIFIERS)

    if not results:
        return dict(_EMPTY_IDENTIFIERS)

    client = AsyncAnthropic(api_key=settings.anthropic_api_key, timeout=_LAYER1_TIMEOUT)
    payload = json.dumps(
        [_result_to_extraction_payload(r) for r in results[:_LAYER1_MAX_RESULTS]],
        ensure_ascii=False,
    )
    user_prompt = (
        f"Analyse ces résultats OSINT pour {profile.full_name} et extrais les "
        f"identifiants confirmés.\n"
        f"Résultats : {payload}\n"
        f"Réponds avec ce JSON exact :\n{_LAYER1_SCHEMA}"
    )

    try:
        response = await client.messages.create(
            model=_MODEL,
            max_tokens=_LAYER1_MAX_TOKENS,
            temperature=0,
            system=_LAYER1_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
        )
        raw_text = response.content[0].text if response.content else ""
        data = json.loads(_clean_json_text(raw_text))
    except json.JSONDecodeError:
        logger.warning("[intelligence_engine] JSON malformé pour l'extraction d'identifiants couche 1")
        return dict(_EMPTY_IDENTIFIERS)
    except Exception as e:
        logger.error(f"[intelligence_engine] Erreur extraction identifiants couche 1 : {e}")
        return dict(_EMPTY_IDENTIFIERS)

    identifiers = dict(_EMPTY_IDENTIFIERS)
    identifiers.update({k: v for k, v in data.items() if k in _EMPTY_IDENTIFIERS and v is not None})
    return identifiers


def _extract_platform_domain(result: OsintResult) -> Optional[str]:
    """Domaine de la plateforme confirmée par social_checker (ex: 'github.com')."""
    if not result.url:
        return None
    netloc = urllib.parse.urlparse(result.url).netloc.lower()
    if netloc.startswith("www."):
        netloc = netloc[4:]
    return netloc or None


def _layer1_usernames(profile: NameProfile, anchors: Optional[SearchAnchors]) -> list[str]:
    """Usernames scannés par Maigret en couche 1A.

    Le pseudo d'ancre est mis EN PREMIER : sans lui, seules les variantes dérivées
    du nom sont scannées, donc les vrais comptes de la cible (souvent sous un pseudo
    distinctif, ex. « ilyes_bzkr ») n'apparaissent qu'en couche 2 — trop tard pour
    ancrer le clustering et pour être proposés à la validation interactive. Les
    homonymes dérivés du nom dominaient alors le profil.
    """
    usernames: list[str] = []
    if anchors is not None and anchors.username:
        usernames.append(anchors.username.lstrip("@"))
    usernames += profile.username_variants[:_LAYER1_SOCIAL_VARIANTS]
    return usernames


async def run_layer1(
    profile: NameProfile,
    search_id: str,
    callback,
    websocket,
    anchors: Optional[SearchAnchors] = None,
    web_browser=None,
    web_semaphore: Optional[asyncio.Semaphore] = None,
) -> tuple[list[OsintResult], dict]:
    """Couche 1 — ancrage, en 2 sous-étapes :
    1A (parallèle)   : social (5 premiers variants) + github + paste, sur le nom brut
    1B (séquentielle): dorks web, dont les dorks plateformes sont adaptés aux comptes
                       confirmés par social_checker en 1A, plus les dorks enrichis par
                       les ancres (ville / employeur) lorsqu'elles sont fournies.

    Les dorks web réutilisent le navigateur Chromium et le sémaphore partagés
    (web_browser / web_semaphore) fournis par l'orchestrateur.
    """
    from app.api.websocket import send_progress

    for module_name in ("social", "github", "paste"):
        await send_progress(websocket, search_id, module_name, "running", f"Module {module_name} en cours...", 12)

    # Les comptes sociaux de couche 1A viennent d'usernames DEVINÉS : on ne les
    # diffuse pas immédiatement. On les bufferise (callback neutre), on les classe
    # par niveau de confiance (moteur de preuves, qui a besoin du résultat GitHub),
    # puis on les diffuse étiquetés. github/paste continuent de streamer en direct.
    social_results, github_results, paste_results = await asyncio.gather(
        _safe_run(
            check_all_platforms(
                profile, search_id, _noop_callback,
                usernames=_layer1_usernames(profile, anchors),
            ),
            "social",
        ),
        _safe_run(search_github(profile, search_id, callback), "github"),
        _safe_run(search_pastes(profile, search_id, callback), "paste"),
    )

    # Référence de preuves = ancres uniquement, puis enrichie des SEULS profils
    # GitHub confirmés (GitHub n'est pas fiable d'office : il prouve son
    # appartenance comme les autres). La classification des comptes SOCIAUX est
    # repoussée APRÈS enrichissement + web_search (voir plus bas) pour que cette
    # matière nourrisse réellement la corroboration. La classification GitHub
    # reste ICI, inchangée (préserve le correctif écart #1).
    reference = _build_anchor_reference(profile, anchors)
    github_login_confidence = _classify_github_results(github_results, anchors, reference)
    _augment_reference_with_confirmed_github(reference, github_results, github_login_confidence)

    # confirmed_platforms ne dépend PAS de la classification (juste les domaines où
    # Maigret a confirmé un compte) : calculable dès maintenant pour paramétrer les
    # dorks plateformes — pas de chicken-and-egg avec la décision de confiance.
    confirmed_platforms = sorted({
        domain
        for r in social_results
        if r.module == ModuleType.SOCIAL and (domain := _extract_platform_domain(r))
    })
    logger.info(f"[intelligence_engine] Couche 1A : plateformes confirmées = {confirmed_platforms}")

    # github/paste ont streamé en direct : on peut les marquer terminés ici.
    for module_name in ("github", "paste"):
        await send_progress(websocket, search_id, module_name, "completed", f"Module {module_name} terminé", 100)

    # ★ ENRICHISSEMENT : remplir raw_data["content"] des comptes "coquilles vides"
    # AVANT la décision de confiance, pour donner de la matière à la corroboration
    # et à la convergence inter-comptes. Ne lève jamais (isolé en interne).
    await enrich_accounts(social_results + github_results, profile)

    # web_search APRÈS enrichissement. Comme la classification est désormais
    # postérieure, ces résultats web entrent aussi dans le filtrage/extraction aval.
    await send_progress(websocket, search_id, "web_search", "running", "Dorks web (adaptatifs)...", 30)
    web_results = await _safe_run(
        run_all_dorks(
            profile, search_id, callback, priority_only=True, confirmed_platforms=confirmed_platforms,
            browser=web_browser, semaphore=web_semaphore,
        ),
        "web_search",
    )

    # Dorks enrichis par les ancres : nom + ville et/ou employeur, très discriminants.
    anchored_dork_results = await _run_anchored_dorks(
        profile, search_id, callback, websocket, anchors, web_browser, web_semaphore
    )

    await send_progress(websocket, search_id, "web_search", "completed", "Module web_search terminé", 100)

    # ★ Décision de confiance des comptes SOCIAUX APRÈS enrichissement + web_search
    # (confirmed / corroborated / guessed). C'est ici que l'enrichissement porte.
    corroborated_usernames = _classify_social_accounts(social_results, reference)

    # ★ Phase A — grappes d'identité : tag additif cluster_id / in_target_cluster
    # (désambiguïsation homonymes). Doit tourner AVANT la convergence pour que
    # celle-ci puisse vérifier le rattachement à la grappe-cible (mode A).
    try:
        _assign_identity_clusters(social_results, github_results, profile, anchors, reference)
    except Exception as e:
        logger.warning(f"[clusters] échec (ignoré) : {e}")

    # ★ Convergence inter-comptes : promeut des clusters de guessed mutuellement
    # cohérents en corroborated (jamais confirmed). En mode A (ancre présente), un
    # cluster n'est promu QUE s'il est rattaché à la grappe-cible : la cohérence
    # interne ne prouve pas l'appartenance à la cible (sinon les homonymes se
    # promeuvent eux-mêmes). Isolée : un échec ne casse pas le pipeline.
    anchored = anchors is not None and not anchors.is_empty()
    try:
        promoted = _run_convergence(
            social_results, github_results, github_login_confidence, profile,
            require_target_link=anchored,
        )
        corroborated_usernames |= promoted
    except Exception as e:
        logger.warning(f"[convergence] échec (ignoré) : {e}")

    # ★ Phase B — gating documentaire (P5) : un document/web n'entre dans le profil
    # cible que s'il recoupe un identifiant établi (ancre, GitHub confirmé, ou
    # username corroboré) ; sinon écarté du profil principal. Actif aussi sans ancre.
    try:
        _gate_web_documents(
            web_results + anchored_dork_results, anchors, reference, profile,
            extra_usernames=corroborated_usernames,
        )
    except Exception as e:
        logger.warning(f"[documents] gating échoué (ignoré) : {e}")

    # Diffusion (et persistance) des comptes désormais étiquetés.
    for result in social_results:
        callback(result)
    await send_progress(websocket, search_id, "social", "completed", "Module social terminé", 100)

    results_l1 = social_results + github_results + paste_results + web_results + anchored_dork_results

    # Filtrage IA avant extraction pour ancrer le prompt sur des résultats pertinents
    # (le scraping web et les pastes renvoient souvent des pages hors-sujet).
    anchored_results = await filter_results(results_l1, profile, search_id, anchors=anchors)
    identifiers = await _extract_identifiers(anchored_results, profile, search_id)

    # Seuls les usernames FIABLES alimenteront la couche 2 : confirmés (GitHub /
    # ancre) et corroborés par preuve. Les "guessed" (homonymes) sont exclus de
    # tout approfondissement — ils ne servent QU'À l'affichage en section séparée.
    identifiers["confirmed_social_usernames"] = sorted(reference.usernames)
    identifiers["corroborated_social_usernames"] = sorted(corroborated_usernames)

    return results_l1, identifiers


async def _run_anchored_dorks(
    profile: NameProfile,
    search_id: str,
    callback,
    websocket,
    anchors: Optional[SearchAnchors],
    web_browser=None,
    web_semaphore: Optional[asyncio.Semaphore] = None,
) -> list[OsintResult]:
    """Exécute les dorks enrichis (nom + ville/employeur) issus de name_engine.

    Les dorks partagent le navigateur et le sémaphore web de la recherche.
    """
    from app.api.websocket import send_progress

    if anchors is None or (not anchors.city and not anchors.employer):
        return []

    dorks = generate_anchored_dorks(
        profile.first_name, profile.last_name, city=anchors.city, employer=anchors.employer
    )
    if not dorks:
        return []

    await send_progress(
        websocket, search_id, "web_search", "running",
        f"Dorks enrichis par les ancres ({len(dorks)})...", 35,
    )
    logger.info(f"[intelligence_engine] Couche 1 : {len(dorks)} dork(s) enrichi(s) par les ancres : {dorks}")

    dork_lists = await asyncio.gather(
        *[
            _safe_run(
                run_manual_dork(q, search_id, callback, browser=web_browser, semaphore=web_semaphore),
                "anchored_dork",
            )
            for q in dorks
        ]
    )
    return [r for sublist in dork_lists for r in sublist]


async def _extract_video_frames(video_url: str, count: int) -> list[str]:
    """Extrait `count` frames clés d'une vidéo via ffmpeg, dans un répertoire temporaire."""
    with TemporaryDirectory() as tmpdir:
        pattern = f"{tmpdir}/frame_%02d.jpg"
        try:
            process = await asyncio.create_subprocess_exec(
                "ffmpeg", "-v", "quiet", "-i", video_url,
                "-vf", f"select='not(mod(n,30))'", "-vsync", "vfr",
                "-frames:v", str(count), pattern,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(process.communicate(), timeout=60.0)
        except FileNotFoundError:
            logger.warning("[intelligence_engine] ffmpeg non installé, extraction de frames vidéo désactivée")
            return []
        except asyncio.TimeoutError:
            logger.warning(f"[intelligence_engine] timeout ffmpeg pour '{video_url}'")
            return []
        except Exception as e:
            logger.warning(f"[intelligence_engine] erreur ffmpeg pour '{video_url}' : {e}")
            return []

        import os
        return [f"{tmpdir}/{name}" for name in sorted(os.listdir(tmpdir))]


async def _process_video(video_url: str, search_id: str) -> list[OsintResult]:
    """Métadonnées vidéo + tentative d'extraction de frames clés via ffmpeg."""
    results = await exif_extractor.extract_video_metadata(video_url, search_id)

    frames = await _extract_video_frames(video_url, _VIDEO_FRAME_COUNT)
    if frames:
        # Les frames extraites sont locales : la recherche inversée (Yandex/Lens) exige
        # une URL publique. Sans étape d'hébergement, on se limite aux métadonnées vidéo.
        logger.warning(
            f"[intelligence_engine] {len(frames)} frames extraites pour '{video_url}', "
            "recherche inversée ignorée (nécessite un hébergement public des frames)"
        )

    return results


async def run_layer2(
    identifiers: dict,
    profile: NameProfile,
    search_id: str,
    callback,
    websocket,
    anchors: Optional[SearchAnchors] = None,
    web_browser=None,
    web_semaphore: Optional[asyncio.Semaphore] = None,
) -> list[OsintResult]:
    """Couche 2 — approfondissement ciblé à partir des identifiants confirmés en couche 1.

    Les ancres fournies par l'utilisateur pré-remplissent directement les
    identifiants : un pseudo connu est traité comme un username confirmé, un
    email connu comme un email confirmé, etc. On déduplique pour ne jamais
    relancer deux fois la même recherche.

    Les dorks web (ville, employeur, téléphone) ET la recherche d'image inversée
    réutilisent le navigateur Chromium partagé (web_browser) fourni par
    l'orchestrateur, plafonnés par web_semaphore pour les requêtes Bing.
    """
    from app.api.websocket import send_progress

    emails = list(identifiers.get("emails") or [])
    phones = identifiers.get("phone_numbers") or []
    photos = (identifiers.get("photo_urls") or [])[:_LAYER2_MAX_IMAGES]
    videos = (identifiers.get("video_urls") or [])[:_LAYER2_MAX_VIDEOS]

    # Usernames sociaux FIABLES uniquement (classés en couche 1) : confirmés
    # (GitHub / ancre) et corroborés par preuve. Les comptes "guessed" (homonymes
    # potentiels) ne déclenchent AUCUNE recherche de couche 2.
    confirmed_social = list(identifiers.get("confirmed_social_usernames") or [])
    corroborated_social = list(identifiers.get("corroborated_social_usernames") or [])

    # Villes / employeurs : on combine ceux extraits par l'IA et ceux fournis en ancre.
    cities = [identifiers["city"]] if identifiers.get("city") else []
    employers = [identifiers["employer"]] if identifiers.get("employer") else []

    # === Pré-remplissage par les ancres (Levier 1) ===
    # NB : l'ancre username est déjà intégrée aux usernames confirmés en couche 1.
    if anchors is not None:
        if anchors.email and anchors.email.lower() not in {e.lower() for e in emails}:
            emails.append(anchors.email)
            logger.info(f"[intelligence_engine] Couche 2 : email ancre injecté ({anchors.email})")
        if anchors.city and anchors.city.lower() not in {c.lower() for c in cities}:
            cities.append(anchors.city)
        if anchors.employer and anchors.employer.lower() not in {e.lower() for e in employers}:
            employers.append(anchors.employer)

    await send_progress(
        websocket, search_id, "intelligence_engine", "running",
        f"Couche 2 : {len(emails)} email(s), "
        f"{len(confirmed_social) + len(corroborated_social)} username(s) fiable(s), "
        f"{len(photos)} photo(s), {len(videos)} vidéo(s) à approfondir...", 45,
    )

    tasks = []

    for email in emails:
        tasks.append(_safe_run(_dispatch(holehe_checker.check_email(email, search_id), callback), "holehe"))
        tasks.append(_safe_run(_dispatch(gravatar_checker.check_gravatar(email, search_id), callback), "gravatar"))
        tasks.append(_safe_run(check_breaches([email], [], search_id, callback), "breach"))

    # Approfondissement social sur usernames FIABLES uniquement : confirmés d'abord,
    # puis corroborés, dans la limite de _LAYER2_MAX_SOCIAL_USERNAMES au total.
    # Chaque compte trouvé hérite du niveau de confiance de l'username scanné.
    take_confirmed = confirmed_social[:_LAYER2_MAX_SOCIAL_USERNAMES]
    take_corroborated = corroborated_social[: max(0, _LAYER2_MAX_SOCIAL_USERNAMES - len(take_confirmed))]
    if take_confirmed:
        tasks.append(_safe_run(
            check_all_platforms(
                profile, search_id, callback,
                usernames=take_confirmed, top_sites=_LAYER2_SOCIAL_TOP_SITES,
                confidence=ConfidenceLevel.CONFIRMED.value,
            ),
            "social_confirmed",
        ))
    if take_corroborated:
        tasks.append(_safe_run(
            check_all_platforms(
                profile, search_id, callback,
                usernames=take_corroborated, top_sites=_LAYER2_SOCIAL_TOP_SITES,
                confidence=ConfidenceLevel.CORROBORATED.value,
            ),
            "social_corroborated",
        ))

    for phone in phones:
        tasks.append(_safe_run(
            run_manual_dork(f'"{phone}"', search_id, callback, browser=web_browser, semaphore=web_semaphore),
            "phone_dork",
        ))

    for city in cities:
        tasks.append(_safe_run(
            run_all_dorks(
                profile, search_id, callback, priority_only=True, city_override=city,
                browser=web_browser, semaphore=web_semaphore,
            ),
            "city_dork",
        ))

    for employer in employers:
        tasks.append(_safe_run(
            run_manual_dork(
                f'"{profile.full_name}" "{employer}"', search_id, callback,
                browser=web_browser, semaphore=web_semaphore,
            ),
            "employer_dork",
        ))

    # Recherche d'image inversée : réutilise le navigateur partagé. S'il est
    # indisponible (échec de démarrage), on lance un navigateur image dédié en
    # repli, fermé localement — le navigateur partagé n'est jamais fermé ici.
    image_browser = web_browser
    own_image_playwright = None
    if (photos or videos) and image_browser is None:
        try:
            own_image_playwright = await async_playwright().start()
            image_browser = await own_image_playwright.chromium.launch()
        except Exception as e:
            logger.error(f"[intelligence_engine] Navigateur image indisponible : {e}")
            image_browser = None

    try:
        for photo_url in photos:
            if image_browser is not None:
                tasks.append(_safe_run(
                    _dispatch(reverse_image.search_all_engines(photo_url, search_id, image_browser), callback),
                    "reverse_image",
                ))
            tasks.append(_safe_run(_dispatch(exif_extractor.extract_from_url(photo_url, search_id), callback), "exif"))

        for video_url in videos:
            tasks.append(_safe_run(_dispatch(_process_video(video_url, search_id), callback), "video"))

        results_lists = await asyncio.gather(*tasks) if tasks else []
    finally:
        # On ne ferme QUE le navigateur de repli local, jamais le navigateur partagé.
        if own_image_playwright is not None:
            try:
                if image_browser is not None:
                    await image_browser.close()
            finally:
                await own_image_playwright.stop()

    results_l2 = [r for sublist in results_lists for r in sublist]
    logger.info(f"[intelligence_engine] Couche 2 : {len(results_l2)} résultats")
    return results_l2


async def run_layer3(
    results_l1: list[OsintResult],
    results_l2: list[OsintResult],
    profile: NameProfile,
    search_id: str,
    websocket,
    request: SearchRequest,
) -> Optional[float]:
    """Couche 3 — consolidation : filtrage IA + profil IA + rapport (réutilise _run_ai_pipeline)."""
    from app.api.websocket import _run_ai_pipeline

    all_results = results_l1 + results_l2
    return await _run_ai_pipeline(websocket, search_id, profile, request, all_results)


async def run_intelligence_engine(websocket, request: SearchRequest, search_id: str) -> tuple[int, Optional[float]]:
    """Orchestrateur principal : ancrage (couche 1) → approfondissement (couche 2) → consolidation IA (couche 3)."""
    from app.api.websocket import send_error, send_message, send_progress

    pending_tasks: list[asyncio.Task] = []
    callback = _make_callback(pending_tasks, websocket, search_id)

    # Ancres de vérité (toutes optionnelles). Robuste à une requête sans ancres.
    anchors = getattr(request, "anchors", None)
    if anchors is not None and not anchors.is_empty():
        logger.info(f"[intelligence_engine] Ancres actives : {', '.join(anchors.active_labels())}")

    await send_progress(websocket, search_id, "name_engine", "running", "Génération du profil de recherche...", 0)
    try:
        profile = generate_search_profile(request.name)
        await send_progress(websocket, search_id, "name_engine", "completed", "Profil généré", 100)
    except Exception as e:
        logger.error(f"[intelligence_engine] Erreur name_engine : {e}")
        await send_error(websocket, search_id, "name_engine", str(e))
        await send_message(websocket, WebSocketMessage(
            type="complete", search_id=search_id, message="Recherche terminée",
            data={"total_results": 0, "risk_score": None},
        ))
        return 0, None

    # Un unique navigateur Chromium + un sémaphore partagés par tous les dorks
    # web de la recherche (couches 1 et 2). Fermés une seule fois en finally.
    web_playwright, web_browser = await _start_shared_browser()
    web_semaphore = asyncio.Semaphore(_WEB_MAX_CONCURRENT)
    try:
        await send_progress(websocket, search_id, "intelligence_engine", "running", "Couche 1 : ancrage...", 10)
        results_l1, identifiers = await run_layer1(
            profile, search_id, callback, websocket, anchors, web_browser, web_semaphore
        )
        await send_progress(websocket, search_id, "intelligence_engine", "running", "Couche 1 terminée", 40)

        # Phases C+D — checkpoint interactif (no-op hors mode interactif). La
        # validation humaine re-ancre l'identité-cible et augmente les
        # identifiants AVANT la couche 2 (qui approfondit l'identité confirmée).
        # Isolé en try/except : une erreur ne doit JAMAIS rompre le pipeline.
        try:
            selection = await _interactive_checkpoint(websocket, search_id, results_l1)
            if selection:
                identifiers = _apply_validation(selection, results_l1, identifiers, profile)
        except Exception as e:
            logger.warning(f"[checkpoint] validation ignorée sur erreur : {e}")

        await send_progress(websocket, search_id, "intelligence_engine", "running", "Couche 2 : approfondissement...", 45)
        results_l2 = await run_layer2(
            identifiers, profile, search_id, callback, websocket, anchors, web_browser, web_semaphore
        )
        await send_progress(websocket, search_id, "intelligence_engine", "running", "Couche 2 terminée", 70)

        if pending_tasks:
            await asyncio.gather(*pending_tasks)

        await send_progress(websocket, search_id, "intelligence_engine", "running", "Couche 3 : consolidation IA...", 75)
        ai_risk_score = await run_layer3(results_l1, results_l2, profile, search_id, websocket, request)
    finally:
        await _close_shared_browser(web_playwright, web_browser)

    total_results = len(results_l1) + len(results_l2)
    await send_message(websocket, WebSocketMessage(
        type="complete",
        search_id=search_id,
        message="Recherche terminée",
        data={"total_results": total_results, "risk_score": ai_risk_score},
    ))

    return total_results, ai_risk_score
