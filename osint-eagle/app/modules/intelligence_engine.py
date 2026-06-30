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


def _run_convergence(
    social_results: list[OsintResult],
    github_results: list[OsintResult],
    github_login_confidence: dict[str, str],
    profile: NameProfile,
) -> set[str]:
    """Convergence inter-comptes (Piste A) : promeut des clusters de comptes guessed
    cohérents en corroborated. Réécrit raw_data["confidence"] des comptes promus et
    retourne l'ensemble des USERNAMES sociaux promus (pour la couche 2).

    GitHub guessed participe comme les autres (jamais promu du seul fait d'être
    GitHub — il suit les mêmes règles). Aucune promotion en confirmed.
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


# ─────────────────────────────────────────────────────────────────────────────
# DIAGNOSTIC TEMPORAIRE [DIAG-ATTR] — mesure la richesse RÉELLE des attributs des
# comptes évalués en couche 1A (combien portent fullname/ville/bio/occupation/
# email/lien, combien ont un content vide = platform+username+url seulement).
# But : chiffrer l'ampleur de l'enrichissement à construire avant la convergence
# inter-comptes (Piste A). N'altère AUCUNE décision : pure observation.
# À RETIRER une fois les chiffres lus (le helper + son appel dans run_layer1).
# ─────────────────────────────────────────────────────────────────────────────
def _diag_attr_view(result: OsintResult, source: str) -> dict:
    """Vue normalisée des attributs d'un compte, quelle que soit sa source
    (GitHub a ses champs à plat ; Maigret les expose sous raw_data['content'])."""
    raw = result.raw_data or {}
    if source == "GitHub":
        return {
            "platform": "GitHub",
            "username": raw.get("login") or "?",
            "fullname": raw.get("name"),
            "ville": raw.get("location"),
            "bio": raw.get("bio"),
            "occupation": raw.get("company"),
            "email": raw.get("email"),
            "links": [raw["blog"]] if raw.get("blog") else [],
            "avatar": raw.get("avatar_url"),
        }
    content = raw.get("content") or {}
    return {
        "platform": raw.get("platform") or "?",
        "username": raw.get("username") or "?",
        "fullname": content.get("fullname"),
        "ville": content.get("location"),
        "bio": content.get("bio"),
        "occupation": content.get("occupation"),
        "email": content.get("email"),
        "links": content.get("links") or [],
        "avatar": raw.get("photo_url"),
    }


def _diag_log_account_attributes(
    social_results: list[OsintResult],
    github_results: list[OsintResult],
) -> None:
    """Logge une ligne [DIAG-ATTR] par compte évalué puis une synthèse chiffrée.

    DIAGNOSTIC TEMPORAIRE : observe la présence des attributs, ne modifie rien.
    """
    def _on(value) -> str:
        return "oui" if value else "non"

    views: list[tuple[str, dict]] = []

    # GitHub : on ne compte que les profils RÉELLEMENT évalués par
    # _classify_github_results (entrées "profil" portant un avatar, dédupliquées
    # par login) — pas les entrées email/commit qui partagent le même login.
    seen_logins: set = set()
    for result in github_results:
        raw = result.raw_data or {}
        login = raw.get("login")
        if not login or not raw.get("avatar_url") or login in seen_logins:
            continue
        seen_logins.add(login)
        views.append(("GitHub", _diag_attr_view(result, "GitHub")))

    for result in social_results:
        views.append(("Maigret", _diag_attr_view(result, "Maigret")))

    counts = {"fullname": 0, "ville": 0, "bio": 0, "occupation": 0, "email": 0, "links": 0, "avatar": 0}
    with_attr = 0
    n_maigret = 0
    n_github = 0

    for source, a in views:
        if source == "GitHub":
            n_github += 1
        else:
            n_maigret += 1

        content_present = any([a["fullname"], a["ville"], a["bio"], a["occupation"], a["email"], a["links"]])
        if content_present:
            with_attr += 1
        for key in ("fullname", "ville", "bio", "occupation", "email", "avatar"):
            if a[key]:
                counts[key] += 1
        if len(a["links"]) >= 1:
            counts["links"] += 1

        logger.info(
            f"[DIAG-ATTR] {a['platform']} @{a['username']} | "
            f"fullname={_on(a['fullname'])} ville={_on(a['ville'])} bio={_on(a['bio'])} "
            f"occupation/employer={_on(a['occupation'])} email={_on(a['email'])} "
            f"liens_croisés={len(a['links'])} avatar={_on(a['avatar'])} | "
            f"content_vide={_on(not content_present)}"
        )

    total = len(views)
    logger.info("[DIAG-ATTR] === SYNTHÈSE ===")
    logger.info(f"[DIAG-ATTR] Total comptes évalués : {total}")
    logger.info(
        "[DIAG-ATTR] Avec au moins un attribut exploitable "
        f"(fullname|ville|bio|occupation|email|lien) : {with_attr} / {total}"
    )
    logger.info(
        "[DIAG-ATTR] content totalement vide (platform+username+url seulement) : "
        f"{total - with_attr} / {total}"
    )
    logger.info(
        f"[DIAG-ATTR] Détail par attribut : fullname={counts['fullname']}, "
        f"ville={counts['ville']}, bio={counts['bio']}, occupation={counts['occupation']}, "
        f"email={counts['email']}, liens_croisés≥1={counts['links']}, avatar={counts['avatar']}"
    )
    logger.info(
        f"[DIAG-ATTR] Répartition des sources : Maigret={n_maigret} comptes, "
        f"GitHub={n_github} profils"
    )


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
            check_all_platforms(profile, search_id, _noop_callback, max_variants=_LAYER1_SOCIAL_VARIANTS),
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

    # DIAGNOSTIC TEMPORAIRE [DIAG-ATTR] : mesure la richesse des attributs APRÈS
    # enrichissement (à retirer une fois les chiffres lus). N'altère aucune décision ;
    # isolé en try/except pour ne jamais casser le pipeline.
    try:
        _diag_log_account_attributes(social_results, github_results)
    except Exception as e:
        logger.warning(f"[DIAG-ATTR] échec du diagnostic d'attributs : {e}")

    # ★ Convergence inter-comptes : promeut des clusters de guessed mutuellement
    # cohérents en corroborated (jamais confirmed). Alimente le profil principal via
    # le routage corroborated EXISTANT. Isolée : un échec ne casse pas le pipeline.
    try:
        promoted = _run_convergence(social_results, github_results, github_login_confidence, profile)
        corroborated_usernames |= promoted
    except Exception as e:
        logger.warning(f"[convergence] échec (ignoré) : {e}")

    # ★ Phase A — grappes d'identité : tag additif cluster_id / in_target_cluster
    # (désambiguïsation homonymes). Aucune décision de routage ici (phase B).
    try:
        _assign_identity_clusters(social_results, github_results, profile, anchors, reference)
    except Exception as e:
        logger.warning(f"[clusters] échec (ignoré) : {e}")

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
    photos = identifiers.get("photo_urls") or []
    videos = identifiers.get("video_urls") or []

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
