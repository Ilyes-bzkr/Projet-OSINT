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
from app.models.result import ModuleType, OsintResult, WebSocketMessage
from app.models.search import NameProfile, SearchAnchors, SearchRequest
from app.modules import exif_extractor, gravatar_checker, holehe_checker, reverse_image
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

    social_results, github_results, paste_results = await asyncio.gather(
        _safe_run(
            check_all_platforms(profile, search_id, callback, max_variants=_LAYER1_SOCIAL_VARIANTS),
            "social",
        ),
        _safe_run(search_github(profile, search_id, callback), "github"),
        _safe_run(search_pastes(profile, search_id, callback), "paste"),
    )

    for module_name in ("social", "github", "paste"):
        await send_progress(websocket, search_id, module_name, "completed", f"Module {module_name} terminé", 100)

    confirmed_platforms = sorted({
        domain
        for r in social_results
        if r.module == ModuleType.SOCIAL and (domain := _extract_platform_domain(r))
    })
    logger.info(f"[intelligence_engine] Couche 1A : plateformes confirmées = {confirmed_platforms}")

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

    results_l1 = social_results + github_results + paste_results + web_results + anchored_dork_results

    # Filtrage IA avant extraction pour ancrer le prompt sur des résultats pertinents
    # (le scraping web et les pastes renvoient souvent des pages hors-sujet).
    anchored_results = await filter_results(results_l1, profile, search_id, anchors=anchors)
    identifiers = await _extract_identifiers(anchored_results, profile, search_id)

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
    usernames = [u.get("value") for u in identifiers.get("usernames_confirmed") or [] if u.get("value")]
    phones = identifiers.get("phone_numbers") or []
    photos = identifiers.get("photo_urls") or []
    videos = identifiers.get("video_urls") or []

    # Villes / employeurs : on combine ceux extraits par l'IA et ceux fournis en ancre.
    cities = [identifiers["city"]] if identifiers.get("city") else []
    employers = [identifiers["employer"]] if identifiers.get("employer") else []

    # === Pré-remplissage par les ancres (Levier 1) ===
    if anchors is not None:
        if anchors.email and anchors.email.lower() not in {e.lower() for e in emails}:
            emails.append(anchors.email)
            logger.info(f"[intelligence_engine] Couche 2 : email ancre injecté ({anchors.email})")
        if anchors.username:
            anchor_user = anchors.username.lstrip("@")
            if anchor_user and anchor_user.lower() not in {u.lstrip("@").lower() for u in usernames}:
                usernames.append(anchor_user)
                logger.info(f"[intelligence_engine] Couche 2 : pseudo ancre injecté ({anchor_user})")
        if anchors.city and anchors.city.lower() not in {c.lower() for c in cities}:
            cities.append(anchors.city)
        if anchors.employer and anchors.employer.lower() not in {e.lower() for e in employers}:
            employers.append(anchors.employer)

    await send_progress(
        websocket, search_id, "intelligence_engine", "running",
        f"Couche 2 : {len(emails)} email(s), {len(usernames)} username(s), "
        f"{len(photos)} photo(s), {len(videos)} vidéo(s) à approfondir...", 45,
    )

    tasks = []

    for email in emails:
        tasks.append(_safe_run(_dispatch(holehe_checker.check_email(email, search_id), callback), "holehe"))
        tasks.append(_safe_run(_dispatch(gravatar_checker.check_gravatar(email, search_id), callback), "gravatar"))
        tasks.append(_safe_run(check_breaches([email], [], search_id, callback), "breach"))

    for username in usernames:
        tasks.append(_safe_run(
            check_all_platforms(profile, search_id, callback, username_override=username),
            "social_username",
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
