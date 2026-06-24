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
from tempfile import TemporaryDirectory
from typing import Optional

from anthropic import AsyncAnthropic
from playwright.async_api import async_playwright

from app.ai.analyzer import filter_results
from app.core.config import settings
from app.core.logger import logger
from app.models.result import OsintResult, WebSocketMessage
from app.models.search import NameProfile, SearchRequest
from app.modules import exif_extractor, gravatar_checker, holehe_checker, reverse_image
from app.modules.breach_checker import check_breaches
from app.modules.github_search import search_github
from app.modules.name_engine import generate_search_profile
from app.modules.social_checker import check_all_platforms
from app.modules.web_search import run_all_dorks, run_manual_dork

__all__ = ["run_intelligence_engine"]

_MODEL = "claude-sonnet-4-6"
_LAYER1_MAX_TOKENS = 500
_LAYER1_TIMEOUT = 60.0
_LAYER1_MAX_RESULTS = 80
_LAYER1_SOCIAL_VARIANTS = 5
_VIDEO_FRAME_COUNT = 3

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


async def run_layer1(
    profile: NameProfile,
    search_id: str,
    callback,
    websocket,
) -> tuple[list[OsintResult], dict]:
    """Couche 1 — ancrage : dorks prioritaires + github + social (5 premiers variants)."""
    from app.api.websocket import send_progress

    for module_name in ("web_search", "github", "social"):
        await send_progress(websocket, search_id, module_name, "running", f"Module {module_name} en cours...", 15)

    web_results, github_results, social_results = await asyncio.gather(
        _safe_run(run_all_dorks(profile, search_id, callback, priority_only=True), "web_search"),
        _safe_run(search_github(profile, search_id, callback), "github"),
        _safe_run(
            check_all_platforms(profile, search_id, callback, max_variants=_LAYER1_SOCIAL_VARIANTS),
            "social",
        ),
    )

    for module_name in ("web_search", "github", "social"):
        await send_progress(websocket, search_id, module_name, "completed", f"Module {module_name} terminé", 100)

    results_l1 = web_results + github_results + social_results

    # Filtrage IA avant extraction pour ancrer le prompt sur des résultats pertinents
    # (le scraping web renvoie souvent des pages hors-sujet).
    anchored_results = await filter_results(results_l1, profile, search_id)
    identifiers = await _extract_identifiers(anchored_results, profile, search_id)

    return results_l1, identifiers


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
) -> list[OsintResult]:
    """Couche 2 — approfondissement ciblé à partir des identifiants confirmés en couche 1."""
    from app.api.websocket import send_progress

    emails = identifiers.get("emails") or []
    usernames = [u.get("value") for u in identifiers.get("usernames_confirmed") or [] if u.get("value")]
    phones = identifiers.get("phone_numbers") or []
    photos = identifiers.get("photo_urls") or []
    videos = identifiers.get("video_urls") or []
    city = identifiers.get("city")
    employer = identifiers.get("employer")

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
        tasks.append(_safe_run(run_manual_dork(f'"{phone}"', search_id, callback), "phone_dork"))

    if city:
        tasks.append(_safe_run(
            run_all_dorks(profile, search_id, callback, priority_only=True, city_override=city),
            "city_dork",
        ))

    if employer:
        tasks.append(_safe_run(
            run_manual_dork(f'"{profile.full_name}" "{employer}"', search_id, callback),
            "employer_dork",
        ))

    browser = None
    playwright_ctx = None
    if photos or videos:
        playwright_ctx = await async_playwright().start()
        browser = await playwright_ctx.chromium.launch()

    try:
        for photo_url in photos:
            tasks.append(_safe_run(
                _dispatch(reverse_image.search_all_engines(photo_url, search_id, browser), callback),
                "reverse_image",
            ))
            tasks.append(_safe_run(_dispatch(exif_extractor.extract_from_url(photo_url, search_id), callback), "exif"))

        for video_url in videos:
            tasks.append(_safe_run(_dispatch(_process_video(video_url, search_id), callback), "video"))

        results_lists = await asyncio.gather(*tasks) if tasks else []
    finally:
        if browser:
            await browser.close()
        if playwright_ctx:
            await playwright_ctx.stop()

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

    await send_progress(websocket, search_id, "intelligence_engine", "running", "Couche 1 : ancrage...", 10)
    results_l1, identifiers = await run_layer1(profile, search_id, callback, websocket)
    await send_progress(websocket, search_id, "intelligence_engine", "running", "Couche 1 terminée", 40)

    await send_progress(websocket, search_id, "intelligence_engine", "running", "Couche 2 : approfondissement...", 45)
    results_l2 = await run_layer2(identifiers, profile, search_id, callback, websocket)
    await send_progress(websocket, search_id, "intelligence_engine", "running", "Couche 2 terminée", 70)

    if pending_tasks:
        await asyncio.gather(*pending_tasks)

    await send_progress(websocket, search_id, "intelligence_engine", "running", "Couche 3 : consolidation IA...", 75)
    ai_risk_score = await run_layer3(results_l1, results_l2, profile, search_id, websocket, request)

    total_results = len(results_l1) + len(results_l2)
    await send_message(websocket, WebSocketMessage(
        type="complete",
        search_id=search_id,
        message="Recherche terminée",
        data={"total_results": total_results, "risk_score": ai_risk_score},
    ))

    return total_results, ai_risk_score
