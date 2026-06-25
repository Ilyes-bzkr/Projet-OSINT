"""
Handler WebSocket — OSINT Eagle.
Orchestre tous les modules OSINT et streame les résultats en temps réel.
"""

import asyncio
import json
import uuid
from datetime import datetime
from typing import Callable, Optional

from fastapi import WebSocket, WebSocketDisconnect

from app.ai.analyzer import filter_results
from app.ai.profiler import build_profile
from app.ai.reporter import generate_report_html
from app.core.config import settings
from app.core.database import AsyncSessionLocal, SearchRecord, ResultRecord, init_db
from app.core.logger import logger
from app.models.result import ModuleType, OsintResult, ResultCategory, WebSocketMessage
from app.models.search import SearchRequest
from app.modules.breach_checker import check_breaches
from app.modules.github_search import search_github
from app.modules.name_engine import generate_search_profile
from app.modules.paste_search import search_pastes
from app.modules.social_checker import check_all_platforms
from app.modules.web_search import run_all_dorks


async def send_message(websocket: WebSocket, msg: WebSocketMessage):
    """Envoie un message JSON via WebSocket, si la connexion est toujours active.

    Garde-fou : on n'émet jamais sur une socket déjà marquée fermée, et à la
    PREMIÈRE erreur d'envoi on bascule l'indicateur `is_connected` à False. Les
    émissions suivantes (souvent des dizaines, lancées en parallèle par les
    callbacks de streaming) court-circuitent alors sans log, ce qui évite la
    marée de « Cannot call send once a close message has been sent ». Les modules
    continuent de tourner et de persister en base : seule l'émission WS est coupée.
    """
    if not getattr(websocket.state, "is_connected", True):
        return
    try:
        await websocket.send_text(msg.model_dump_json())
    except Exception as e:
        # On ne logge qu'au moment où l'on bascule l'état (premier échec), pas à
        # chaque envoi concurrent qui échouerait après la fermeture.
        if getattr(websocket.state, "is_connected", True):
            logger.warning(f"WebSocket fermé, arrêt des émissions : {e}")
        websocket.state.is_connected = False


async def send_progress(
    websocket: WebSocket,
    search_id: str,
    module: str,
    status: str,
    message: str,
    progress: int
):
    """Envoie une mise à jour de progression."""
    await send_message(websocket, WebSocketMessage(
        type="progress",
        module=module,
        search_id=search_id,
        message=message,
        progress=progress,
        data={"status": status}
    ))


async def send_result(websocket: WebSocket, search_id: str, module: str, result: dict):
    """Envoie un résultat trouvé."""
    await send_message(websocket, WebSocketMessage(
        type="result",
        module=module,
        search_id=search_id,
        data=result
    ))


async def send_error(websocket: WebSocket, search_id: str, module: str, error: str):
    """Envoie une erreur non-bloquante."""
    await send_message(websocket, WebSocketMessage(
        type="error",
        module=module,
        search_id=search_id,
        message=error
    ))


async def _save_result_to_db(result: OsintResult):
    """Sauvegarde un résultat OSINT dans la table results."""
    try:
        async with AsyncSessionLocal() as session:
            record = ResultRecord(
                id=result.id,
                search_id=result.search_id,
                module=result.module.value,
                category=result.category.value,
                title=result.title,
                url=result.url,
                snippet=result.snippet,
                raw_data=json.dumps(result.raw_data) if result.raw_data else None,
                relevance_score=result.relevance_score,
                is_sensitive=result.is_sensitive,
                found_at=result.found_at,
            )
            session.add(record)
            await session.commit()
    except Exception as e:
        logger.warning(f"Erreur sauvegarde résultat en DB : {e}")


async def _create_search_record(search_id: str, name_query: str):
    """Crée l'enregistrement de recherche (session courte, échec non bloquant)."""
    try:
        async with AsyncSessionLocal() as session:
            session.add(SearchRecord(
                id=search_id,
                name_query=name_query,
                created_at=datetime.utcnow(),
                status="running",
            ))
            await session.commit()
    except Exception as e:
        logger.warning(f"Erreur création SearchRecord en DB : {e}")


async def _mark_search_completed(search_id: str, total_results: int, risk_score: Optional[float]):
    """Marque la recherche comme terminée (session courte, échec non bloquant)."""
    try:
        async with AsyncSessionLocal() as session:
            record = await session.get(SearchRecord, search_id)
            if record:
                record.status = "completed"
                record.completed_at = datetime.utcnow()
                record.total_results = total_results
                record.risk_score = risk_score
                await session.commit()
    except Exception as e:
        logger.warning(f"Erreur mise à jour SearchRecord (completed) en DB : {e}")


async def _handle_result(websocket: WebSocket, search_id: str, module_name: str, result: OsintResult):
    """Envoie le résultat au frontend puis le persiste en base."""
    await send_result(websocket, search_id, module_name, result.model_dump(mode="json"))
    await _save_result_to_db(result)


async def _safe_run_module(coro, module_name: str):
    """Exécute un module en isolant ses erreurs des autres modules."""
    try:
        return await coro
    except Exception as e:
        logger.error(f"Erreur module {module_name} : {e}")
        return []


def _collect_emails(results: list[OsintResult]) -> set[str]:
    """Extrait les emails trouvés dans les résultats d'un module."""
    emails = set()
    for result in results:
        if result.raw_data and result.raw_data.get("email"):
            emails.add(result.raw_data["email"])
    return emails


async def run_search(websocket: WebSocket, request: SearchRequest, search_id: str) -> tuple[int, Optional[float]]:
    """
    Orchestre tous les modules OSINT et streame les résultats en temps réel.
    Retourne (nombre total de résultats trouvés, risk_score IA ou None).
    """
    total_results = 0
    pending_tasks: list[asyncio.Task] = []
    emails_collected: set[str] = set()
    all_results: list[OsintResult] = []

    def make_callback(module_name: str) -> Callable:
        def callback(result: OsintResult):
            nonlocal total_results
            total_results += 1
            all_results.append(result)
            if result.category == ResultCategory.CONTACT and result.raw_data:
                email = result.raw_data.get("email")
                if email:
                    emails_collected.add(email)
            task = asyncio.create_task(_handle_result(websocket, search_id, module_name, result))
            pending_tasks.append(task)
        return callback

    # === Module 1 : name_engine (synchrone, pas de callback) ===
    await send_progress(websocket, search_id, "name_engine", "running", "Génération du profil de recherche...", 0)
    try:
        profile = generate_search_profile(request.name)
        await send_progress(websocket, search_id, "name_engine", "completed", "Profil généré", 100)
    except Exception as e:
        logger.error(f"Erreur name_engine : {e}")
        await send_error(websocket, search_id, "name_engine", str(e))
        await send_message(websocket, WebSocketMessage(
            type="complete", search_id=search_id, message="Recherche terminée",
            data={"total_results": 0, "risk_score": None}
        ))
        return 0, None

    # === Modules 2 : web_search, github_search, social_checker en parallèle ===
    for module_name in ("web_search", "github", "social"):
        await send_progress(websocket, search_id, module_name, "running", f"Module {module_name} en cours...", 10)

    web_results, github_results, social_results = await asyncio.gather(
        _safe_run_module(run_all_dorks(profile, search_id, make_callback("web_search")), "web_search"),
        _safe_run_module(search_github(profile, search_id, make_callback("github")), "github"),
        _safe_run_module(check_all_platforms(profile, search_id, make_callback("social")), "social"),
    )

    for module_name in ("web_search", "github", "social"):
        await send_progress(websocket, search_id, module_name, "completed", f"Module {module_name} terminé", 100)

    emails_collected |= _collect_emails(web_results) | _collect_emails(github_results)

    # === Module 5+6 : breach_checker (a besoin des emails) et paste_search en parallèle ===
    for module_name in ("breach", "paste"):
        await send_progress(websocket, search_id, module_name, "running", f"Module {module_name} en cours...", 10)

    breach_results, paste_results = await asyncio.gather(
        _safe_run_module(
            check_breaches(
                list(emails_collected), profile.username_variants, search_id, make_callback("breach")
            ),
            "breach",
        ),
        _safe_run_module(search_pastes(profile, search_id, make_callback("paste")), "paste"),
    )

    for module_name in ("breach", "paste"):
        await send_progress(websocket, search_id, module_name, "completed", f"Module {module_name} terminé", 100)

    # Attendre l'envoi et la sauvegarde de tous les résultats en attente
    if pending_tasks:
        await asyncio.gather(*pending_tasks)

    # === Module 7 : analyse IA (filtrage + profil + rapport) ===
    ai_risk_score = await _run_ai_pipeline(websocket, search_id, profile, request, all_results)

    # Annonce la fin
    await send_message(websocket, WebSocketMessage(
        type="complete",
        search_id=search_id,
        message="Recherche terminée",
        data={
            "total_results": total_results,
            "risk_score": ai_risk_score
        }
    ))

    return total_results, ai_risk_score


async def _run_ai_pipeline(
    websocket: WebSocket,
    search_id: str,
    profile,
    request: SearchRequest,
    all_results: list[OsintResult],
) -> Optional[float]:
    """Filtre les résultats, construit le profil IA et génère le rapport HTML."""
    if not request.enable_ai:
        await send_progress(websocket, search_id, "ai_analysis", "completed", "Analyse IA désactivée", 100)
        return None

    if not settings.anthropic_api_key:
        logger.warning("[AI] ANTHROPIC_API_KEY absente, analyse IA ignorée")
        await send_progress(
            websocket, search_id, "ai_analysis", "failed",
            "Configurez ANTHROPIC_API_KEY pour l'analyse IA", 100
        )
        return None

    await send_progress(
        websocket, search_id, "ai_analysis", "running",
        "Filtrage des résultats par intelligence artificielle...", 10
    )

    try:
        async def ai_progress_callback(message: str):
            await send_progress(websocket, search_id, "ai_analysis", "running", message, 50)

        anchors = getattr(request, "anchors", None)
        filtered = await filter_results(all_results, profile, search_id, ai_progress_callback, anchors=anchors)

        await send_progress(websocket, search_id, "ai_analysis", "running", "Construction du profil de renseignement...", 70)
        ai_profile_data = await build_profile(filtered, profile, search_id)

        await send_progress(websocket, search_id, "ai_analysis", "running", "Génération du rapport final...", 90)
        ai_html = await generate_report_html(ai_profile_data, profile)

        ai_risk_score = None
        privacy = ai_profile_data.get("privacy_score") if isinstance(ai_profile_data, dict) else None
        if privacy and isinstance(privacy.get("score"), (int, float)):
            ai_risk_score = float(privacy["score"])

        total_count = len(all_results)
        filtered_count = len(filtered)
        filter_rate = f"{round((1 - filtered_count / total_count) * 100)}%" if total_count else "0%"

        await send_message(websocket, WebSocketMessage(
            type="ai_profile",
            search_id=search_id,
            data={
                "html": ai_html,
                "profile": ai_profile_data,
                "risk_score": ai_risk_score,
                "filtered_count": filtered_count,
                "total_count": total_count,
                "filter_rate": filter_rate,
            }
        ))

        await send_progress(websocket, search_id, "ai_analysis", "completed", "Analyse IA terminée", 100)
        return ai_risk_score
    except Exception as e:
        logger.error(f"Erreur pipeline IA : {e}")
        await send_progress(websocket, search_id, "ai_analysis", "failed", "Erreur lors de l'analyse IA", 100)
        return None


async def handle_search_websocket(websocket: WebSocket):
    """
    Point d'entrée WebSocket.
    Reçoit la requête de recherche et lance l'orchestration.
    """
    await websocket.accept()
    websocket.state.is_connected = True
    logger.info("WebSocket connecté")

    try:
        # Attendre la requête initiale
        raw = await websocket.receive_text()
        data = json.loads(raw)

        # Robustesse : un champ "anchors" mal formé (type inattendu) ne doit jamais
        # faire planter la recherche. On l'ignore et on repart sur des ancres vides.
        if "anchors" in data and not isinstance(data["anchors"], dict):
            logger.warning("Champ 'anchors' mal formé, ignoré (ancres vides par défaut)")
            data.pop("anchors", None)

        request = SearchRequest(**data)

        search_id = str(uuid.uuid4())
        active = request.anchors.active_labels()
        anchors_log = f" | ancres : {', '.join(active)}" if active else ""
        logger.info(f"Recherche démarrée : {request.name} [{search_id}]{anchors_log}")

        # Initialiser DB et sauvegarder la recherche
        await init_db()
        await _create_search_record(search_id, request.name)

        # Confirmer le démarrage au frontend
        await send_message(websocket, WebSocketMessage(
            type="started",
            search_id=search_id,
            message=f"Recherche lancée pour : {request.name}",
            data={"name": request.name}
        ))

        # Lancer la recherche (orchestrateur 3 couches)
        from app.modules.intelligence_engine import run_intelligence_engine
        total_results, risk_score = await run_intelligence_engine(websocket, request, search_id)

        # Marquer comme terminé en DB
        await _mark_search_completed(search_id, total_results, risk_score)

    except WebSocketDisconnect:
        websocket.state.is_connected = False
        logger.info("WebSocket déconnecté par le client")
    except json.JSONDecodeError:
        await send_message(websocket, WebSocketMessage(
            type="error",
            message="Format JSON invalide"
        ))
    except Exception as e:
        logger.error(f"Erreur WebSocket : {e}")
        try:
            await send_message(websocket, WebSocketMessage(
                type="error",
                message=f"Erreur serveur : {str(e)}"
            ))
        except:
            pass
