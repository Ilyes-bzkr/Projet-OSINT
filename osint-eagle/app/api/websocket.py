"""
Handler WebSocket — OSINT Eagle.
Orchestre tous les modules OSINT et streame les résultats en temps réel.
"""

import asyncio
import json
import uuid
from datetime import datetime
from typing import Callable

from fastapi import WebSocket, WebSocketDisconnect

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
    """Envoie un message JSON via WebSocket."""
    try:
        await websocket.send_text(msg.model_dump_json())
    except Exception as e:
        logger.warning(f"Erreur envoi WebSocket : {e}")


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


async def run_search(websocket: WebSocket, request: SearchRequest, search_id: str) -> int:
    """
    Orchestre tous les modules OSINT et streame les résultats en temps réel.
    Retourne le nombre total de résultats trouvés.
    """
    total_results = 0
    pending_tasks: list[asyncio.Task] = []
    emails_collected: set[str] = set()

    def make_callback(module_name: str) -> Callable:
        def callback(result: OsintResult):
            nonlocal total_results
            total_results += 1
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
        return 0

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

    # Annonce la fin
    await send_message(websocket, WebSocketMessage(
        type="complete",
        search_id=search_id,
        message="Recherche terminée",
        data={
            "total_results": total_results,
            "risk_score": None
        }
    ))

    return total_results


async def handle_search_websocket(websocket: WebSocket):
    """
    Point d'entrée WebSocket.
    Reçoit la requête de recherche et lance l'orchestration.
    """
    await websocket.accept()
    logger.info("WebSocket connecté")

    try:
        # Attendre la requête initiale
        raw = await websocket.receive_text()
        data = json.loads(raw)
        request = SearchRequest(**data)

        search_id = str(uuid.uuid4())
        logger.info(f"Recherche démarrée : {request.name} [{search_id}]")

        # Initialiser DB et sauvegarder la recherche
        await init_db()
        async with AsyncSessionLocal() as session:
            record = SearchRecord(
                id=search_id,
                name_query=request.name,
                created_at=datetime.utcnow(),
                status="running"
            )
            session.add(record)
            await session.commit()

        # Confirmer le démarrage au frontend
        await send_message(websocket, WebSocketMessage(
            type="started",
            search_id=search_id,
            message=f"Recherche lancée pour : {request.name}",
            data={"name": request.name}
        ))

        # Lancer la recherche
        total_results = await run_search(websocket, request, search_id)

        # Marquer comme terminé en DB
        async with AsyncSessionLocal() as session:
            result = await session.get(SearchRecord, search_id)
            if result:
                result.status = "completed"
                result.completed_at = datetime.utcnow()
                result.total_results = total_results
                await session.commit()

    except WebSocketDisconnect:
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
