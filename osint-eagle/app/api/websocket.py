"""
Handler WebSocket — OSINT Eagle.
Orchestre tous les modules OSINT et streame les résultats en temps réel.
"""

import asyncio
import json
import uuid
from datetime import datetime
from fastapi import WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import AsyncSessionLocal, SearchRecord, ResultRecord, init_db
from app.core.logger import logger
from app.models.result import WebSocketMessage, ModuleProgress, ModuleType
from app.models.search import SearchRequest


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


async def run_search(websocket: WebSocket, request: SearchRequest, search_id: str):
    """
    Orchestre tous les modules OSINT en parallèle.
    Streame chaque résultat dès qu'il est trouvé.
    TODO Phase 2+ : brancher les vrais modules ici.
    """
    from app.core.config import settings

    # Modules à exécuter (sera enrichi Phase 2+)
    modules = [
        ModuleType.NAME_ENGINE,
        ModuleType.WEB_SEARCH,
        ModuleType.GITHUB,
        ModuleType.SOCIAL,
        ModuleType.BREACH,
        ModuleType.PASTE,
    ]

    if settings.enable_data_brokers:
        modules.append(ModuleType.DATA_BROKERS)

    total_results = 0

    # Annonce le démarrage de chaque module
    for module in modules:
        await send_progress(
            websocket, search_id, module.value,
            "pending", f"En attente...", 0
        )

    await asyncio.sleep(0.1)

    # === PHASE 2 : les modules seront branchés ici ===
    # Pour l'instant : simulation pour valider le pipeline WebSocket

    for i, module in enumerate(modules):
        await send_progress(
            websocket, search_id, module.value,
            "running", f"Module {module.value} en cours...",
            int((i / len(modules)) * 100)
        )
        await asyncio.sleep(0.2)  # Retiré en Phase 2

        await send_progress(
            websocket, search_id, module.value,
            "completed", f"Module {module.value} terminé",
            100
        )

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
        await run_search(websocket, request, search_id)

        # Marquer comme terminé en DB
        async with AsyncSessionLocal() as session:
            result = await session.get(SearchRecord, search_id)
            if result:
                result.status = "completed"
                result.completed_at = datetime.utcnow()
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
