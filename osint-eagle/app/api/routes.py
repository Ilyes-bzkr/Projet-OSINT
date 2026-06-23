"""
Endpoints HTTP FastAPI — OSINT Eagle.
"""

from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from app.core.database import get_session, SearchRecord, init_db
from app.core.logger import logger
from app.models.search import SearchRequest, SearchSummary, SearchStatus
import uuid
from datetime import datetime

router = APIRouter()


@router.on_event("startup")
async def startup():
    await init_db()
    logger.info("Base de données initialisée")


@router.get("/health")
async def health_check():
    """Vérifie que le serveur tourne."""
    return {
        "status": "ok",
        "app": "OSINT Eagle",
        "version": "0.1.0"
    }


@router.get("/api/history")
async def get_history(
    limit: int = 20,
    session: AsyncSession = Depends(get_session)
):
    """Retourne l'historique des recherches."""
    try:
        result = await session.execute(
            select(SearchRecord)
            .order_by(desc(SearchRecord.created_at))
            .limit(limit)
        )
        records = result.scalars().all()
        return {
            "searches": [
                SearchSummary(
                    search_id=r.id,
                    name_query=r.name_query,
                    created_at=r.created_at,
                    total_results=r.total_results,
                    risk_score=r.risk_score,
                    status=r.status
                ) for r in records
            ]
        }
    except Exception as e:
        logger.error(f"Erreur historique : {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/search/{search_id}")
async def get_search_status(
    search_id: str,
    session: AsyncSession = Depends(get_session)
):
    """Retourne le statut d'une recherche."""
    result = await session.execute(
        select(SearchRecord).where(SearchRecord.id == search_id)
    )
    record = result.scalar_one_or_none()
    if not record:
        raise HTTPException(status_code=404, detail="Recherche non trouvée")
    return SearchStatus(
        search_id=record.id,
        name_query=record.name_query,
        status=record.status,
        created_at=record.created_at,
        completed_at=record.completed_at,
        total_results=record.total_results,
        risk_score=record.risk_score
    )


@router.delete("/api/search/{search_id}")
async def delete_search(
    search_id: str,
    session: AsyncSession = Depends(get_session)
):
    """Supprime une recherche de l'historique."""
    result = await session.execute(
        select(SearchRecord).where(SearchRecord.id == search_id)
    )
    record = result.scalar_one_or_none()
    if not record:
        raise HTTPException(status_code=404, detail="Recherche non trouvée")
    await session.delete(record)
    await session.commit()
    return {"status": "deleted", "search_id": search_id}
