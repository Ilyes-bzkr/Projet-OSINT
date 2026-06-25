"""
Setup SQLite async avec aiosqlite + SQLAlchemy.
Crée les tables au démarrage si elles n'existent pas.
"""

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.ext.asyncio import async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import Column, String, Integer, Float, DateTime, Text, Boolean, event
from datetime import datetime
from app.core.config import settings


class Base(DeclarativeBase):
    pass


class SearchRecord(Base):
    __tablename__ = "searches"
    id = Column(String, primary_key=True)
    name_query = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    status = Column(String, default="running")  # running | completed | failed
    total_results = Column(Integer, default=0)
    risk_score = Column(Float, nullable=True)


class ResultRecord(Base):
    __tablename__ = "results"
    id = Column(String, primary_key=True)
    search_id = Column(String, nullable=False)
    module = Column(String, nullable=False)
    category = Column(String, nullable=False)
    title = Column(String, nullable=True)
    url = Column(String, nullable=True)
    snippet = Column(Text, nullable=True)
    raw_data = Column(Text, nullable=True)
    relevance_score = Column(Float, nullable=True)
    is_sensitive = Column(Boolean, default=False)
    found_at = Column(DateTime, default=datetime.utcnow)


engine = create_async_engine(settings.database_url, echo=settings.debug)
AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


@event.listens_for(engine.sync_engine, "connect")
def _set_sqlite_pragmas(dbapi_connection, connection_record):
    """Active WAL + busy_timeout sur CHAQUE connexion SQLite.

    - WAL (journal_mode) : plusieurs lecteurs concurrents + un écrivain sans
      verrou bloquant -> indispensable quand plusieurs modules OSINT écrivent
      leurs résultats en parallèle.
    - busy_timeout=5000 : si un verrou d'écriture est tenu, on patiente jusqu'à
      5 s qu'il se libère au lieu de lever immédiatement « database is locked ».
    - synchronous=NORMAL : compromis sûr/performant recommandé avec WAL.

    Le PRAGMA est posé par connexion (busy_timeout n'est pas persistant), via
    l'event 'connect' qui couvre toutes les connexions du pool.
    """
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA busy_timeout=5000;")
        cursor.execute("PRAGMA synchronous=NORMAL;")
    finally:
        cursor.close()


async def init_db():
    """Crée les tables si elles n'existent pas (PRAGMAs WAL/busy_timeout appliqués
    automatiquement à chaque connexion via l'event 'connect' ci-dessus)."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_session() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        yield session
