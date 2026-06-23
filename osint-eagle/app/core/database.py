"""
Setup SQLite async avec aiosqlite + SQLAlchemy.
Crée les tables au démarrage si elles n'existent pas.
"""

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.ext.asyncio import async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import Column, String, Integer, Float, DateTime, Text, Boolean
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


async def init_db():
    """Crée les tables si elles n'existent pas."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_session() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        yield session
