"""
Modèles Pydantic pour les résultats OSINT Eagle.
"""

from pydantic import BaseModel, Field
from typing import Optional, Any
from datetime import datetime
from enum import Enum


class ModuleType(str, Enum):
    NAME_ENGINE = "name_engine"
    WEB_SEARCH = "web_search"
    GITHUB = "github"
    SOCIAL = "social"
    BREACH = "breach"
    PASTE = "paste"
    DATA_BROKERS = "data_brokers"
    AI_ANALYSIS = "ai_analysis"


class ResultCategory(str, Enum):
    IDENTITY = "identity"
    CONTACT = "contact"
    PROFESSIONAL = "professional"
    SOCIAL = "social"
    TECHNICAL = "technical"
    BREACH = "breach"
    DOCUMENT = "document"
    AI_REPORT = "ai_report"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class OsintResult(BaseModel):
    """Un résultat OSINT unique."""
    id: str = Field(default_factory=lambda: str(__import__('uuid').uuid4()))
    search_id: str
    module: ModuleType
    category: ResultCategory
    title: str
    url: Optional[str] = None
    snippet: Optional[str] = None
    raw_data: Optional[dict[str, Any]] = None
    relevance_score: float = Field(default=0.0, ge=0.0, le=1.0)
    risk_level: RiskLevel = RiskLevel.LOW
    is_sensitive: bool = False
    found_at: datetime = Field(default_factory=datetime.utcnow)


class WebSocketMessage(BaseModel):
    """Message envoyé via WebSocket au frontend."""
    type: str  # result | progress | error | complete | ai_report
    module: Optional[str] = None
    data: Optional[Any] = None
    message: Optional[str] = None
    progress: Optional[int] = None  # 0-100
    search_id: Optional[str] = None


class ModuleProgress(BaseModel):
    """Progression d'un module."""
    module: ModuleType
    status: str  # pending | running | completed | failed
    results_count: int = 0
    message: Optional[str] = None


class SearchProgress(BaseModel):
    """Progression globale d'une recherche."""
    search_id: str
    overall_progress: int = 0
    modules: dict[str, ModuleProgress] = {}
    total_results: int = 0
