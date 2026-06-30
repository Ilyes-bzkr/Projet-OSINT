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


class ConfidenceLevel(str, Enum):
    """Niveau de confiance d'appartenance d'un compte à la cible.

    - CONFIRMED    : appartient certainement à la cible (ancre / profil GitHub trouvé).
    - CORROBORATED : compte deviné, mais prouvé par le moteur de preuves
                     (1 preuve forte ou 2 preuves moyennes le reliant à un
                     identifiant confirmé).
    - GUESSED      : existence confirmée par Maigret mais AUCUNE preuve
                     d'appartenance — c'est là que tombent les homonymes.
    """
    CONFIRMED = "confirmed"
    CORROBORATED = "corroborated"
    GUESSED = "guessed"


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
    """Message envoyé via WebSocket au frontend.

    `validation_request` (sortant) / `validation_response` (entrant) portent le
    flux interactif de pause/reprise : le serveur émet un `validation_request`
    au checkpoint et suspend l'orchestration jusqu'à recevoir un
    `validation_response` (ou un repli sur timeout/déconnexion).
    """
    type: str  # result | progress | error | complete | ai_report | validation_request | validation_response
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
