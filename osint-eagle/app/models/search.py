"""
Modèles Pydantic pour les recherches OSINT Eagle.
"""

from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime
import uuid


class SearchRequest(BaseModel):
    """Requête de recherche envoyée par le frontend."""
    name: str = Field(..., min_length=2, max_length=100, description="Nom complet à rechercher")
    enable_ai: bool = Field(default=True, description="Activer l'analyse IA")
    enable_data_brokers: bool = Field(default=True, description="Activer le scraping data brokers")
    enable_dark_web: bool = Field(default=False, description="Activer la recherche dark web")


class SearchStatus(BaseModel):
    """Statut d'une recherche en cours."""
    search_id: str
    name_query: str
    status: str  # running | completed | failed
    created_at: datetime
    completed_at: Optional[datetime] = None
    total_results: int = 0
    risk_score: Optional[float] = None


class SearchSummary(BaseModel):
    """Résumé d'une recherche terminée."""
    search_id: str
    name_query: str
    created_at: datetime
    total_results: int
    risk_score: Optional[float] = None
    status: str


class NameProfile(BaseModel):
    """Profil de nom généré par name_engine."""
    first_name: str
    last_name: str
    full_name: str
    full_variants: list[str]
    username_variants: list[str]
    search_queries: dict[str, list[str]]
