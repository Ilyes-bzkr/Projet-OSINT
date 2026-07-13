"""
Modèles Pydantic pour les recherches OSINT Eagle.
"""

from pydantic import BaseModel, Field, field_validator
from typing import Optional
from datetime import datetime
import uuid

# Longueur maximale tolérée pour une ancre texte. Au-delà, on tronque
# silencieusement plutôt que de faire échouer la validation : une ancre
# inattendue ne doit jamais faire planter la recherche.
_MAX_ANCHOR_LEN = 150

# Valeurs de la tranche d'âge considérées comme « non renseignée ».
_AGE_NONE_VALUES = {"", "non précisé", "non precise"}


class SearchAnchors(BaseModel):
    """Ancres de vérité optionnelles fournies avant la recherche.

    Toutes les ancres sont facultatives : une recherche sans aucune ancre
    se comporte exactement comme avant. Plus l'utilisateur en renseigne,
    plus la recherche est précise (filtrage IA, dorks ciblés, couche 2).
    """
    city: Optional[str] = Field(default=None, description="Ville ou région connue")
    employer: Optional[str] = Field(default=None, description="Employeur ou école connus")
    username: Optional[str] = Field(default=None, description="Pseudo / identifiant connu")
    email: Optional[str] = Field(default=None, description="Email connu (vérifié en priorité)")
    age_range: Optional[str] = Field(default=None, description="Tranche d'âge approximative")

    @field_validator("city", "employer", "username", "email", "age_range", mode="before")
    @classmethod
    def _normalize(cls, value):
        """Normalise chaque ancre : coercition en texte, trim, vide -> None, troncature.

        Robuste aux types inattendus : on n'échoue jamais, au pire on ignore.
        """
        if value is None:
            return None
        if not isinstance(value, str):
            value = str(value)
        value = value.strip()
        if not value or value.lower() in _AGE_NONE_VALUES:
            return None
        return value[:_MAX_ANCHOR_LEN]

    def is_empty(self) -> bool:
        """True si aucune ancre n'est renseignée (comportement historique)."""
        return not any([self.city, self.employer, self.username, self.email, self.age_range])

    def active_labels(self) -> list[str]:
        """Libellés courts des ancres renseignées, pour le logging."""
        labels = []
        if self.city:
            labels.append("ville")
        if self.employer:
            labels.append("employeur/école")
        if self.username:
            labels.append("pseudo")
        if self.email:
            labels.append("email")
        if self.age_range:
            labels.append("tranche d'âge")
        return labels

    def to_prompt_summary(self) -> str:
        """Résumé lisible des ancres renseignées, injectable dans un prompt IA.

        Une ancre par segment, segments séparés par des barres verticales.
        Retourne une chaîne vide si rien n'est renseigné.
        """
        parts = []
        if self.city:
            parts.append(f"Ville/région : {self.city}")
        if self.employer:
            parts.append(f"Employeur/École : {self.employer}")
        if self.username:
            parts.append(f"Pseudo : {self.username}")
        if self.email:
            parts.append(f"Email : {self.email}")
        if self.age_range:
            parts.append(f"Tranche d'âge : {self.age_range}")
        return " | ".join(parts)


class SearchRequest(BaseModel):
    """Requête de recherche envoyée par le frontend."""
    name: str = Field(..., min_length=2, max_length=100, description="Nom complet à rechercher")
    enable_ai: bool = Field(default=True, description="Activer l'analyse IA")
    enable_data_brokers: bool = Field(default=True, description="Activer le scraping data brokers")
    enable_dark_web: bool = Field(default=False, description="Activer la recherche dark web")
    anchors: SearchAnchors = Field(default_factory=SearchAnchors, description="Ancres de vérité optionnelles")
    interactive: bool = Field(
        default=True,
        description=(
            "Active le checkpoint de validation interactif entre couche 1 et "
            "couche 2 (pause/reprise WebSocket). Défaut True (précision maximale) : "
            "l'humain confirme les comptes de la bonne personne avant "
            "l'approfondissement, ce qui élimine les homonymes en amont. Le "
            "frontend peut le désactiver explicitement (interactive=False)."
        ),
    )


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
