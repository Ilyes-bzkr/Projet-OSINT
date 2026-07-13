"""Tests profiler — passe anti-invention (Phase 1, précision maximale).

Vérifie que _enforce_sourced_fields neutralise tout attribut d'identité
déductible non attesté littéralement par les sources fournies, et conserve ceux
qui le sont. Garantie indépendante du modèle.
"""

from app.ai.profiler import _build_sources_text, _enforce_sourced_fields
from app.models.result import ModuleType, OsintResult, ResultCategory


def _profile_with(**overrides) -> dict:
    base = {
        "identity": {"full_name": "Ilyes Bouzekri", "nationality": None,
                     "age_estimated": None, "languages": []},
        "location": {"current_city": None, "current_country": None,
                     "past_cities": [], "timezone_estimated": None},
        "professional": {"current_employer": None, "current_school": None,
                         "field": None, "job_title": None},
        "behavior": {"writing_style": None, "posting_hours_estimated": None},
        "contact": {"emails": [{"value": "a@b.com"}]},
    }
    for section, values in overrides.items():
        base.setdefault(section, {}).update(values)
    return base


def test_nulls_unsourced_nationality_and_city():
    # Aucune source ne contient "Tunisienne" ni "Tunis" → neutralisés.
    sources = "Compte Instagram actif. Social anxiety fears me."
    profile = _profile_with(
        identity={"nationality": "Tunisienne"},
        location={"current_city": "Tunis"},
    )
    out = _enforce_sourced_fields(profile, sources)
    assert out["identity"]["nationality"] is None
    assert out["location"]["current_city"] is None


def test_keeps_sourced_values():
    sources = "Profil basé à Paris, France. Développeur logiciel."
    profile = _profile_with(
        location={"current_city": "Paris", "current_country": "France"},
        professional={"job_title": "Développeur logiciel"},
    )
    out = _enforce_sourced_fields(profile, sources)
    assert out["location"]["current_city"] == "Paris"
    assert out["location"]["current_country"] == "France"
    assert out["professional"]["job_title"] == "Développeur logiciel"


def test_filters_lists_to_sourced_entries():
    sources = "Publie en français. A vécu à Paris."
    profile = _profile_with(
        identity={"languages": ["Français", "Arabe", "Anglais"]},
        location={"past_cities": ["Paris", "Tunis"]},
    )
    out = _enforce_sourced_fields(profile, sources)
    assert out["identity"]["languages"] == ["Français"]
    assert out["location"]["past_cities"] == ["Paris"]


def test_contact_untouched_by_provenance_pass():
    # Les champs déterministes (contact) ne sont jamais neutralisés.
    profile = _profile_with(identity={"nationality": "Martienne"})
    out = _enforce_sourced_fields(profile, "aucune source pertinente")
    assert out["contact"]["emails"] == [{"value": "a@b.com"}]
    assert out["identity"]["nationality"] is None


def test_sources_text_includes_structured_account_content():
    # Un attribut présent uniquement dans le content structuré d'un compte
    # confirmé (pas dans le snippet) doit être reconnu comme sourcé.
    result = OsintResult(
        search_id="t", module=ModuleType.SOCIAL, category=ResultCategory.SOCIAL,
        title="GitHub @ib", url="http://gh/ib", snippet=None,
        raw_data={"platform": "GitHub", "username": "ib",
                  "content": {"location": "Lyon", "occupation": "Data Scientist"}},
    )
    text = _build_sources_text([result])
    profile = _profile_with(
        location={"current_city": "Lyon"},
        professional={"job_title": "Data Scientist"},
    )
    out = _enforce_sourced_fields(profile, text)
    assert out["location"]["current_city"] == "Lyon"
    assert out["professional"]["job_title"] == "Data Scientist"
