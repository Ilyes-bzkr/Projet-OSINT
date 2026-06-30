"""Tests Phase E — l'image au service de la validation (P6).

Vérifie : extraction d'avatar tous types de comptes (social photo_url / GitHub
avatar_url) dans les candidats ; les avatars des comptes validés alimentent la
recherche d'image inversée de couche 2 (identifiers["photo_urls"]).
"""

from types import SimpleNamespace

from app.models.result import ModuleType, OsintResult, ResultCategory
from app.modules.intelligence_engine import (
    _account_photo,
    _apply_validation,
    _build_validation_candidates,
)

_PROFILE = SimpleNamespace(first_name="Ilyes", last_name="Bouzekri", full_name="Ilyes Bouzekri")


def _social(rid, username, photo=None, content=None, confidence="guessed"):
    raw = {"username": username, "platform": "X", "confidence": confidence}
    if photo:
        raw["photo_url"] = photo
    if content:
        raw["content"] = content
    return OsintResult(id=rid, search_id="t", module=ModuleType.SOCIAL,
                       category=ResultCategory.SOCIAL, title="t",
                       url=f"http://x/{username}", raw_data=raw)


def _github(rid, login, avatar=None):
    raw = {"login": login}
    if avatar:
        raw["avatar_url"] = avatar
    return OsintResult(id=rid, search_id="t", module=ModuleType.GITHUB,
                       category=ResultCategory.SOCIAL, title="gh",
                       url=f"http://gh/{login}", raw_data=raw)


# --- extraction d'avatar ----------------------------------------------------

def test_account_photo_prefers_photo_url_then_avatar_url():
    assert _account_photo({"photo_url": "http://p"}) == "http://p"
    assert _account_photo({"avatar_url": "http://a"}) == "http://a"
    assert _account_photo({"photo_url": "http://p", "avatar_url": "http://a"}) == "http://p"
    assert _account_photo({}) is None


def test_candidates_carry_avatars_all_account_types():
    social = _social("s1", "ilyes", photo="http://soc/avatar.png")
    github = _github("g1", "octocat", avatar="http://gh/octocat.png")
    payload = _build_validation_candidates([social, github])
    by_user = {c["username"]: c for c in payload["candidates"]}
    assert by_user["ilyes"]["photo_url"] == "http://soc/avatar.png"
    assert by_user["octocat"]["photo_url"] == "http://gh/octocat.png"  # avatar_url fallback


# --- avatars validés → corroboration image (couche 2) -----------------------

def test_validated_avatar_feeds_photo_urls():
    a = _social("id_a", "ilyesbouzekri", photo="http://soc/me.png",
                content={"email": "ilyes@mail.com"})
    b = _social("id_b", "ilyes-bouzekri", content={"email": "ilyes@mail.com"})
    out = _apply_validation({"selected": ["id_a"]}, [a, b],
                            {"photo_urls": []}, _PROFILE)
    assert "http://soc/me.png" in out["photo_urls"]


def test_validation_preserves_existing_photo_urls():
    a = _social("id_a", "ilyesbouzekri", photo="http://soc/me.png")
    out = _apply_validation({"selected": ["id_a"]}, [a],
                            {"photo_urls": ["http://ai/extracted.jpg"]}, _PROFILE)
    assert "http://ai/extracted.jpg" in out["photo_urls"]   # non retirée
    assert "http://soc/me.png" in out["photo_urls"]         # ajoutée


def test_non_validated_avatar_not_corroborated():
    # Homonyme divergent : son avatar ne doit PAS alimenter la corroboration.
    a = _social("id_a", "ilyesbouzekri", photo="http://soc/me.png",
                content={"fullname": "Ilyes Bouzekri", "location": "Paris"})
    b = _social("id_b", "ilyes-bouzekri", photo="http://soc/homonym.png",
                content={"fullname": "Ilyes Bouzekri", "location": "Tokyo"})
    out = _apply_validation({"selected": ["id_a"]}, [a, b],
                            {"photo_urls": []}, _PROFILE)
    assert "http://soc/me.png" in out["photo_urls"]
    assert "http://soc/homonym.png" not in out["photo_urls"]
