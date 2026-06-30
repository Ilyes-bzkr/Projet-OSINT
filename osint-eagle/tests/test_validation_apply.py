"""Tests Phase D — application d'une validation humaine (_apply_validation).

Vérifie : compte coché → ancre confirmée ; auto-rattachement P2 d'un compte
fortement lié ; non-fusion d'un homonyme divergent ; augmentation des
identifiants pour la couche 2 ; tolérance du parseur de sélection.
"""

from types import SimpleNamespace

from app.models.result import ModuleType, OsintResult, ResultCategory
from app.modules.intelligence_engine import (
    _apply_validation,
    _parse_validation_selection,
)

_PROFILE = SimpleNamespace(first_name="Ilyes", last_name="Bouzekri", full_name="Ilyes Bouzekri")


def _acc(rid, username, platform="X", confidence="guessed", content=None):
    raw = {"username": username, "platform": platform, "confidence": confidence}
    if content:
        raw["content"] = content
    return OsintResult(id=rid, search_id="t", module=ModuleType.SOCIAL,
                       category=ResultCategory.SOCIAL, title="t",
                       url=f"http://x/{username}", raw_data=raw)


def _empty_ids():
    return {"confirmed_social_usernames": [], "corroborated_social_usernames": []}


# --- parseur de sélection ---------------------------------------------------

def test_parse_selection_variants():
    assert _parse_validation_selection({"selected": ["a", "b"]}) == {"a", "b"}
    assert _parse_validation_selection({"ids": ["a"]}) == {"a"}
    assert _parse_validation_selection(["a", "b"]) == {"a", "b"}
    assert _parse_validation_selection(None) == set()
    assert _parse_validation_selection("garbage") == set()
    assert _parse_validation_selection({"selected": []}) == set()


# --- validation : confirmation + auto-rattachement (P2) ---------------------

def test_validated_account_confirmed_and_pulls_linked_account():
    # a et b partagent un email (signal FORT) → b est auto-rattaché quand a est validé.
    a = _acc("id_a", "ilyesbouzekri", content={"email": "ilyes@mail.com"})
    b = _acc("id_b", "ilyes-bouzekri", content={"email": "ilyes@mail.com"})
    out = _apply_validation({"selected": ["id_a"]}, [a, b], _empty_ids(), _PROFILE)

    assert a.raw_data["confidence"] == "confirmed"
    assert a.raw_data["in_target_cluster"] is True
    assert b.raw_data["in_target_cluster"] is True          # auto-rattaché
    assert b.raw_data["confidence"] == "corroborated"       # promu, pas confirmed
    assert "ilyesbouzekri" in out["confirmed_social_usernames"]
    assert "ilyes-bouzekri" in out["corroborated_social_usernames"]


def test_single_validated_account_is_confirmed():
    a = _acc("id_a", "uniquehandle")
    out = _apply_validation(["id_a"], [a], _empty_ids(), _PROFILE)
    assert a.raw_data["confidence"] == "confirmed"
    assert a.raw_data["in_target_cluster"] is True
    assert "uniquehandle" in out["confirmed_social_usernames"]


# --- validation : homonyme divergent NON rattaché ---------------------------

def test_divergent_homonym_not_attached():
    a = _acc("id_a", "ilyesbouzekri", content={"fullname": "Ilyes Bouzekri", "location": "Paris"})
    b = _acc("id_b", "ilyes-bouzekri", content={"fullname": "Ilyes Bouzekri", "location": "Tokyo"})
    out = _apply_validation({"selected": ["id_a"]}, [a, b], _empty_ids(), _PROFILE)

    assert a.raw_data["in_target_cluster"] is True
    assert a.raw_data["confidence"] == "confirmed"
    assert b.raw_data["in_target_cluster"] is False
    assert b.raw_data["confidence"] == "guessed"            # inchangé
    assert "ilyes-bouzekri" not in out["corroborated_social_usernames"]


# --- validation : repli / préservation --------------------------------------

def test_empty_selection_returns_identifiers_unchanged():
    a = _acc("id_a", "x")
    ids = _empty_ids()
    out = _apply_validation({"selected": []}, [a], ids, _PROFILE)
    assert out is ids                                        # même objet, aucun effet
    assert "confidence" in a.raw_data and a.raw_data["confidence"] == "guessed"


def test_augmentation_preserves_existing_identifiers():
    a = _acc("id_a", "ilyesbouzekri", content={"email": "ilyes@mail.com"})
    b = _acc("id_b", "ilyes-bouzekri", content={"email": "ilyes@mail.com"})
    ids = {"confirmed_social_usernames": ["deja_confirme"], "corroborated_social_usernames": ["deja_corr"]}
    out = _apply_validation({"selected": ["id_a"]}, [a, b], ids, _PROFILE)
    assert "deja_confirme" in out["confirmed_social_usernames"]
    assert "ilyesbouzekri" in out["confirmed_social_usernames"]
    assert "deja_corr" in out["corroborated_social_usernames"]
