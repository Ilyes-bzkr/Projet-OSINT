"""Tests Phase B — routage par grappe (profiler) + gating documents (P5)."""

from types import SimpleNamespace

from app.ai import profiler
from app.models.result import ModuleType, OsintResult, ResultCategory
from app.modules import intelligence_engine as ie
from app.modules.evidence_engine import ConfirmedReference


def _acc(confidence=None, in_target=None, username="u", platform="X"):
    raw = {"username": username, "platform": platform}
    if confidence is not None:
        raw["confidence"] = confidence
    if in_target is not None:
        raw["in_target_cluster"] = in_target
    return OsintResult(search_id="t", module=ModuleType.SOCIAL, category=ResultCategory.SOCIAL,
                       title="t", url="http://x/u", raw_data=raw)


def _doc(title="", snippet="", url=""):
    return OsintResult(search_id="t", module=ModuleType.WEB_SEARCH, category=ResultCategory.DOCUMENT,
                       title=title, url=url, snippet=snippet, raw_data={})


# --- routage profiler -------------------------------------------------------

def test_other_cluster_is_offtarget():
    assert profiler._is_offtarget(_acc(confidence="guessed", in_target=False)) is True


def test_target_cluster_is_main_even_if_guessed():
    assert profiler._is_offtarget(_acc(confidence="guessed", in_target=True)) is False


def test_confirmed_always_main_even_outside_target():
    assert profiler._is_offtarget(_acc(confidence="confirmed", in_target=False)) is False


def test_corroborated_always_main_even_outside_target():
    assert profiler._is_offtarget(_acc(confidence="corroborated", in_target=False)) is False


def test_untagged_guessed_stays_offtarget():
    assert profiler._is_offtarget(_acc(confidence="guessed")) is True


def test_untagged_nonguessed_stays_main():
    assert profiler._is_offtarget(_acc()) is False


def test_name_only_document_is_offtarget():
    # Document tagué non rattaché (P5) → hors profil principal, et n'est pas un compte.
    doc = _doc(title="Ilyes Bouzekri (film)")
    doc.raw_data["in_target_cluster"] = False
    assert profiler._is_offtarget(doc) is True
    assert profiler._is_account(doc) is False


# --- aperçu des grappes -----------------------------------------------------

def test_clusters_overview_groups_and_marks_target():
    a = _acc(in_target=True, username="a"); a.raw_data["cluster_id"] = "c0"
    b = _acc(in_target=False, username="b"); b.raw_data["cluster_id"] = "c1"
    overview = profiler._clusters_overview([a, b])
    assert len(overview) == 2
    assert sum(1 for c in overview if c["is_target"]) == 1


def test_finalize_injects_namesakes_deterministically():
    target = _acc(confidence="guessed", in_target=True, username="me")
    homonym = _acc(confidence="guessed", in_target=False, username="other")
    parsed = profiler._finalize_profile({}, [target, homonym])
    users = [n["username"] for n in parsed["unverified_namesakes"]]
    assert users == ["other"]  # seul l'homonyme hors-cible


# --- gating documents (P5) --------------------------------------------------

_ANCHORS = SimpleNamespace(username="ily_bzk_dev", employer="EPITA", city="Paris")
_PROFILE = SimpleNamespace(first_name="Ilyes", last_name="Bouzekri", full_name="Ilyes Bouzekri")
_REF = ConfirmedReference(emails={"ilyes@mail.com"}, links={"https://github.com/ilybzk2"})


def test_doc_name_only_not_linked():
    assert ie._doc_anchor_linked(_doc(title="Ilyes Bouzekri", snippet="acteur"), _ANCHORS, _REF, _PROFILE) is False


def test_doc_distinctive_pseudo_linked():
    assert ie._doc_anchor_linked(_doc(snippet="profil ily_bzk_dev actif"), _ANCHORS, _REF, _PROFILE) is True


def test_doc_email_linked():
    assert ie._doc_anchor_linked(_doc(snippet="contact ilyes@mail.com"), _ANCHORS, _REF, _PROFILE) is True


def test_doc_name_plus_employer_linked():
    assert ie._doc_anchor_linked(_doc(title="Ilyes Bouzekri", snippet="étudiant à EPITA"), _ANCHORS, _REF, _PROFILE) is True


def test_doc_anchor_url_linked():
    assert ie._doc_anchor_linked(_doc(url="https://github.com/ilybzk2"), _ANCHORS, _REF, _PROFILE) is True
