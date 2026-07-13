"""Tests account_enricher — OSINT Eagle (garde-fous anti-invention)."""

from app.models.result import ModuleType, OsintResult, ResultCategory
from app.modules import account_enricher as ae
from app.modules.evidence_engine import account_content_view


def _social(username, platform="YouTube", content=None, confidence="guessed"):
    raw = {"platform": platform, "username": username, "confidence": confidence}
    if content:
        raw["content"] = content
    return OsintResult(
        search_id="t", module=ModuleType.SOCIAL, category=ResultCategory.SOCIAL,
        title=f"{platform} @{username}", url=f"http://{platform}/{username}", raw_data=raw,
    )


# --- account_content_view ---------------------------------------------------

def test_content_view_empty_social():
    assert account_content_view({"platform": "YouTube", "username": "ib"}) == {}


def test_content_view_github_toplevel():
    view = account_content_view({"login": "ib", "name": "Ilyes B", "company": "ACME", "blog": "http://b"})
    assert view["fullname"] == "Ilyes B"
    assert view["occupation"] == "ACME"
    assert view["links"] == ["http://b"]


# --- sélection des cibles ---------------------------------------------------

def test_select_skips_trusted_and_filled():
    targets = ae._select_targets([
        _social("a", confidence="guessed"),                       # à enrichir
        _social("b", confidence="confirmed"),                     # fiable → skip
        _social("c", content={"fullname": "X"}),                  # déjà rempli → skip
        OsintResult(search_id="t", module=ModuleType.SOCIAL,
                    category=ResultCategory.SOCIAL, title="x", url="u",
                    raw_data={"platform": "Y"}),                   # pas d'username → skip
    ])
    assert [t.raw_data["username"] for t in targets] == ["a"]


# --- validation par provenance (anti-invention) -----------------------------

def test_validate_keeps_attr_with_valid_provenance():
    snippets = [{"url": "http://s1", "text": "Ilyes Bouzekri habite à Paris, développeur."}]
    raw_attrs = {
        "fullname": {"value": "Ilyes Bouzekri", "source_url": "http://s1"},
        "location": {"value": "Paris", "source_url": "http://s1"},
    }
    content, prov = ae._validate_attrs(raw_attrs, snippets)
    assert content == {"fullname": "Ilyes Bouzekri", "location": "Paris"}
    assert prov["fullname"] == "http://s1"


def test_validate_rejects_value_absent_from_snippet():
    # "Lyon" n'apparaît pas dans le snippet → rejet (invention).
    snippets = [{"url": "http://s1", "text": "Ilyes Bouzekri, développeur."}]
    raw_attrs = {"location": {"value": "Lyon", "source_url": "http://s1"}}
    content, _ = ae._validate_attrs(raw_attrs, snippets)
    assert "location" not in content


def test_validate_rejects_unknown_source_url():
    # source_url non fournie → rejet (provenance inventée).
    snippets = [{"url": "http://s1", "text": "Ilyes Bouzekri à Paris."}]
    raw_attrs = {"location": {"value": "Paris", "source_url": "http://inventé"}}
    content, _ = ae._validate_attrs(raw_attrs, snippets)
    assert "location" not in content


def test_validate_links_must_appear_literally():
    snippets = [{"url": "http://s1", "text": "Profil: https://github.com/ilyes ici."}]
    raw_attrs = {"links": [
        {"value": "https://github.com/ilyes", "source_url": "http://s1"},  # présent → gardé
        {"value": "https://linkedin.com/in/ilyes", "source_url": "http://s1"},  # absent → rejeté
    ]}
    content, _ = ae._validate_attrs(raw_attrs, snippets)
    assert content["links"] == ["https://github.com/ilyes"]


def test_validate_empty_when_nothing_valid():
    content, prov = ae._validate_attrs({"fullname": {"value": None, "source_url": None}}, [])
    assert content == {} and prov == {}


# --- garde-fou anti-homonyme (Phase 4) --------------------------------------

from app.modules.name_engine import generate_search_profile

_PROFILE = generate_search_profile("Ilyes Bouzekri")


def test_name_gate_rejects_homonym_snippet_for_simple_username():
    # username SIMPLE (= nom) + snippet qui ne cite PAS le nom → homonyme probable, rejet.
    snippets = [{"url": "http://s1", "text": "Compte basé à Berlin, photographe."}]
    raw_attrs = {"location": {"value": "Berlin", "source_url": "http://s1"}}
    content, _ = ae._validate_attrs(raw_attrs, snippets, _PROFILE, "ilyesbouzekri")
    assert "location" not in content


def test_name_gate_allows_when_name_present_for_simple_username():
    snippets = [{"url": "http://s1", "text": "Ilyes Bouzekri, basé à Paris."}]
    raw_attrs = {"location": {"value": "Paris", "source_url": "http://s1"}}
    content, _ = ae._validate_attrs(raw_attrs, snippets, _PROFILE, "ilyesbouzekri")
    assert content["location"] == "Paris"


def test_distinctive_username_bypasses_name_gate():
    # username DISTINCTIF (identifiant fiable) : snippet sans le nom accepté quand même.
    snippets = [{"url": "http://s1", "text": "Profil @ily_bzk_dev, basé à Lyon."}]
    raw_attrs = {"location": {"value": "Lyon", "source_url": "http://s1"}}
    content, _ = ae._validate_attrs(raw_attrs, snippets, _PROFILE, "ily_bzk_dev")
    assert content["location"] == "Lyon"
