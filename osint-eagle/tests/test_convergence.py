"""Tests convergence inter-comptes (Piste A) — evidence_engine.converge_accounts."""

from app.modules.evidence_engine import converge_accounts


def _acc(key, username, **content):
    return {"key": key, "username": username, "content": content,
            "first_name": "Ilyes", "last_name": "Bouzekri"}


def _cluster_of(clusters, key):
    return next(c for c in clusters if key in c["members"])


# --- PALIER FORT ------------------------------------------------------------

def test_strong_cross_link_promotes():
    clusters = converge_accounts([
        _acc("a", "ilyesbouzekri", links=["https://soundcloud.com/ilyes-bouzekri"]),
        _acc("b", "ilyes-bouzekri"),
    ])
    c = _cluster_of(clusters, "a")
    assert c["promoted"] is True
    assert {"a", "b"} == set(c["members"])
    assert any("FORT: lien croisé" in s for s in c["signals"])


def test_strong_shared_email_promotes():
    clusters = converge_accounts([
        _acc("a", "ilyesbouzekri", email="ilyes@mail.com"),
        _acc("b", "ilyes-bouzekri", email="ilyes@mail.com"),
    ])
    assert _cluster_of(clusters, "a")["promoted"] is True


# --- DEUX PALIERS MOYENS ----------------------------------------------------

def test_two_mediums_name_and_city_promote():
    clusters = converge_accounts([
        _acc("a", "ilyesbouzekri", fullname="Ilyes Bouzekri", location="Paris"),
        _acc("b", "ilyes-bouzekri", fullname="Ilyes Bouzekri", location="Paris"),
    ])
    c = _cluster_of(clusters, "a")
    assert c["promoted"] is True
    assert any("MOYEN: fullname" in s for s in c["signals"])
    assert any("MOYEN: location" in s for s in c["signals"])


def test_single_medium_name_only_stays_guessed():
    # Même nom non-trivial mais AUCUN autre attribut → 1 seul moyen → non promu.
    clusters = converge_accounts([
        _acc("a", "ilyesbouzekri", fullname="Ilyes Bouzekri"),
        _acc("b", "ilyes-bouzekri", fullname="Ilyes Bouzekri"),
    ])
    assert _cluster_of(clusters, "a")["promoted"] is False


# --- PALIER FAIBLE SEUL -----------------------------------------------------

def test_weak_only_pseudo_variants_stay_guessed():
    # Comptes à content vide : seulement des variantes de pseudo → jamais promu.
    clusters = converge_accounts([
        _acc("a", "ilyesbouzekri"),
        _acc("b", "ilyes-bouzekri"),
        _acc("c", "ilyes.bouzekri"),
    ])
    assert all(c["promoted"] is False for c in clusters)


# --- GARDE-FOU ANTI-HOMONYME ------------------------------------------------

def test_homonym_divergent_cities_not_promoted():
    # Même nom mais villes divergentes → clusters séparés, non promus.
    clusters = converge_accounts([
        _acc("a", "ilyesbouzekri", fullname="Ilyes Bouzekri", location="Paris"),
        _acc("b", "ilyes-bouzekri", fullname="Ilyes Bouzekri", location="Tokyo"),
    ])
    assert _cluster_of(clusters, "a")["promoted"] is False
    assert _cluster_of(clusters, "b")["promoted"] is False
    # Pas fusionnés (incompatibles) : clusters distincts.
    assert _cluster_of(clusters, "a") is not _cluster_of(clusters, "b")


def test_homonym_divergence_blocks_even_with_other_signals():
    # Même nom + email partagé MAIS villes divergentes : la divergence l'emporte.
    clusters = converge_accounts([
        _acc("a", "ilyesbouzekri", fullname="Ilyes Bouzekri", location="Paris", email="x@y.z"),
        _acc("b", "ilyes-bouzekri", fullname="Ilyes Bouzekri", location="Lyon", email="x@y.z"),
    ])
    assert _cluster_of(clusters, "a")["promoted"] is False


# --- PLAFOND : jamais confirmed --------------------------------------------

def test_convergence_never_returns_confirmed():
    # La fonction ne renvoie qu'un booléen promoted ; aucune notion de confirmed.
    clusters = converge_accounts([
        _acc("a", "ilyesbouzekri", email="ilyes@mail.com"),
        _acc("b", "ilyes-bouzekri", email="ilyes@mail.com"),
    ])
    for c in clusters:
        assert set(c.keys()) == {"members", "promoted", "signals"}
        assert isinstance(c["promoted"], bool)


def test_compatible_city_substring_is_a_match_not_divergence():
    # "Paris" vs "Paris, France" → concordance (pas divergence) → 2 moyens → promu.
    clusters = converge_accounts([
        _acc("a", "ilyesbouzekri", fullname="Ilyes Bouzekri", location="Paris"),
        _acc("b", "ilyes-bouzekri", fullname="Ilyes Bouzekri", location="Paris, France"),
    ])
    assert _cluster_of(clusters, "a")["promoted"] is True


# ─── Phase A : grappes d'identité (strict_edges) + pseudo distinctif ─────────

def _node(key, username, first="Foo", last="Bar", **content):
    return {"key": key, "username": username, "content": content,
            "first_name": first, "last_name": last}


def test_strict_edges_name_only_does_not_merge():
    # Même nom complet SEUL (1 moyen) → en mode strict, AUCUNE arête → grappes
    # séparées (correction du faux positif homonyme).
    clusters = converge_accounts([
        _acc("a", "ilyesbouzekri", fullname="Ilyes Bouzekri"),
        _acc("b", "ilyes-bouzekri", fullname="Ilyes Bouzekri"),
    ], strict_edges=True)
    assert _cluster_of(clusters, "a") is not _cluster_of(clusters, "b")


def test_strict_edges_two_mediums_still_merge():
    clusters = converge_accounts([
        _acc("a", "ilyesbouzekri", fullname="Ilyes Bouzekri", location="Paris"),
        _acc("b", "ilyes-bouzekri", fullname="Ilyes Bouzekri", location="Paris"),
    ], strict_edges=True)
    assert _cluster_of(clusters, "a") is _cluster_of(clusters, "b")


def test_same_distinctive_username_is_strong():
    # Pseudo distinctif identique (résidu "uniquehandle" hors prénom/nom) → FORT.
    clusters = converge_accounts([
        _node("a", "uniquehandle"),
        _node("b", "uniquehandle"),
    ], strict_edges=True)
    c = _cluster_of(clusters, "a")
    assert {"a", "b"} == set(c["members"])
    assert any("pseudo distinctif identique" in s for s in c["signals"])


def test_simple_pseudo_variants_not_strong():
    # Variantes du nom (pseudo SIMPLE) → pas de signal fort → non fusionnées en strict.
    clusters = converge_accounts([
        _acc("a", "ilyesbouzekri"),
        _acc("b", "ilyes.bouzekri"),
    ], strict_edges=True)
    assert _cluster_of(clusters, "a") is not _cluster_of(clusters, "b")


def test_anchor_node_pulls_linked_account_not_homonym():
    # Nœud-ancre (email X + nom + Paris). A partage l'email → rejoint l'ancre (FORT).
    # B n'a que le même nom mais ville divergente (Tokyo) → écarté de la grappe-cible.
    clusters = converge_accounts([
        _node("anchor", "", first="Ilyes", last="Bouzekri",
              email="ilyes@mail.com", fullname="Ilyes Bouzekri", location="Paris"),
        _node("a", "ilyesbouzekri", first="Ilyes", last="Bouzekri", email="ilyes@mail.com"),
        _node("b", "ilyes-bouzekri", first="Ilyes", last="Bouzekri",
              fullname="Ilyes Bouzekri", location="Tokyo"),
    ], strict_edges=True)
    target = _cluster_of(clusters, "anchor")
    assert "a" in target["members"]
    assert "b" not in target["members"]
