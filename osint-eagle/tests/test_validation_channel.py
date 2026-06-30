"""Tests Phase C — canal de validation interactif (pause/reprise WebSocket).

Plomberie pure : on vérifie la mécanique pause/reprise, le repli sur
timeout/déconnexion, le heartbeat, et le no-op hors mode interactif. Aucune
logique métier n'est testée (elle viendra en Phase D).

Les tests pilotent les coroutines via asyncio.run() — aucun marqueur asyncio
requis (le projet n'en configure pas).
"""

import asyncio
import types

from app.api.validation_channel import ValidationChannel
from app.models.result import ModuleType, OsintResult, ResultCategory
from app.modules.intelligence_engine import (
    _build_validation_candidates,
    _interactive_checkpoint,
)


def _sender(sink):
    """Faux émetteur : capture les WebSocketMessage au lieu de les envoyer."""
    async def send(msg):
        sink.append(msg)
    return send


def _acc(username="u", platform="X", **extra):
    raw = {"username": username, "platform": platform}
    raw.update(extra)
    return OsintResult(search_id="t", module=ModuleType.SOCIAL, category=ResultCategory.SOCIAL,
                       title="t", url=f"http://x/{username}", raw_data=raw)


def _doc():
    return OsintResult(search_id="t", module=ModuleType.WEB_SEARCH, category=ResultCategory.DOCUMENT,
                       title="doc", url="http://d", raw_data={})


# --- request_validation : repli immédiat ------------------------------------

def test_disabled_channel_returns_none_without_emitting():
    sent = []
    ch = ValidationChannel("s", send=_sender(sent), is_connected=lambda: True, enabled=False)
    assert asyncio.run(ch.request_validation({"candidates": []})) is None
    assert sent == []  # rien émis : no-op total


def test_disconnected_socket_returns_none_without_emitting():
    sent = []
    ch = ValidationChannel("s", send=_sender(sent), is_connected=lambda: False, enabled=True)
    assert asyncio.run(ch.request_validation({})) is None
    assert sent == []


# --- request_validation : reprise par submit --------------------------------

def test_submit_resolves_with_selection():
    async def scenario():
        sent = []
        ch = ValidationChannel("s", send=_sender(sent), is_connected=lambda: True,
                               timeout=5.0, heartbeat_interval=5.0)
        task = asyncio.ensure_future(ch.request_validation({"candidates": []}))
        await asyncio.sleep(0.05)  # laisse le request s'émettre puis attendre
        assert ch.submit({"selected": ["x"]}) is True
        result = await task
        assert result == {"selected": ["x"]}
        assert any(m.type == "validation_request" for m in sent)

    asyncio.run(scenario())


# --- request_validation : replis -------------------------------------------

def test_timeout_returns_none():
    async def scenario():
        sent = []
        ch = ValidationChannel("s", send=_sender(sent), is_connected=lambda: True,
                               timeout=0.05, heartbeat_interval=0.02)
        assert await ch.request_validation({}) is None  # personne ne répond → repli

    asyncio.run(scenario())


def test_fail_returns_none():
    async def scenario():
        ch = ValidationChannel("s", send=_sender([]), is_connected=lambda: True,
                               timeout=5.0, heartbeat_interval=5.0)
        task = asyncio.ensure_future(ch.request_validation({}))
        await asyncio.sleep(0.05)
        ch.fail()  # simule une déconnexion
        assert await task is None

    asyncio.run(scenario())


# --- heartbeat pendant l'attente --------------------------------------------

def test_heartbeat_emitted_while_waiting():
    async def scenario():
        sent = []
        ch = ValidationChannel("s", send=_sender(sent), is_connected=lambda: True,
                               timeout=5.0, heartbeat_interval=0.02)
        task = asyncio.ensure_future(ch.request_validation({}))
        await asyncio.sleep(0.08)  # plusieurs tics de heartbeat
        ch.submit("done")
        await task
        beats = [m for m in sent if m.type == "progress" and m.module == "validation"]
        assert len(beats) >= 1

    asyncio.run(scenario())


# --- submit / fail hors attente ---------------------------------------------

def test_submit_without_pending_is_noop():
    ch = ValidationChannel("s", send=_sender([]), is_connected=lambda: True)
    assert ch.submit("x") is False  # rien en attente → ignoré
    ch.fail()  # ne lève pas


# --- _build_validation_candidates -------------------------------------------

def test_build_candidates_keeps_only_accounts():
    acc = _acc("u", "X", photo_url="http://p", confidence="guessed",
               cluster_id="c0", in_target_cluster=True)
    payload = _build_validation_candidates([acc, _doc()])
    assert len(payload["candidates"]) == 1
    c = payload["candidates"][0]
    assert c["username"] == "u"
    assert c["platform"] == "X"
    assert c["cluster_id"] == "c0"
    assert c["in_target_cluster"] is True


def test_build_candidates_uses_login_fallback():
    gh = OsintResult(search_id="t", module=ModuleType.GITHUB, category=ResultCategory.SOCIAL,
                     title="gh", url="http://gh", raw_data={"login": "octocat"})
    payload = _build_validation_candidates([gh])
    assert payload["candidates"][0]["username"] == "octocat"


# --- _interactive_checkpoint : no-op hors mode interactif -------------------

def test_checkpoint_noop_without_channel():
    ws = types.SimpleNamespace(state=types.SimpleNamespace())
    assert asyncio.run(_interactive_checkpoint(ws, "s", [_acc()])) is None


def test_checkpoint_noop_when_channel_disabled():
    ch = ValidationChannel("s", send=_sender([]), is_connected=lambda: True, enabled=False)
    ws = types.SimpleNamespace(state=types.SimpleNamespace(validation_channel=ch))
    assert asyncio.run(_interactive_checkpoint(ws, "s", [_acc()])) is None


# --- _interactive_checkpoint : reprise sur sélection ------------------------

def test_checkpoint_returns_submitted_selection():
    async def scenario():
        sent = []
        ch = ValidationChannel("s", send=_sender(sent), is_connected=lambda: True,
                               timeout=5.0, heartbeat_interval=5.0)
        ws = types.SimpleNamespace(state=types.SimpleNamespace(validation_channel=ch))
        task = asyncio.ensure_future(_interactive_checkpoint(ws, "s", [_acc("u")]))
        await asyncio.sleep(0.05)
        ch.submit({"selected": ["u"]})
        result = await task
        assert result == {"selected": ["u"]}
        req = next(m for m in sent if m.type == "validation_request")
        assert req.data["candidates"][0]["username"] == "u"

    asyncio.run(scenario())
