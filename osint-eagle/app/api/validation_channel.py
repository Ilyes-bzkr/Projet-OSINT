"""
Canal de validation interactive — OSINT Eagle (Phase C, plomberie pure).

Fournit la capacité technique de PAUSE/REPRISE de l'orchestration en attendant
une décision humaine, sans aucune logique métier de validation (celle-ci viendra
en Phase D). Le canal est volontairement découplé de FastAPI : il reçoit un
`send` (coroutine d'émission) et un `is_connected` (prédicat) injectés, ce qui le
rend testable en isolation avec un faux émetteur.

Mécanique :
- `request_validation(payload)` émet un message `validation_request` puis
  suspend la coroutine appelante sur une `Future` (pas de busy-wait). Pendant
  l'attente, un battement de heartbeat maintient la WebSocket ouverte (les
  navigateurs ferment une socket inactive ~60s). Au-delà du `timeout`, ou si la
  connexion tombe, la méthode rend `None` → l'orchestrateur reprend (repli).
- `submit(response)` (appelé par la tâche lectrice à la réception d'un
  `validation_response`) résout la `Future` → reprise immédiate.
- `fail()` (appelé sur déconnexion) résout la `Future` avec `None` → repli.

Désactivé (`enabled=False`), `request_validation` rend `None` immédiatement sans
rien émettre : le mode non-interactif se comporte exactement comme avant.
"""

import asyncio
from typing import Any, Awaitable, Callable, Optional

from app.core.logger import logger
from app.models.result import WebSocketMessage

# Délai max d'attente d'une validation avant repli (poursuite sans nouvelle
# décision). Généreux : l'humain doit avoir le temps de cocher.
DEFAULT_VALIDATION_TIMEOUT = 300.0
# Intervalle de heartbeat pendant l'attente (les navigateurs ferment une socket
# inactive ~60s ; 15s laisse une marge large). Aligné sur le heartbeat IA.
DEFAULT_VALIDATION_HEARTBEAT = 15.0
# Progression émise par le heartbeat de validation : entre « couche 1 terminée »
# (40) et « couche 2 » (45), volontairement stable.
_VALIDATION_PROGRESS = 42


class ValidationChannel:
    """Canal awaitable de pause/reprise pour la validation interactive."""

    def __init__(
        self,
        search_id: str,
        send: Callable[[WebSocketMessage], Awaitable[Any]],
        is_connected: Callable[[], bool],
        enabled: bool = True,
        timeout: float = DEFAULT_VALIDATION_TIMEOUT,
        heartbeat_interval: float = DEFAULT_VALIDATION_HEARTBEAT,
    ):
        self._search_id = search_id
        self._send = send
        self._is_connected = is_connected
        self.enabled = enabled
        self._timeout = timeout
        self._heartbeat = heartbeat_interval
        self._pending: Optional[asyncio.Future] = None

    # --- côté orchestrateur -------------------------------------------------

    async def request_validation(
        self,
        payload: Any,
        *,
        timeout: Optional[float] = None,
        heartbeat_interval: Optional[float] = None,
    ) -> Optional[Any]:
        """Émet un `validation_request` et attend la réponse (ou un repli).

        Rend la sélection reçue, ou `None` si : le canal est désactivé, la socket
        est fermée, le délai est dépassé, ou la connexion tombe pendant l'attente.
        Ne lève jamais : tout repli rend `None`.
        """
        if not self.enabled or not self._is_connected():
            return None

        timeout = self._timeout if timeout is None else timeout
        heartbeat_interval = self._heartbeat if heartbeat_interval is None else heartbeat_interval

        loop = asyncio.get_running_loop()

        # Garde-fou : un checkpoint précédent encore en attente est replié avant
        # d'en ouvrir un nouveau (ne devrait pas arriver — un seul checkpoint).
        if self._pending is not None and not self._pending.done():
            self._pending.set_result(None)

        fut: asyncio.Future = loop.create_future()
        self._pending = fut
        try:
            await self._emit_request(payload)
            deadline = loop.time() + timeout
            while True:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    logger.info("[validation] délai dépassé — reprise sans validation (repli)")
                    return None
                wait = max(0.01, min(remaining, heartbeat_interval))
                done, _ = await asyncio.wait({fut}, timeout=wait)
                if fut in done:
                    return fut.result()
                # Tic de heartbeat : maintenir la socket ouverte, puis re-attendre.
                if not self._is_connected():
                    return None
                await self._emit_heartbeat()
        except Exception as e:  # robustesse : aucune erreur d'émission ne bloque
            logger.warning(f"[validation] erreur pendant l'attente (repli) : {e}")
            return None
        finally:
            if self._pending is fut:
                self._pending = None

    # --- côté lecteur (messages entrants) -----------------------------------

    def submit(self, response: Any) -> bool:
        """Résout le checkpoint en attente avec la sélection reçue.

        Rend True si un checkpoint attendait, False sinon (réponse ignorée).
        """
        fut = self._pending
        if fut is not None and not fut.done():
            fut.set_result(response)
            return True
        return False

    def fail(self) -> None:
        """Replie le checkpoint en attente (déconnexion / erreur lecteur)."""
        fut = self._pending
        if fut is not None and not fut.done():
            fut.set_result(None)

    # --- émission -----------------------------------------------------------

    async def _emit_request(self, payload: Any) -> None:
        await self._send(WebSocketMessage(
            type="validation_request",
            search_id=self._search_id,
            message="En attente de validation des candidats...",
            progress=_VALIDATION_PROGRESS,
            data=payload,
        ))

    async def _emit_heartbeat(self) -> None:
        try:
            await self._send(WebSocketMessage(
                type="progress",
                module="validation",
                search_id=self._search_id,
                message="En attente de votre validation...",
                progress=_VALIDATION_PROGRESS,
            ))
        except Exception:
            # Le heartbeat ne doit jamais propager : l'attente continue jusqu'au
            # timeout, qui repliera proprement.
            pass
