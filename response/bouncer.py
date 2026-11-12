"""Bouncer: event-driven remediation executor.

Consumes ``Decision`` payloads from the bus (``consume``) or, in a one-shot
host such as the CLI, receives the report's decisions directly through
``handle_decision`` so the run can terminate deterministically.  Either way
every decision goes through the HITL gate: the pipeline publishes, the
bouncer enforces — crowdsec-style decoupling on an in-process bus.

Concept inspired by: crowdsec — remediation components polling decisions,
rebuilt as a bus subscriber.
"""

from __future__ import annotations

import time

from core.models import Decision, DecisionAction
from gates.human_approval import ApprovalState, HumanApprovalGate

__all__ = ["Bouncer"]


class Bouncer:
    """Decision subscriber + HITL-gated executor."""

    def __init__(self, gate: HumanApprovalGate) -> None:
        self.gate = gate
        self.executed: list[Decision] = []
        self.rejected: list[Decision] = []
        self._handlers: dict[DecisionAction, object] = {}
        self._executed_ids: set[str] = set()

    def register_handler(self, action: DecisionAction, handler) -> None:
        """Bind an executor callable ``handler(decision) -> None`` to an action."""
        self._handlers[action] = handler

    async def handle_decision(self, decision: Decision) -> Decision:
        """One decision through the gate; executes iff APPROVED."""
        # Second line of defense: even if a gate ever returns APPROVED twice
        # (stale request replay), one decision id executes exactly once.
        if decision.decision_id in self._executed_ids:
            self.rejected.append(decision)
            return decision
        request = await self.gate.request(decision)
        if request.state == ApprovalState.APPROVED:
            self._executed_ids.add(decision.decision_id)
            self._execute(decision)
            self.executed.append(decision)
        else:
            self.rejected.append(decision)
        return decision

    async def consume(self, subscription) -> None:
        """Bus loop: pull ``(kind, payload)`` items and route decisions."""
        while True:
            _kind, payload = await subscription.get()
            if isinstance(payload, Decision):
                await self.handle_decision(payload)

    def _execute(self, decision: Decision) -> None:
        handler = self._handlers.get(decision.action)
        if handler is not None:
            handler(decision)
        # Default (no handler): record-only execution; the pipeline owns the
        # file move. Either way the gate records the APPROVED -> EXECUTED
        # transition, so the documented state machine is the one that ran.
        decision.executed_at_epoch_ms = int(time.time() * 1000)
        self.gate.mark_executed(decision.decision_id)

    def summary(self) -> dict:
        return {
            "executed": [d.decision_id for d in self.executed],
            "rejected": [d.decision_id for d in self.rejected],
        }
