"""Human-in-the-loop approval state machine.

High-severity remediations (quarantine, rebuild-block) do not fire straight
away: the decider publishes a pending approval, this gate blocks on a
confirmation channel (CLI prompt, webhook callback, or a test harness), and
only a ``PENDING -> APPROVED`` transition lets the bouncer execute.  Every
transition is recorded so the audit trail shows who approved what, when.

State machine::

    PENDING --approve--> APPROVED --execute--> EXECUTED
       |                                        (terminal)
       +--deny--> DENIED                        (terminal)
       +--timeout--> TIMED_OUT                  (terminal)

Concept inspired by: crowdsec -- decision/bouncer separation; chelate-shell
-- hard gates on consequential actions.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from enum import Enum

from core.models import Decision

__all__ = [
    "ApprovalRequest",
    "ApprovalState",
    "HumanApprovalGate",
]

class ApprovalState(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    TIMED_OUT = "timed_out"
    EXECUTED = "executed"



class ApprovalRequest:
    """One decision awaiting a human verdict."""

    __slots__ = ("decision", "requested_at_epoch_ms", "resolved_at_epoch_ms", "resolved_by", "state")

    def __init__(self, decision: Decision) -> None:
        self.decision = decision
        self.state = ApprovalState.PENDING
        self.requested_at_epoch_ms = int(time.time() * 1000)
        self.resolved_at_epoch_ms: int | None = None
        self.resolved_by: str | None = None

    @property
    def decision_id(self) -> str:
        return self.decision.decision_id

    def snapshot(self) -> dict:
        return {
            "decision_id": self.decision_id,
            "state": self.state.value,
            "action": self.decision.action.value,
            "artifact": self.decision.artifact_path,
            "requested_at_epoch_ms": self.requested_at_epoch_ms,
            "resolved_at_epoch_ms": self.resolved_at_epoch_ms,
            "resolved_by": self.resolved_by,
        }


ApproverFn = Callable[["ApprovalRequest"], Awaitable[bool]]


class HumanApprovalGate:
    """Async HITL gate with timeout, deny-by-default, and a full audit trail.

    ``approver`` is the blocking confirmation channel: an async callable that
    resolves ``True`` (approve) or ``False`` (deny) — e.g. a CLI prompt
    wrapped in ``asyncio.to_thread``, or a webhook-awaiting coroutine.  When
    the timeout expires or no approver is wired, the request auto-denies:
    fail-closed, never fail-open.
    """

    def __init__(
        self,
        approver: ApproverFn | None = None,
        *,
        timeout_seconds: float = 300.0,
        auto_deny_on_timeout: bool = True,
    ) -> None:
        self._approver = approver
        self._timeout = timeout_seconds
        self._auto_deny = auto_deny_on_timeout
        self._requests: dict[str, ApprovalRequest] = {}

    # -- registry ---------------------------------------------------------

    @property
    def requests(self) -> dict[str, ApprovalRequest]:
        return dict(self._requests)

    def get(self, decision_id: str) -> ApprovalRequest | None:
        return self._requests.get(decision_id)

    def pending_ids(self) -> list[str]:
        return [d for d, r in self._requests.items() if r.state == ApprovalState.PENDING]

    # -- the gate -----------------------------------------------------------

    async def request(self, decision: Decision) -> ApprovalRequest:
        """Register a decision and block until a terminal state is reached."""
        existing = self._requests.get(decision.decision_id)
        if existing is not None and existing.state != ApprovalState.PENDING:
            # Replay guard: a terminal request must never be re-registered, or a
            # second ``request()`` call resurrects it to PENDING and the bouncer
            # executes an already-resolved decision again.
            return existing
        req = ApprovalRequest(decision)
        self._requests[decision.decision_id] = req
        if decision.requires_human_approval is False:
            # Auto-approve non-guarded actions (monitor/report).
            req.state = ApprovalState.APPROVED
            req.resolved_by = "auto"
            req.resolved_at_epoch_ms = int(time.time() * 1000)
            # The audit trail must attribute every approved decision, and the
            # early return below skips the generic assignment, so record it here.
            decision.approved_by = "auto"
            return req

        verdict: bool | None = None
        if self._approver is not None:
            try:
                verdict = await asyncio.wait_for(
                    self._approver(req), timeout=self._timeout
                )
            except TimeoutError:
                verdict = None
            except Exception as exc:  # noqa: BLE001 — a broken channel must deny, not crash
                verdict = False
                req.resolved_by = f"approver-error:{type(exc).__name__}"
        else:
            verdict = None

        now = int(time.time() * 1000)
        if verdict is True:
            req.state = ApprovalState.APPROVED
        elif verdict is False:
            req.state = ApprovalState.DENIED
        else:
            req.state = ApprovalState.TIMED_OUT if self._auto_deny else ApprovalState.PENDING
        if req.resolved_by is None:
            req.resolved_by = "timeout" if verdict is None else "approver"
        req.resolved_at_epoch_ms = now
        decision.approved_by = req.resolved_by if req.state == ApprovalState.APPROVED else None
        return req

    def approve(self, decision_id: str, by: str) -> ApprovalRequest:
        """Synchronous external confirmation (e.g. webhook callback endpoint)."""
        return self._resolve(decision_id, ApprovalState.APPROVED, by)

    def deny(self, decision_id: str, by: str) -> ApprovalRequest:
        return self._resolve(decision_id, ApprovalState.DENIED, by)

    def mark_executed(self, decision_id: str) -> ApprovalRequest:
        """Record execution of an approved decision (APPROVED -> EXECUTED).

        Called by the bouncer after its handler returns, so the state machine
        is the one that actually ran rather than a diagram-only terminal.
        """
        req = self._requests[decision_id]
        if req.state != ApprovalState.APPROVED:
            raise RuntimeError(
                f"decision {decision_id} cannot be executed from {req.state.value}"
            )
        req.state = ApprovalState.EXECUTED
        return req

    def _resolve(self, decision_id: str, state: ApprovalState, by: str) -> ApprovalRequest:
        req = self._requests[decision_id]
        if req.state != ApprovalState.PENDING:
            raise RuntimeError(f"decision {decision_id} already {req.state.value}")
        req.state = state
        req.resolved_by = by
        req.resolved_at_epoch_ms = int(time.time() * 1000)
        if state == ApprovalState.APPROVED:
            req.decision.approved_by = by
        return req
