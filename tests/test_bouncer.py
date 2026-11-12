"""Bouncer + HITL end-to-end: decision published on the bus -> gate -> execution.

Concept inspired by: crowdsec — decoupled decision enforcement tests.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from core.models import Decision, DecisionAction
from gates.human_approval import ApprovalState, HumanApprovalGate
from response.bouncer import Bouncer
from response.event_bus import EventBus


def test_approved_decision_executes(tmp_path: Path) -> None:
    moved_to: list[str] = []

    def quarantine_handler(decision: Decision) -> None:
        moved_to.append(decision.artifact_path)

    gate = HumanApprovalGate()

    async def approver(req):
        return True

    gate._approver = approver
    bouncer = Bouncer(gate)
    bouncer.register_handler(DecisionAction.QUARANTINE, quarantine_handler)
    decision = Decision(
        decision_id="dq1",
        artifact_path=str(tmp_path / "evil.py"),
        action=DecisionAction.QUARANTINE,
        reason="critical",
        triggered_by="e1",
        requires_human_approval=True,
    )
    result = asyncio.run(bouncer.handle_decision(decision))
    assert result.executed_at_epoch_ms is not None
    assert moved_to == [decision.artifact_path]
    assert bouncer.summary()["executed"] == ["dq1"]
    assert gate.get("dq1").state is ApprovalState.EXECUTED


def test_denied_decision_never_executes() -> None:
    executed: list[str] = []
    gate = HumanApprovalGate()

    async def approver(req):
        return False

    bouncer = Bouncer(gate)
    bouncer.register_handler(DecisionAction.QUARANTINE, lambda d: executed.append(d.decision_id))
    decision = Decision(
        decision_id="dq2",
        artifact_path="/tmp/x.py",
        action=DecisionAction.QUARANTINE,
        reason="critical",
        triggered_by="e1",
        requires_human_approval=True,
    )
    asyncio.run(bouncer.handle_decision(decision))
    assert executed == []
    assert bouncer.summary()["rejected"] == ["dq2"]


def test_bus_to_bouncer_decoupled_flow(tmp_path: Path) -> None:
    """Decider publishes; bouncer subscribes — no direct call between them."""
    bus = EventBus()
    gate = HumanApprovalGate()

    async def approver(req):
        return True

    gate._approver = approver
    bouncer = Bouncer(gate)
    sub = bus.subscribe("bouncer", types=(Decision,), maxsize=16)
    # wire the consume loop manually

    async def flow() -> None:
        async def consume() -> None:
            while True:
                _kind, payload = await sub.get()
                if isinstance(payload, Decision):
                    await bouncer.handle_decision(payload)

        task = asyncio.ensure_future(consume())
        decision = Decision(
            decision_id="dq3",
            artifact_path="/tmp/y.py",
            action=DecisionAction.QUARANTINE,
            reason="critical",
            triggered_by="e1",
            requires_human_approval=True,
        )
        bus.publish(decision)
        await asyncio.sleep(0.05)
        task.cancel()
        with __import__("contextlib").suppress(asyncio.CancelledError):
            await task

    asyncio.run(flow())
    assert "dq3" in [d.decision_id for d in bouncer.executed]


def test_replayed_decision_is_not_executed_twice() -> None:
    """Regression: re-requesting a resolved decision must not re-execute it.

    Pre-fix, ``gate.request()`` re-registered a terminal request as PENDING and
    the bouncer executed the same approved decision on every replay.
    """
    import asyncio

    from core.models import Decision, DecisionAction

    gate = HumanApprovalGate(timeout_seconds=1.0)
    bouncer = Bouncer(gate)

    def handler(decision: Decision) -> None:
        pass

    bouncer.register_handler(DecisionAction.QUARANTINE, handler)

    async def approve_first(_req) -> bool:
        return True

    gate._approver = approve_first

    decision = Decision(
        decision_id="replay-1",
        artifact_path="x.py",
        action=DecisionAction.QUARANTINE,
        reason="critical",
        triggered_by="e1",
        requires_human_approval=True,
    )

    async def scenario() -> None:
        await bouncer.handle_decision(decision)
        # Replay: same decision id arriving again (e.g. a duplicate bus event).
        replay = Decision(
            decision_id="replay-1",
            artifact_path="x.py",
            action=DecisionAction.QUARANTINE,
            reason="critical",
            triggered_by="e1",
            requires_human_approval=True,
        )
        await bouncer.handle_decision(replay)

    asyncio.run(scenario())
    assert bouncer.summary()["executed"] == ["replay-1"], bouncer.summary()


def test_gate_replay_returns_terminal_request() -> None:
    """Regression: gate.request() on an already-resolved decision returns it as-is.

    Scenario: an unguarded decision with no approver times out (auto-deny); a
    later re-request must observe TIMED_OUT, not resurrect PENDING.
    """
    import asyncio

    from core.models import Decision, DecisionAction
    from gates.human_approval import ApprovalState

    gate = HumanApprovalGate(timeout_seconds=0.05, auto_deny_on_timeout=True)

    async def scenario() -> tuple[ApprovalState, ApprovalState]:
        decision = Decision(
            decision_id="term-1",
            artifact_path="x.py",
            action=DecisionAction.QUARANTINE,
            reason="r",
            triggered_by="e1",
            requires_human_approval=True,
        )
        first = (await gate.request(decision)).state
        second = (await gate.request(decision)).state
        return first, second

    first, second = asyncio.run(scenario())
    assert first == ApprovalState.TIMED_OUT
    assert second == ApprovalState.TIMED_OUT  # terminal state survives replay
