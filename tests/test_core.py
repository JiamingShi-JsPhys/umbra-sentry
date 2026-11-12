"""Tests for the pipeline, event bus, and HITL gate.

Concept inspired by: crowdsec tests — pipeline behavior verification.
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

import pytest

from core.models import (
    ActivityKind,
    Decision,
    DecisionAction,
    DefensePhase,
    DefenseVerdict,
    HardeningEvent,
)
from core.pipeline import HardeningPipeline
from defense.base import BaseDefenseStrategy, StrategyContext, StrategyResult
from gates.human_approval import ApprovalState, HumanApprovalGate
from response.event_bus import EventBus


class AppendStrategy(BaseDefenseStrategy):
    """Deterministic strategy that appends a marker line."""

    name = "test-append"
    phase = DefensePhase.POISON

    def _apply(self, file_path: Path, data: bytes, ctx: StrategyContext) -> StrategyResult:
        marker = f"# {self.name}:{ctx.seed}\n".encode()
        return StrategyResult(data=data + marker)


class BoomStrategy(BaseDefenseStrategy):
    """Strategy whose _apply always raises."""

    name = "test-boom"
    phase = DefensePhase.EXHAUST

    def _apply(self, file_path: Path, data: bytes, ctx: StrategyContext) -> StrategyResult:
        raise RuntimeError("boom")


def test_chain_runs_in_phase_order(tmp_path: Path) -> None:
    target = tmp_path / "app.py"
    target.write_text("print(1)\n", encoding="utf-8")
    pipe = HardeningPipeline([AppendStrategy()])
    report = pipe.run(target)
    assert report.success
    assert report.applied_events, "expected at least one applied event"
    assert str(target) in report.modified_artifacts


def test_strategy_failure_is_isolated(tmp_path: Path) -> None:
    target = tmp_path / "app.py"
    target.write_text("print(1)\n", encoding="utf-8")
    boom = BoomStrategy()
    result = boom.apply(target, b"data", StrategyContext())
    assert result.verdict == DefenseVerdict.FAILED
    assert result.data is None
    assert "boom" in result.events[0].message


def test_pipeline_survives_failing_strategy(tmp_path: Path) -> None:
    target = tmp_path / "app.py"
    target.write_text("print(1)\n", encoding="utf-8")
    pipe = HardeningPipeline([BoomStrategy(), AppendStrategy()])
    report = pipe.run(target)
    # The boom strategy failed but the chain continued.
    assert any(e.strategy == "test-append" for e in report.applied_events)
    assert "# test-append:0" in target.read_text(encoding="utf-8")


def test_phase_sorting(tmp_path: Path) -> None:
    pipe = HardeningPipeline([AppendStrategy()])
    assert [s.phase for s in pipe.strategies] == [DefensePhase.POISON]


def test_bounded_discovery(tmp_path: Path) -> None:
    for i in range(10):
        (tmp_path / f"f{i}.txt").write_text("x", encoding="utf-8")
    pipe = HardeningPipeline([AppendStrategy()], max_files=3)
    assert len(pipe.discover_artifacts(tmp_path)) == 3


def test_bus_publish_subscribe() -> None:
    bus = EventBus()
    sub = bus.subscribe("collector")

    ev = HardeningEvent(
        event_id="e1",
        phase=DefensePhase.POISON,
        activity=ActivityKind.MODIFY,
        severity="low",
        artifact_path="/tmp/x.py",
        strategy="s",
        message="m",
    )
    bus.publish(ev)
    kind, payload = asyncio.get_event_loop_policy().new_event_loop().run_until_complete(sub.get())
    assert kind is HardeningEvent
    assert payload.event_id == "e1"
    assert bus.history
    assert "collector" in bus.subscriber_names


def test_bus_filters_by_type() -> None:
    bus = EventBus()
    sub_events = bus.subscribe("events-only", types=(HardeningEvent,))
    decision = Decision(
        decision_id="d1",
        artifact_path="/tmp/x.py",
        action=DecisionAction.QUARANTINE,
        reason="r",
        triggered_by="e1",
    )
    bus.publish(decision)
    assert sub_events.pending == 0, "event-only subscriber must not receive decisions"


def test_gate_auto_deny_on_timeout() -> None:
    async def scenario() -> ApprovalState:
        gate = HumanApprovalGate(timeout_seconds=0.01)

        async def never(req):
            await asyncio.sleep(10)
            return True

        gate._approver = never
        decision = Decision(
            decision_id="d2",
            artifact_path="/tmp/x.py",
            action=DecisionAction.QUARANTINE,
            reason="r",
            triggered_by="e1",
            requires_human_approval=True,
        )
        req = await gate.request(decision)
        return req.state

    state = asyncio.run(scenario())
    assert state == ApprovalState.TIMED_OUT


def test_gate_approve_then_execute() -> None:
    gate = HumanApprovalGate()
    decision = Decision(
        decision_id="d3",
        artifact_path="/tmp/x.py",
        action=DecisionAction.QUARANTINE,
        reason="r",
        triggered_by="e1",
        requires_human_approval=True,
    )
    gate._requests["d3"] = __import__(
        "gates.human_approval", fromlist=["ApprovalRequest"]
    ).ApprovalRequest(decision)
    req = gate.approve("d3", "operator-alice")
    assert req.state == ApprovalState.APPROVED
    assert decision.approved_by == "operator-alice"
    with pytest.raises(RuntimeError):
        gate.approve("d3", "bob")  # already resolved


def test_gate_deny_is_fail_closed() -> None:
    async def scenario() -> str:
        gate = HumanApprovalGate()

        async def rejector(req):
            return False

        gate._approver = rejector

        decision = Decision(
            decision_id="d4",
            artifact_path="/tmp/x.py",
            action=DecisionAction.BLOCK_REBUILD,
            reason="r",
            triggered_by="e1",
            requires_human_approval=True,
        )
        req = await gate.request(decision)
        return req.state.value

    assert asyncio.run(scenario()) == "denied"


class IdempotentStrategy(BaseDefenseStrategy):
    """Appends one marker line, then reports SKIPPED on every later pass."""

    name = "test-idempotent"
    phase = DefensePhase.POISON

    def _apply(self, file_path: Path, data: bytes, ctx: StrategyContext) -> StrategyResult:
        marker = f"# {self.name}\n".encode()
        if marker in data:
            return StrategyResult(data=data)
        return StrategyResult(data=data + marker)


class DetailEventStrategy(IdempotentStrategy):
    """Emits its own detail event, the way the built-in strategies do."""

    name = "test-detail"

    def _apply(self, file_path: Path, data: bytes, ctx: StrategyContext) -> StrategyResult:
        marker = f"# {self.name}\n".encode()
        if marker in data:
            return StrategyResult(data=data)
        new = data + marker
        return StrategyResult(
            data=new,
            events=[self._event(file_path, data, new, "detail", severity="low")],
        )


def test_event_ids_are_unique_per_event_and_per_artifact(tmp_path: Path) -> None:
    """OCSF finding_info.uid is the event id, so event ids must not collide."""
    target = tmp_path / "app.py"
    target.write_text("print(1)\n", encoding="utf-8")
    report = HardeningPipeline([DetailEventStrategy()]).run(target)

    # The strategy's detail event and the template outcome event are two
    # distinct events for one artifact and must not share an id.
    ids = [event.event_id for event in report.events]
    assert len(ids) == 2
    assert len(set(ids)) == 2, f"duplicate event ids: {ids}"

    # Same basename, different directories, different content: also distinct.
    nested = tmp_path / "nested"
    for folder in ("first", "second"):
        (nested / folder).mkdir(parents=True)
        (nested / folder / "app.py").write_text(
            f"print({folder!r})\n", encoding="utf-8"
        )
    report = HardeningPipeline([DetailEventStrategy()]).run(nested)
    ids = [event.event_id for event in report.events]
    assert len(ids) == 4
    assert len(set(ids)) == 4, f"duplicate event ids: {ids}"


def test_rerun_does_not_report_unchanged_artifacts(tmp_path: Path) -> None:
    """A second pass writes nothing, so it must report no applied work."""
    target = tmp_path / "app.py"
    target.write_text("print(1)\n", encoding="utf-8")
    pipe = HardeningPipeline([IdempotentStrategy()])

    first = pipe.run(target)
    assert str(target) in first.modified_artifacts
    assert first.applied_events

    hardened = target.read_bytes()
    second = pipe.run(target)
    assert target.read_bytes() == hardened
    assert second.modified_artifacts == []
    assert second.applied_events == []


def test_bus_overflow_does_not_hang_drain() -> None:
    """Regression: dropped-on-overflow items were consumed without task_done(),
    leaving unfinished_tasks stuck and drain() hanging forever."""
    import asyncio

    from core.models import Decision

    bus = EventBus(default_maxsize=4)
    sub = bus.subscribe("slow", types=(Decision,), maxsize=4)

    for i in range(60):
        bus.publish(Decision(decision_id=f"d{i}", artifact_path="a", action=DecisionAction.MONITOR, reason="r", triggered_by="e"))

    async def drain_all() -> None:
        while True:
            try:
                _kind, _payload = await asyncio.wait_for(sub.get(), timeout=1.0)
                sub.queue.task_done()
            except TimeoutError:
                return

    async def join_cleanly() -> None:
        # Without per-drop task_done(), the dropped items keep the join counter
        # pinned above zero and this join hangs forever (fail after 2s).
        await asyncio.wait_for(sub.queue.join(), timeout=2.0)

    asyncio.run(drain_all())
    asyncio.run(join_cleanly())
    assert any("overflow" in d for d in bus.dead_letters)


def test_write_failure_fails_the_report() -> None:
    """Regression: an unwritable artifact must fail the report and skip
    decisions, not be reported as hardened with success=True."""
    from defense.base import BaseDefenseStrategy, StrategyResult

    class AppendStrategy(BaseDefenseStrategy):
        name = "append"
        phase = DefensePhase.POISON

        def _apply(self, file_path: Path, data: bytes, ctx: StrategyContext) -> StrategyResult:
            return StrategyResult(data=data + b"# more\n")

    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp) / "locked.py"
        target.write_text("x = 1\n", encoding="utf-8")

        pipe = HardeningPipeline([AppendStrategy()])
        pipe._write = lambda path, data: OSError(13, "Permission denied")  # denied write
        report = pipe.run(target)

        assert report.success is False
        assert report.error is not None and "write failed" in report.error
        assert report.modified_artifacts == []
        assert report.applied_events == []
        assert report.decisions == []  # no decisions over lost work
        # The real _write surfaces the OSError for run() to audit.
        assert HardeningPipeline([AppendStrategy()])._write(
            Path(tmp) / "no-dir" / "x.py", b"d"
        ) is not None

def test_decider_publishes_each_decision_on_the_bus(tmp_path: Path) -> None:
    """The decider -> bus edge in the architecture diagram must be real.

    Regression: decisions used to live only in the report, so a bouncer
    subscribed to the bus could never see one.
    """
    bus = EventBus()
    pipeline = HardeningPipeline([AppendStrategy()], bus=bus, seed=0, intensity="balanced")
    event = HardeningEvent(
        event_id="ev-critical",
        phase=DefensePhase.AUDIT,
        activity=ActivityKind.SCAN,
        severity="critical",
        artifact_path=str(tmp_path / "x.bin"),
        strategy="test",
        message="critical",
    )

    decisions = pipeline._decide([event], tmp_path / "x.bin")

    published = [payload for _seq, payload in bus.history
                 if isinstance(payload, Decision)]
    assert decisions
    assert published == decisions
