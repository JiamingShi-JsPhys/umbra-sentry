"""Defense strategy chain-of-responsibility.

``HardeningPipeline`` owns an ordered list of strategies, walks every target
artifact through them, writes results to disk, and emits typed events onto
the bus.  Order matters: strategies declare a phase (audit -> poison ->
exhaust -> hallucinate -> verify) and the chain sorts by phase before
running, so later strategies see earlier strategies output.

Concept inspired by: bla -- 5-stage defend pipeline (audit/protect/verify);
chelate-shell -- deterministic ordered orchestration.
"""

from __future__ import annotations

import random
import shutil
import time
from pathlib import Path

from core.models import (
    ActivityKind,
    Decision,
    DecisionAction,
    DefensePhase,
    DefenseVerdict,
    HardeningEvent,
    HardeningReport,
    sha256_of,
)
from defense.base import BaseDefenseStrategy, StrategyContext
from response.event_bus import EventBus

__all__ = ["PHASE_ORDER", "HardeningPipeline"]

PHASE_ORDER: dict[DefensePhase, int] = {
    DefensePhase.AUDIT: 0,
    DefensePhase.POISON: 1,
    DefensePhase.EXHAUST: 2,
    DefensePhase.HALLUCINATE: 3,
    DefensePhase.VERIFY: 4,
    DefensePhase.RESPONSE: 5,
}

_PHASE_SORT_KEY = dict(PHASE_ORDER)


class HardeningPipeline:
    """Run a list of strategies over a target path, in phase order."""

    def __init__(
        self,
        strategies: list[BaseDefenseStrategy],
        bus: EventBus | None = None,
        *,
        seed: int = 0,
        intensity: str = "balanced",
        max_file_bytes: int = 8 * 1024 * 1024,
        max_files: int = 64,
        quarantine_dir: str | None = None,
    ) -> None:
        if not strategies:
            raise ValueError("pipeline needs at least one strategy")
        self.strategies = sorted(strategies, key=lambda s: _PHASE_SORT_KEY[s.phase])
        self.bus = bus
        self.seed = seed
        self.intensity = intensity
        self.max_file_bytes = max_file_bytes
        self.max_files = max_files
        self.quarantine_dir = quarantine_dir

    def discover_artifacts(self, target: Path) -> list[Path]:
        """Collect candidate files under target (bounded walk)."""
        if target.is_file():
            return [target]
        out: list[Path] = []
        for p in sorted(target.rglob("*")):
            if p.is_file():
                out.append(p)
            if len(out) >= self.max_files:
                break
        return out

    def run(self, target: str | Path) -> HardeningReport:
        """Harden everything under target and return the full report."""
        started = int(time.time() * 1000)
        target_path = Path(target).resolve()
        events: list[HardeningEvent] = []
        decisions: list[Decision] = []
        success = True
        error: str | None = None

        try:
            artifacts = self.discover_artifacts(target_path)
        except OSError as exc:
            return HardeningReport(
                target=str(target_path),
                started_epoch_ms=started,
                finished_epoch_ms=int(time.time() * 1000),
                strategies=[s.name for s in self.strategies],
                events=[],
                success=False,
                error=f"discovery failed: {exc}",
            )

        write_errors: list[str] = []

        for artifact in artifacts:
            data = self._read(artifact, events)
            if data is None:
                continue
            # One context per artifact.  A single shared RNG would let the
            # draws made for artifact A shift every later artifact's output,
            # so hardening one file would silently change the bytes written to
            # its siblings.  Deriving the stream from (seed, relative path)
            # keeps each artifact independent and stable across runs; str
            # seeding is SHA-512 based, unlike the per-process-randomized
            # ``hash()``.  The label is relative so relocating the tree does
            # not change the output.
            try:
                rel_label = artifact.relative_to(target_path).as_posix()
            except ValueError:  # pragma: no cover - discovery walks under target
                rel_label = artifact.name
            ctx = StrategyContext(
                seed=self.seed,
                intensity=self.intensity,
                rng=random.Random(f"{self.seed}\0{rel_label}"),
            )
            for strategy in self.strategies:
                if not strategy.supports(artifact):
                    continue
                result = strategy.apply(artifact, data, ctx)
                events.extend(result.events)
                self._emit_all(result.events)
                if result.verdict == DefenseVerdict.FAILED:
                    continue
                if result.data is not None and result.data != data:
                    exc = self._write(artifact, result.data)
                    if exc is None:
                        data = result.data
                    else:
                        # The bytes never reached disk: fail the report, audit
                        # the loss, and do not decide on events describing
                        # work that was lost.  ``failed_after_sha256`` lets the
                        # report properties exclude this artifact.
                        ev = self._book_event(artifact, "write-error", f"write failed: {exc}", "critical")
                        ev.detail["failed_after_sha256"] = sha256_of(result.data)
                        events.append(ev)
                        success = False
                        write_errors.append(str(artifact))
                        continue
                decisions.extend(self._decide(result.events, artifact))

        if write_errors:
            error = f"write failed: {len(write_errors)} artifact(s) could not be written: {', '.join(write_errors)}"

        return HardeningReport(
            target=str(target_path),
            started_epoch_ms=started,
            finished_epoch_ms=int(time.time() * 1000),
            strategies=[s.name for s in self.strategies],
            events=events,
            decisions=decisions,
            success=success,
            error=error,
        )

    def _read(self, path: Path, events: list[HardeningEvent]) -> bytes | None:
        try:
            if path.stat().st_size > self.max_file_bytes:
                events.append(self._book_event(path, "skip-large", f"exceeds max_file_bytes ({self.max_file_bytes})", "low"))
                return None
            return path.read_bytes()
        except OSError as exc:
            events.append(self._book_event(path, "read-error", f"read failed: {exc}", "high"))
            return None

    def _write(self, path: Path, data: bytes) -> OSError | None:
        """Persist bytes; return the ``OSError`` on failure, ``None`` on success.

        Audit bookkeeping lives in ``run()`` so it cannot be skipped by a
        subclass overriding I/O.
        """
        try:
            path.write_bytes(data)
            return None
        except OSError as exc:
            return exc

    def _book_event(self, path: Path, tag: str, message: str, severity: str) -> HardeningEvent:
        return HardeningEvent(
            event_id=f"pipeline:{tag}:{path.name}",
            phase=DefensePhase.AUDIT,
            activity=ActivityKind.SCAN,
            severity=severity,
            artifact_path=str(path),
            strategy="pipeline",
            message=message,
        )

    def _decide(self, events: list[HardeningEvent], artifact: Path) -> list[Decision]:
        """Decider: critical events request quarantine behind a HITL gate.

        Each Decision is published on the bus as it is raised, so a host can
        attach the bouncer as a subscriber instead of polling the report; the
        report keeps the same objects for one-shot callers and serialization.
        """
        out: list[Decision] = []
        for ev in events:
            if ev.severity.value == "critical":
                out.append(
                    Decision(
                        decision_id=f"dec:{ev.event_id}",
                        artifact_path=str(artifact),
                        action=DecisionAction.QUARANTINE,
                        reason=f"critical event {ev.event_id}: {ev.message}",
                        triggered_by=ev.event_id,
                        confidence=0.9,
                        requires_human_approval=True,
                    )
                )
        if self.bus is not None:
            for decision in out:
                self.bus.publish(decision)
        return out

    def _emit_all(self, events: list[HardeningEvent]) -> None:
        if self.bus is None:
            return
        for ev in events:
            self.bus.publish(ev)

    def quarantine(self, artifact: Path, decision: Decision) -> Path | None:
        """Bouncer action: move an artifact into the quarantine directory."""
        if self.quarantine_dir is None:
            return None
        qroot = Path(self.quarantine_dir)
        qroot.mkdir(parents=True, exist_ok=True)
        dest = qroot / artifact.name
        shutil.move(str(artifact), str(dest))
        decision.executed_at_epoch_ms = int(time.time() * 1000)
        if self.bus is not None:
            self.bus.publish(
                HardeningEvent(
                    event_id=f"bouncer:quarantine:{artifact.name}",
                    phase=DefensePhase.RESPONSE,
                    activity=ActivityKind.BLOCK,
                    severity="medium",
                    artifact_path=str(dest),
                    strategy="bouncer",
                    message=f"quarantined per {decision.decision_id}",
                )
            )
        return dest
