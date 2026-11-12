"""Defense strategy contract.

``BaseDefenseStrategy`` is the single seam every hardening technique plugs
into.  Strategies receive bytes, return bytes, and emit typed
``HardeningEvent`` objects — they never touch the filesystem or the bus
directly, which keeps them composable and unit-testable.

Concept inspired by: bla — per-format shield modules returning transformed
payloads; chelate-shell — hard-gated stage contract.
"""

from __future__ import annotations

import abc
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

from core.models import ActivityKind, DefensePhase, DefenseVerdict, HardeningEvent

__all__ = ["BaseDefenseStrategy", "StrategyContext", "StrategyResult"]


@dataclass
class StrategyContext:
    """Everything a strategy may read; injected by the pipeline.

    ``seed`` drives deterministic randomness so re-running the same pipeline
    on the same input reproduces byte-identical output (attestable builds).
    """

    seed: int = 0
    intensity: str = "balanced"  # stealth | balanced | maximum | bankrupt
    rng: object = None  # random.Random, injected by pipeline


@dataclass
class StrategyResult:
    """Outcome of one ``apply`` call on one artifact."""

    data: bytes | None  # None means artifact untouched
    verdict: DefenseVerdict = DefenseVerdict.APPLIED
    events: list[HardeningEvent] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class BaseDefenseStrategy(abc.ABC):
    """One hardening technique over one artifact.

    Subclasses declare what they support via ``SUPPORTED_SUFFIXES`` (a suffix
    such as ``.py``/``.pyc``, or ``None`` for format-agnostic) and implement
    ``_apply``.
    """

    name: str = "base"
    phase: DefensePhase = DefensePhase.POISON
    SUPPORTED_SUFFIXES: ClassVar[set[str] | None] = None

    def supports(self, file_path: Path) -> bool:
        """Format gate: does this strategy accept the given artifact?"""
        if not self.SUPPORTED_SUFFIXES:
            return True
        return file_path.suffix.lower() in self.SUPPORTED_SUFFIXES

    def apply(self, file_path: Path, data: bytes, ctx: StrategyContext) -> StrategyResult:
        """Template method: delegate to ``_apply``; never raises.

        A strategy failure downgrades to a ``FAILED`` verdict and leaves
        ``data`` untouched so the chain keeps running.
        """
        try:
            result = self._apply(file_path, data, ctx)
        except Exception as exc:  # noqa: BLE001 — strategy failures must not kill the chain
            return StrategyResult(
                data=None,
                verdict=DefenseVerdict.FAILED,
                events=[
                    HardeningEvent(
                        event_id=f"{self.name}:error:{_artifact_key(file_path)}",
                        phase=self.phase,
                        activity=ActivityKind.SCAN,
                        severity="high",
                        artifact_path=str(file_path),
                        strategy=self.name,
                        message=f"strategy raised: {type(exc).__name__}: {exc}",
                    )
                ],
            )

        if result.data is None or result.data == data:
            # Nothing is written to disk, so the event must not advertise an
            # after-hash: report properties read a hash as "changed on disk".
            return StrategyResult(
                data=result.data,
                verdict=DefenseVerdict.SKIPPED,
                events=[
                    *result.events,
                    self._event(
                        file_path, data, None, "skipped: no change", role="outcome"
                    ),
                ],
            )

        return StrategyResult(
            data=result.data,
            verdict=DefenseVerdict.APPLIED,
            events=[
                *result.events,
                self._event(file_path, data, result.data, "applied", role="outcome"),
            ],
        )

    @abc.abstractmethod
    def _apply(self, file_path: Path, data: bytes, ctx: StrategyContext) -> StrategyResult:
        """Transform ``data``; return a result (``data=None`` means no change)."""

    def _event(
        self,
        file_path: Path,
        before: bytes | None,
        after: bytes | None,
        message: str,
        severity: str = "informational",
        *,
        role: str = "",
        **detail: object,
    ) -> HardeningEvent:
        scope = f"{self.name}:{role}" if role else self.name
        return HardeningEvent(
            event_id=f"{scope}:{_artifact_key(file_path)}",
            phase=self.phase,
            activity=ActivityKind.MODIFY,
            severity=severity,  # type: ignore[arg-type]
            artifact_path=str(file_path),
            strategy=self.name,
            message=message,
            before_sha256=_sha(before) if before is not None else None,
            after_sha256=_sha(after) if after is not None else None,
            detail=dict(detail),
        )


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _artifact_key(file_path: Path) -> str:
    """Collision-free id fragment for one artifact.

    ``Path.name`` alone is not unique: a build tree routinely holds several
    ``app.py``/``index.js``/``package.json`` files, and every event for them
    would share one id (and therefore one OCSF ``finding_info.uid``).
    """
    digest = hashlib.sha256(str(file_path).encode("utf-8")).hexdigest()[:12]
    return f"{file_path.name}:{digest}"
