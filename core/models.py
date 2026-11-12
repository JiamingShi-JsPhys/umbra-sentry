"""Typed event contracts for umbra-sentry.

Every datum flowing between pipeline stages, adapters, and the response layer
carries one of these Pydantic models.  Nothing crosses a boundary as a bare
dict.

Concept inspired by: py-ocsf-models (Prowler) — strong-typed OCSF event
classes; crowdsec — typed alerts/decisions crossing stage boundaries.
"""

from __future__ import annotations

import hashlib
import time
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, computed_field

__all__ = [
    "ActivityKind",
    "Decision",
    "DecisionAction",
    "DefensePhase",
    "DefenseVerdict",
    "EventSeverity",
    "HardeningEvent",
    "HardeningReport",
    "sha256_of",
]


def sha256_of(data: bytes) -> str:
    """Lowercase hex SHA-256 of ``data`` — the artifact identity primitive."""
    return hashlib.sha256(data).hexdigest()


class DefensePhase(str, Enum):
    """Where in the hardening lifecycle an event was emitted."""

    AUDIT = "audit"
    POISON = "poison"
    EXHAUST = "exhaust"
    HALLUCINATE = "hallucinate"
    VERIFY = "verify"
    RESPONSE = "response"


class DefenseVerdict(str, Enum):
    """Terminal state a strategy reports for one artifact."""

    APPLIED = "applied"
    SKIPPED = "skipped"  # format unsupported / nothing to do
    FAILED = "failed"  # strategy raised; artifact left untouched
    BLOCKED = "blocked"  # HITL gate refused the action


class EventSeverity(str, Enum):
    """OCSF-aligned severity ladder (severity_id 0..6)."""

    UNKNOWN = "unknown"
    INFO = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    FATAL = "fatal"

    @property
    def ocsf_id(self) -> int:
        return _OCSF_SEVERITY_ID[self]


_OCSF_SEVERITY_ID: dict[EventSeverity, int] = {
    EventSeverity.UNKNOWN: 0,
    EventSeverity.INFO: 1,
    EventSeverity.LOW: 2,
    EventSeverity.MEDIUM: 3,
    EventSeverity.HIGH: 4,
    EventSeverity.CRITICAL: 5,
    EventSeverity.FATAL: 6,
}


class ActivityKind(str, Enum):
    """What happened, in OCSF activity_id terms (class_uid 4001 scoped)."""

    CREATE = "create"
    READ = "read"
    MODIFY = "modify"
    SCAN = "scan"
    ALERT = "alert"
    BLOCK = "block"

    @property
    def ocsf_id(self) -> int:
        return _OCSF_ACTIVITY_ID[self]


_OCSF_ACTIVITY_ID: dict[ActivityKind, int] = {
    ActivityKind.CREATE: 1,
    ActivityKind.READ: 2,
    ActivityKind.MODIFY: 3,
    ActivityKind.SCAN: 4,
    ActivityKind.ALERT: 5,
    ActivityKind.BLOCK: 6,
}


class HardeningEvent(BaseModel):
    """One atomic thing that happened while hardening one artifact.

    Internal IR.  The OCSF adapter projects this into a typed OCSF Detection
    Finding; the Sigma adapter consumes rule-shaped events into YAML.
    """

    model_config = {"validate_assignment": True}

    event_id: str = Field(..., description="Deterministic id, e.g. 'poison:canary:0007'.")
    phase: DefensePhase
    activity: ActivityKind
    severity: EventSeverity = EventSeverity.INFO
    artifact_path: str = Field(..., description="File the event concerns.")
    strategy: str = Field(..., description="Strategy short name, e.g. 'poison-canary'.")
    message: str
    detail: dict[str, Any] = Field(default_factory=dict)
    before_sha256: str | None = Field(None, pattern=r"^[a-f0-9]{64}$")
    after_sha256: str | None = Field(None, pattern=r"^[a-f0-9]{64}$")
    ts_epoch_ms: int = Field(
        default_factory=lambda: int(time.time() * 1000),
        description="Wall-clock epoch ms; injected by callers so replay stays deterministic.",
    )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def artifact_name(self) -> str:
        return self.artifact_path.replace("\\", "/").rsplit("/", 1)[-1]


class DecisionAction(str, Enum):
    """Remediation verbs the decider may request (crowdsec decision types)."""

    MONITOR = "monitor"
    QUARANTINE = "quarantine"  # copy aside, mark on disk
    REPORT = "report"  # append to hardening report only
    BLOCK_REBUILD = "block_rebuild"  # forbid shipping the artifact


class Decision(BaseModel):
    """A remediation request emitted by the decider and executed by the bouncer."""

    model_config = {"validate_assignment": True}

    decision_id: str
    artifact_path: str
    action: DecisionAction
    reason: str
    triggered_by: str = Field(..., description="Event id that produced this decision.")
    confidence: float = Field(0.0, ge=0.0, le=1.0, allow_inf_nan=False)
    requires_human_approval: bool = False
    approved_by: str | None = None
    executed_at_epoch_ms: int | None = None


class HardeningReport(BaseModel):
    """Pipeline output: everything that was done to one target path."""

    model_config = {"validate_assignment": True}

    target: str
    started_epoch_ms: int
    finished_epoch_ms: int
    strategies: list[str]
    events: list[HardeningEvent]
    decisions: list[Decision] = Field(default_factory=list)
    success: bool = True
    error: str | None = None

    @property
    def _failed_writes(self) -> set[str]:
        """Artifacts whose write-back failed: strategy events describe work
        that never reached disk, so they must not count as applied/modified."""
        return {
            e.artifact_path
            for e in self.events
            if e.detail.get("failed_after_sha256") is not None
        }

    @property
    def applied_events(self) -> list[HardeningEvent]:
        # A skipped or failed strategy writes no bytes, so it carries no
        # after-hash; only events with one describe work that was done —
        # and an after-hash is only evidence when the write-back succeeded.
        return [
            e
            for e in self.events
            if e.phase != DefensePhase.AUDIT
            and e.after_sha256 is not None
            and e.artifact_path not in self._failed_writes
        ]

    @property
    def modified_artifacts(self) -> list[str]:
        return sorted(
            {
                e.artifact_path
                for e in self.events
                if e.after_sha256 is not None
                and e.after_sha256 != e.before_sha256
                and e.artifact_path not in self._failed_writes
            }
        )
