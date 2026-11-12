"""OCSF v1.5.0 detection-finding projection for umbra-sentry.

Maps the internal :class:`core.models.HardeningEvent` IR onto a strong-typed
subset of the OCSF ``Detection Finding`` class (``class_uid`` 2004, category
``Findings``) and converts whole :class:`core.models.HardeningReport` batches
back and forth without ever handing a bare dict across a module boundary.

# Concept inspired by: py-ocsf-models (Prowler) — typed OCSF Detection Finding projection.
"""

from __future__ import annotations

import math
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field, model_validator

from core.models import ActivityKind, DefensePhase, HardeningEvent, HardeningReport

__all__ = [
    "OCSF_CATEGORY_NAME_FINDINGS",
    "OCSF_CATEGORY_UID_FINDINGS",
    "OCSF_CLASS_NAME_DETECTION_FINDING",
    "OCSF_CLASS_UID_DETECTION_FINDING",
    "OcsfAdapter",
    "OcsfDetectionFinding",
    "OcsfFindingInfo",
    "OcsfMetadata",
    "OcsfProduct",
]

OCSF_CLASS_UID_DETECTION_FINDING: int = 2004
OCSF_CATEGORY_UID_FINDINGS: int = 2
OCSF_CLASS_NAME_DETECTION_FINDING: str = "Detection Finding"
OCSF_CATEGORY_NAME_FINDINGS: str = "Findings"

OCSF_PRODUCT_NAME: str = "umbra-sentry"
OCSF_PRODUCT_VENDOR: str = "Umbra Sentry"
OCSF_PRODUCT_VERSION: str = "1.0.0"
OCSF_METADATA_VERSION: str = "1.5.0"

_ALLOWED_ACTIVITY_IDS: frozenset[int] = frozenset({0, 1, 2, 3, 99})

# Internal ActivityKind -> (OCSF activity_id, activity_name).  Internal verbs
# without a first-class OCSF Detection Finding activity map to 99 ("Other");
# their real name is preserved in activity_name.
_ACTIVITY_MAP: dict[ActivityKind, tuple[int, str]] = {
    ActivityKind.CREATE: (1, "Create"),
    ActivityKind.MODIFY: (2, "Update"),
    ActivityKind.READ: (99, "Read"),
    ActivityKind.SCAN: (99, "Scan"),
    ActivityKind.ALERT: (99, "Alert"),
    ActivityKind.BLOCK: (99, "Block"),
}

# Internal DefensePhase -> (OCSF status_id, status).  Only the verify phase is
# terminal; response is in flight; everything earlier is a fresh finding.
_PHASE_STATUS: dict[DefensePhase, tuple[int, str]] = {
    DefensePhase.AUDIT: (1, "New"),
    DefensePhase.POISON: (1, "New"),
    DefensePhase.EXHAUST: (1, "New"),
    DefensePhase.HALLUCINATE: (1, "New"),
    DefensePhase.VERIFY: (4, "Resolved"),
    DefensePhase.RESPONSE: (2, "In Progress"),
}


class OcsfProduct(BaseModel):
    """OCSF ``product`` object identifying the emitting tool."""

    vendor_name: str = OCSF_PRODUCT_VENDOR
    name: str
    version: str = OCSF_PRODUCT_VERSION


class OcsfMetadata(BaseModel):
    """OCSF ``metadata`` object: schema version, product, correlation labels."""

    version: str = OCSF_METADATA_VERSION
    product: OcsfProduct
    uid: str | None = None
    correlation_uid: str | None = None
    labels: list[str] = Field(default_factory=list)


class OcsfFindingInfo(BaseModel):
    """OCSF ``finding_info`` object: what was found and its stable identity."""

    title: str
    uid: str
    created: datetime | None = None
    first_seen_time: datetime | None = None


class OcsfDetectionFinding(BaseModel):
    """Typed OCSF v1.5.0 Detection Finding (``class_uid`` 2004).

    Only the fields this toolkit populates are modelled.  Required OCSF
    semantics are enforced: ``severity_id`` is 0..6, ``activity_id`` is one of
    0/1/2/3/99, and ``type_uid`` equals ``class_uid * 100 + activity_id`` (so
    200400..200499 for this class).
    """

    # OCSF-canonical field order for serialization.
    activity_id: int
    activity_name: str
    category_uid: int = OCSF_CATEGORY_UID_FINDINGS
    category_name: str = OCSF_CATEGORY_NAME_FINDINGS
    class_uid: int = OCSF_CLASS_UID_DETECTION_FINDING
    class_name: str = OCSF_CLASS_NAME_DETECTION_FINDING
    metadata: OcsfMetadata
    severity_id: int = Field(..., ge=0, le=6)
    time: datetime
    type_uid: int = Field(..., ge=0)
    finding_info: OcsfFindingInfo

    message: str | None = None
    status: str | None = None
    status_id: int | None = Field(None, ge=0)
    confidence_id: int | None = Field(None, ge=0, le=99)
    confidence_score: int | None = Field(None, ge=0, le=99)
    evidences: list[dict[str, Any]] = Field(default_factory=list)
    resources: list[dict[str, Any]] = Field(default_factory=list)
    impact: str | None = None
    risk_details: str | None = None
    unmapped: dict[str, Any] | None = None

    @model_validator(mode="after")
    def _validate_ocsf_codes(self) -> OcsfDetectionFinding:
        if self.activity_id not in _ALLOWED_ACTIVITY_IDS:
            raise ValueError(
                "activity_id must be one of "
                f"{sorted(_ALLOWED_ACTIVITY_IDS)}, got {self.activity_id}"
            )
        expected_type_uid = self.class_uid * 100 + self.activity_id
        if self.type_uid != expected_type_uid:
            raise ValueError(
                "type_uid must equal class_uid*100+activity_id "
                f"({expected_type_uid}), got {self.type_uid}"
            )
        return self


class OcsfAdapter:
    """Project internal hardening IR onto OCSF Detection Findings and back."""

    def to_finding(self, event: HardeningEvent) -> OcsfDetectionFinding:
        """Convert one :class:`HardeningEvent` into a typed OCSF finding."""
        activity_id, activity_name = _ACTIVITY_MAP[event.activity]
        status_id, status = _PHASE_STATUS[event.phase]
        event_time = datetime.fromtimestamp(event.ts_epoch_ms / 1000, tz=UTC)
        confidence_score = self._confidence_score(event)
        confidence_id = self._confidence_id(confidence_score)

        evidence: dict[str, Any] = {"file": event.artifact_path}
        if event.before_sha256 is not None:
            evidence["sha256_before"] = event.before_sha256
        if event.after_sha256 is not None:
            evidence["sha256_after"] = event.after_sha256

        return OcsfDetectionFinding(
            activity_id=activity_id,
            activity_name=activity_name,
            metadata=OcsfMetadata(
                product=OcsfProduct(name=OCSF_PRODUCT_NAME),
                uid=event.artifact_name,
                labels=[
                    f"raw_uid:{event.event_id}",
                    f"phase.{event.phase.value}",
                ],
            ),
            severity_id=event.severity.ocsf_id,
            time=event_time,
            type_uid=OCSF_CLASS_UID_DETECTION_FINDING * 100 + activity_id,
            finding_info=OcsfFindingInfo(
                title=f"[{event.strategy}] {event.message[:80]}",
                uid=event.event_id,
                created=event_time,
                first_seen_time=event_time,
            ),
            message=event.message,
            status=status,
            status_id=status_id,
            confidence_id=confidence_id,
            confidence_score=confidence_score,
            evidences=[evidence],
            unmapped={
                "event_id": event.event_id,
                "phase": event.phase.value,
                "strategy": event.strategy,
                "artifact_path": event.artifact_path,
                "activity": event.activity.value,
                "detail": event.detail,
            },
        )

    def to_finding_json(self, event: HardeningEvent) -> dict[str, Any]:
        """Serialize one event as a JSON-ready OCSF detection-finding dict."""
        return self.to_finding(event).model_dump(mode="json", exclude_none=True)

    def report_to_batch(self, report: HardeningReport) -> list[dict[str, Any]]:
        """Emit one OCSF finding per event, linking remediation decisions.

        Every decision whose ``triggered_by`` matches an event id is attached
        to that finding's ``resources`` array so downstream SIEMs see the
        remediation request alongside the detection.
        """
        decisions_by_event: dict[str, list[dict[str, Any]]] = {}
        for decision in report.decisions:
            decisions_by_event.setdefault(decision.triggered_by, []).append(
                {
                    "action": decision.action.value,
                    "requires_human_approval": decision.requires_human_approval,
                    "approved_by": decision.approved_by,
                }
            )

        batch: list[dict[str, Any]] = []
        for event in report.events:
            payload = self.to_finding_json(event)
            linked = decisions_by_event.get(event.event_id)
            if linked:
                payload.setdefault("resources", []).extend(linked)
            batch.append(payload)
        return batch

    def batch_to_findings(
        self, batch: list[dict[str, Any]]
    ) -> list[OcsfDetectionFinding]:
        """Validate raw OCSF finding dicts back into typed models (reverse)."""
        return [OcsfDetectionFinding.model_validate(item) for item in batch]

    @staticmethod
    def _confidence_score(event: HardeningEvent) -> int | None:
        """Read ``detail['confidence']`` and normalize it to an OCSF 0..99 score.

        Only real numbers are accepted.  ``bool`` is rejected explicitly (it
        subclasses ``int`` and would silently become 0 or 100), as are strings
        and every non-finite value: ``round(nan)`` raises ``ValueError`` and
        ``round(inf)`` raises ``OverflowError``, so a crafted report could
        otherwise crash the whole OCSF export.
        """
        raw = event.detail.get("confidence")
        if raw is None or isinstance(raw, bool):
            return None
        if not isinstance(raw, int | float):
            return None
        value = float(raw)
        if not math.isfinite(value):
            return None
        # Accept either a 0..1 probability or an already-percentage value.
        if value <= 1.0:
            value *= 100.0
        # ``round`` with no ndigits already returns an int.
        return max(0, min(99, round(value)))

    @staticmethod
    def _confidence_id(score: int | None) -> int | None:
        """Map an OCSF confidence score onto ``confidence_id`` (0/1/2/3)."""
        if score is None:
            return None
        if score >= 80:
            return 3
        if score >= 50:
            return 2
        if score > 0:
            return 1
        return 0
