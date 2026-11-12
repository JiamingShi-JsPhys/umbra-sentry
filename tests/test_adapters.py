"""Tests for the OCSF and Sigma adapters (typed IR -> industry formats)."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from adapters.ocsf_adapter import OcsfAdapter, OcsfDetectionFinding
from adapters.sigma_adapter import SigmaAdapter, UmbraRule
from core.models import (
    ActivityKind,
    Decision,
    DecisionAction,
    DefensePhase,
    EventSeverity,
    HardeningEvent,
    HardeningReport,
)

FIXED_TS = 1_700_000_000_000  # 2023-11-14T22:13:20Z
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64


def _event(**overrides: Any) -> HardeningEvent:
    """Build a deterministic poison-phase event, overridable per test."""
    base: dict[str, Any] = {
        "event_id": "poison:canary:0001",
        "phase": DefensePhase.POISON,
        "activity": ActivityKind.MODIFY,
        "severity": EventSeverity.HIGH,
        "artifact_path": "dist/app.bin",
        "strategy": "poison-canary",
        "message": "Injected canary marker into app.bin",
        "detail": {"confidence": 0.9},
        "before_sha256": SHA_A,
        "after_sha256": SHA_B,
        "ts_epoch_ms": FIXED_TS,
    }
    base.update(overrides)
    return HardeningEvent(**base)


def _build_events() -> list[HardeningEvent]:
    """Four events: three (strategy, artifact) groups, one duplicated group."""
    return [
        _event(
            event_id="audit:scan:0001",
            phase=DefensePhase.AUDIT,
            activity=ActivityKind.SCAN,
            severity=EventSeverity.INFO,
            strategy="audit-surface",
            message="Scanned app.bin for exposed symbols",
            detail={},
            before_sha256=None,
            after_sha256=None,
        ),
        _event(),
        _event(
            event_id="poison:canary:0002",
            activity=ActivityKind.MODIFY,
            severity=EventSeverity.MEDIUM,
            message="Verified canary marker survives repack",
            detail={"confidence": 0.5},
            before_sha256=SHA_B,
            after_sha256=SHA_C,
        ),
        _event(
            event_id="response:block:0009",
            phase=DefensePhase.RESPONSE,
            activity=ActivityKind.BLOCK,
            severity=EventSeverity.FATAL,
            artifact_path="dist/keys.json",
            strategy="response-block",
            message="Blocked rebuild because canary reverted",
            detail={"confidence": 0.4},
            before_sha256=SHA_D,
            after_sha256=None,
        ),
    ]


@pytest.fixture()
def events() -> list[HardeningEvent]:
    return _build_events()


@pytest.fixture()
def report(events: list[HardeningEvent]) -> HardeningReport:
    decision = Decision(
        decision_id="dec:quarantine:0001",
        artifact_path="dist/app.bin",
        action=DecisionAction.QUARANTINE,
        reason="Canary marker indicates a reverted artifact",
        triggered_by="poison:canary:0001",
        confidence=0.9,
        requires_human_approval=True,
        approved_by="reviewer",
        executed_at_epoch_ms=FIXED_TS + 500,
    )
    return HardeningReport(
        target="dist/app.bin",
        started_epoch_ms=FIXED_TS,
        finished_epoch_ms=FIXED_TS + 1_000,
        strategies=["audit-surface", "poison-canary", "response-block"],
        events=events,
        decisions=[decision],
        success=True,
    )


def _make_rule(**overrides: Any) -> UmbraRule:
    base: dict[str, Any] = {
        "rule_id": str(uuid.uuid4()),
        "title": "Test rule",
        "description": "Test description",
        "selection_field": "umbra_event_id",
        "selection_values": ["evt:1"],
        "date": "2023-11-14",
    }
    base.update(overrides)
    return UmbraRule(**base)


# ---------------------------------------------------------------------------
# OCSF projection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("severity", "expected_id"),
    [
        (EventSeverity.UNKNOWN, 0),
        (EventSeverity.INFO, 1),
        (EventSeverity.LOW, 2),
        (EventSeverity.MEDIUM, 3),
        (EventSeverity.HIGH, 4),
        (EventSeverity.CRITICAL, 5),
        (EventSeverity.FATAL, 6),
    ],
)
def test_ocsf_severity_mapping(severity: EventSeverity, expected_id: int) -> None:
    finding = OcsfAdapter().to_finding(_event(severity=severity))
    assert finding.severity_id == expected_id


@pytest.mark.parametrize(
    ("activity", "expected_id", "expected_name"),
    [
        (ActivityKind.CREATE, 1, "Create"),
        (ActivityKind.MODIFY, 2, "Update"),
        (ActivityKind.READ, 99, "Read"),
        (ActivityKind.SCAN, 99, "Scan"),
        (ActivityKind.ALERT, 99, "Alert"),
        (ActivityKind.BLOCK, 99, "Block"),
    ],
)
def test_ocsf_activity_mapping(
    activity: ActivityKind, expected_id: int, expected_name: str
) -> None:
    finding = OcsfAdapter().to_finding(_event(activity=activity))
    assert finding.activity_id == expected_id
    assert finding.activity_name == expected_name


def test_ocsf_type_uid_for_modify_is_200402() -> None:
    finding = OcsfAdapter().to_finding(_event(activity=ActivityKind.MODIFY))
    assert finding.type_uid == 200402
    assert finding.class_uid == 2004
    assert finding.class_name == "Detection Finding"
    assert finding.category_uid == 2
    assert finding.category_name == "Findings"


def test_ocsf_time_is_utc_datetime() -> None:
    finding = OcsfAdapter().to_finding(_event())
    expected = datetime.fromtimestamp(FIXED_TS / 1000, tz=UTC)
    assert finding.time == expected
    assert finding.finding_info.created == expected
    assert finding.time.tzinfo is not None


def test_ocsf_finding_info_and_labels() -> None:
    event = _event()
    finding = OcsfAdapter().to_finding(event)
    assert finding.finding_info.uid == event.event_id
    assert finding.finding_info.title == f"[poison-canary] {event.message}"
    assert finding.metadata.version == "1.5.0"
    assert finding.metadata.product.name == "umbra-sentry"
    assert finding.metadata.product.vendor_name == "Umbra Sentry"
    assert f"raw_uid:{event.event_id}" in finding.metadata.labels


@pytest.mark.parametrize(
    ("phase", "expected_id", "expected_status"),
    [
        (DefensePhase.AUDIT, 1, "New"),
        (DefensePhase.POISON, 1, "New"),
        (DefensePhase.VERIFY, 4, "Resolved"),
        (DefensePhase.RESPONSE, 2, "In Progress"),
    ],
)
def test_ocsf_status_mapping(
    phase: DefensePhase, expected_id: int, expected_status: str
) -> None:
    finding = OcsfAdapter().to_finding(_event(phase=phase))
    assert finding.status_id == expected_id
    assert finding.status == expected_status


def test_ocsf_evidences_drop_missing_hashes() -> None:
    finding = OcsfAdapter().to_finding(
        _event(before_sha256=None, after_sha256=None)
    )
    assert finding.evidences == [{"file": "dist/app.bin"}]

    full = OcsfAdapter().to_finding(_event())
    assert full.evidences[0]["sha256_before"] == SHA_A
    assert full.evidences[0]["sha256_after"] == SHA_B


def test_ocsf_confidence_from_detail() -> None:
    high = OcsfAdapter().to_finding(_event(detail={"confidence": 0.9}))
    assert high.confidence_score == 90
    assert high.confidence_id == 3

    none = OcsfAdapter().to_finding(_event(detail={}))
    assert none.confidence_score is None
    assert none.confidence_id is None


def test_ocsf_to_finding_json_validates_and_is_json_serializable() -> None:
    event = _event()
    payload = OcsfAdapter().to_finding_json(event)
    json.dumps(payload)  # must not raise
    finding = OcsfDetectionFinding.model_validate(payload)
    assert finding.finding_info.uid == event.event_id
    assert finding.severity_id == EventSeverity.HIGH.ocsf_id
    assert payload["type_uid"] == 200402


def test_ocsf_json_full_round_trip() -> None:
    adapter = OcsfAdapter()
    payload = adapter.to_finding_json(_event())
    restored = OcsfDetectionFinding.model_validate(payload)
    assert restored.model_dump(mode="json", exclude_none=True) == payload


def test_ocsf_report_to_batch_one_finding_per_event(report: HardeningReport) -> None:
    batch = OcsfAdapter().report_to_batch(report)
    assert len(batch) == len(report.events)
    by_uid = {item["finding_info"]["uid"]: item for item in batch}
    assert set(by_uid) == {event.event_id for event in report.events}

    resources = by_uid["poison:canary:0001"]["resources"]
    assert {
        "action": "quarantine",
        "requires_human_approval": True,
        "approved_by": "reviewer",
    } in resources
    assert by_uid["audit:scan:0001"]["resources"] == []


def test_ocsf_batch_to_findings_round_trips(report: HardeningReport) -> None:
    adapter = OcsfAdapter()
    batch = adapter.report_to_batch(report)
    findings = adapter.batch_to_findings(batch)
    assert len(findings) == len(batch)
    assert [f.finding_info.uid for f in findings] == [
        event.event_id for event in report.events
    ]
    for payload, finding in zip(batch, findings, strict=True):
        assert finding.type_uid == 2004 * 100 + payload["activity_id"]
        assert finding.severity_id == payload["severity_id"]
        assert finding.activity_name == payload["activity_name"]


def test_ocsf_invalid_severity_raises_validation_error() -> None:
    payload = OcsfAdapter().to_finding_json(_event())
    with pytest.raises(ValidationError):
        OcsfDetectionFinding.model_validate({**payload, "severity_id": 9})


def test_ocsf_invalid_activity_raises_validation_error() -> None:
    payload = OcsfAdapter().to_finding_json(_event())
    with pytest.raises(ValidationError):
        OcsfDetectionFinding.model_validate(
            {**payload, "activity_id": 7, "type_uid": 200407}
        )


# ---------------------------------------------------------------------------
# Sigma rule emission
# ---------------------------------------------------------------------------


def test_sigma_groups_by_strategy_and_artifact(events: list[HardeningEvent]) -> None:
    rules = SigmaAdapter().from_artifact_events(events)
    assert len(rules) == 3
    titles = {rule.title for rule in rules}
    assert "Umbra Sentry: poison-canary activity on app.bin" in titles
    assert "Umbra Sentry: audit-surface activity on app.bin" in titles
    assert "Umbra Sentry: response-block activity on keys.json" in titles

    poison = next(rule for rule in rules if "poison-canary" in rule.title)
    assert poison.selection_field == "umbra_event_id"
    assert poison.selection_values == ["poison:canary:0001", "poison:canary:0002"]
    assert "umbra-sentry" in poison.tags
    assert "phase.poison" in poison.tags


def test_sigma_rule_ids_are_deterministic(events: list[HardeningEvent]) -> None:
    adapter = SigmaAdapter()
    first = adapter.from_artifact_events(events)
    second = adapter.from_artifact_events(events)
    assert [rule.rule_id for rule in first] == [rule.rule_id for rule in second]

    expected = str(uuid.uuid5(uuid.NAMESPACE_URL, "umbra:poison-canary:app.bin"))
    poison = next(rule for rule in first if "poison-canary" in rule.title)
    assert poison.rule_id == expected
    assert uuid.UUID(poison.rule_id)


def test_sigma_to_yaml_has_required_fields(events: list[HardeningEvent]) -> None:
    adapter = SigmaAdapter()
    rule = adapter.from_artifact_events(events)[0]
    document = yaml.safe_load(adapter.to_yaml(rule))

    assert document["title"] == rule.title
    uuid.UUID(document["id"])  # valid UUID string
    assert document["status"] in {"stable", "test", "experimental"}
    assert document["description"]
    assert document["logsource"]["category"]
    assert document["logsource"]["product"]
    assert document["detection"]["condition"] == "selection"
    assert document["detection"]["selection"][rule.selection_field] == (
        rule.selection_values
    )
    assert document["level"] in {
        "informational",
        "low",
        "medium",
        "high",
        "critical",
    }
    assert document["references"] == ["https://umbra-sentry.invalid/sigma"]


def test_sigma_yaml_field_order(events: list[HardeningEvent]) -> None:
    adapter = SigmaAdapter()
    text = adapter.to_yaml(adapter.from_artifact_events(events)[0])
    top_level = [
        line.split(":", 1)[0]
        for line in text.splitlines()
        if line and not line.startswith((" ", "-"))
    ]
    assert top_level == [
        "title",
        "id",
        "status",
        "description",
        "date",
        "logsource",
        "detection",
        "tags",
        "falsepositives",
        "level",
        "references",
    ]


def test_sigma_round_trip_all_generated_rules(events: list[HardeningEvent]) -> None:
    adapter = SigmaAdapter()
    rules = adapter.from_artifact_events(events)
    assert rules
    for rule in rules:
        assert adapter.round_trip(rule) is True


def test_sigma_from_yaml_reconstructs_typed_rule(events: list[HardeningEvent]) -> None:
    adapter = SigmaAdapter()
    rule = adapter.from_artifact_events(events)[1]
    restored = adapter.from_yaml(adapter.to_yaml(rule))
    assert isinstance(restored, UmbraRule)
    assert restored == rule
    assert restored.date == "2023-11-14"


def test_sigma_invalid_rule_id_rejected() -> None:
    with pytest.raises(ValidationError):
        _make_rule(rule_id="not-a-uuid")


def test_sigma_invalid_status_rejected() -> None:
    with pytest.raises(ValidationError):
        _make_rule(status="bogus")


def test_sigma_invalid_date_rejected() -> None:
    with pytest.raises(ValidationError):
        _make_rule(date="14/11/2023")
