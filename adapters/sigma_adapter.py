"""Internal hardening rules -> Sigma rule YAML, both directions.

Groups :class:`core.models.HardeningEvent` records into typed
:class:`UmbraRule` objects, emits canonical Sigma documents via ``pyyaml``,
and parses those documents back into the same typed model so rules can be
regenerated, diffed, and validated without a lossy dict hop.

# Concept inspired by: sigma-cli / pySigma — Sigma rule emission.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator

from core.models import HardeningEvent

__all__ = ["SigmaAdapter", "UmbraRule"]

SigmaStatus = Literal["stable", "test", "experimental"]
SigmaLevel = Literal["informational", "low", "medium", "high", "critical"]

_UMBRA_SIGMA_REFERENCES: tuple[str, ...] = ("https://umbra-sentry.invalid/sigma",)
_UMBRA_RULE_NAMESPACE = uuid.NAMESPACE_URL


class UmbraRule(BaseModel):
    """Typed internal Sigma rule before/after YAML serialization."""

    model_config = {"validate_assignment": True}

    rule_id: str
    title: str
    description: str
    status: SigmaStatus = "experimental"
    level: SigmaLevel = "medium"
    logsource_category: str = "process_creation"
    logsource_product: str = "windows"
    selection_field: str
    selection_values: list[str]
    condition: str = "selection"
    tags: list[str] = Field(default_factory=list)
    falsepositives: list[str] = Field(default_factory=list)
    date: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}$")

    @field_validator("rule_id", mode="before")
    @classmethod
    def _normalize_rule_id(cls, value: Any) -> str:
        """Accept a UUID object or string and store the canonical UUID text."""
        try:
            return str(uuid.UUID(str(value)))
        except (AttributeError, TypeError, ValueError) as exc:
            raise ValueError("rule_id must be a valid UUID string") from exc


class SigmaAdapter:
    """Emit and re-parse Sigma rules generated from hardening events."""

    @staticmethod
    def rule_id_for(strategy: str, artifact_name: str) -> str:
        """Deterministic UUID5 for a (strategy, artifact) pair.

        Regenerating rules from the same events therefore yields the same id,
        which keeps SIEM deduplication stable across hardening runs.
        """
        name = f"umbra:{strategy}:{artifact_name}"
        return str(uuid.uuid5(_UMBRA_RULE_NAMESPACE, name))

    def from_artifact_events(self, events: list[HardeningEvent]) -> list[UmbraRule]:
        """Group events by ``(strategy, artifact_name)`` into one rule each."""
        groups: dict[tuple[str, str], list[HardeningEvent]] = {}
        for event in events:
            groups.setdefault((event.strategy, event.artifact_name), []).append(event)

        rules: list[UmbraRule] = []
        for (strategy, artifact_name), group in groups.items():
            event_ids = list(dict.fromkeys(event.event_id for event in group))
            phases = sorted({event.phase.value for event in group})
            earliest_ms = min(event.ts_epoch_ms for event in group)
            rule_date = datetime.fromtimestamp(earliest_ms / 1000, tz=UTC).strftime("%Y-%m-%d")
            rules.append(
                UmbraRule(
                    rule_id=self.rule_id_for(strategy, artifact_name),
                    title=f"Umbra Sentry: {strategy} activity on {artifact_name}",
                    description=(
                        f"Detects {strategy} activity on {artifact_name} observed by "
                        f"Umbra Sentry across {len(group)} hardening event(s): "
                        f"{', '.join(event_ids)}."
                    ),
                    date=rule_date,
                    selection_field="umbra_event_id",
                    selection_values=event_ids,
                    tags=[
                        "umbra-sentry",
                        f"strategy.{strategy}",
                        *[f"phase.{phase}" for phase in phases],
                    ],
                )
            )
        return rules

    def to_yaml(self, rule: UmbraRule) -> str:
        """Render ``rule`` as a canonical Sigma YAML document.

        Field order is fixed for stable diffs; values are emitted in block
        style (``default_flow_style=False``) with keys unsorted.
        """
        document: dict[str, Any] = {
            "title": rule.title,
            "id": rule.rule_id,
            "status": rule.status,
            "description": rule.description,
            "date": rule.date,
            "logsource": {
                "category": rule.logsource_category,
                "product": rule.logsource_product,
            },
            "detection": {
                "selection": {rule.selection_field: list(rule.selection_values)},
                "condition": rule.condition,
            },
            "tags": list(rule.tags),
            "falsepositives": list(rule.falsepositives),
            "level": rule.level,
            "references": list(_UMBRA_SIGMA_REFERENCES),
        }
        return yaml.safe_dump(
            document,
            sort_keys=False,
            default_flow_style=False,
            allow_unicode=True,
            width=4096,
        )

    def from_yaml(self, text: str) -> UmbraRule:
        """Parse a Sigma YAML document back into a typed :class:`UmbraRule`."""
        document = yaml.safe_load(text)
        if not isinstance(document, dict):
            raise TypeError("Sigma rule YAML must be a mapping")

        logsource = document.get("logsource") or {}
        if not isinstance(logsource, dict):
            raise TypeError("logsource must be a mapping")
        detection = document.get("detection") or {}
        if not isinstance(detection, dict):
            raise TypeError("detection must be a mapping")

        selection = detection.get("selection")
        if not isinstance(selection, dict):
            candidates = [
                value
                for key, value in detection.items()
                if key != "condition" and isinstance(value, dict)
            ]
            selection = candidates[0] if candidates else None
        if not isinstance(selection, dict) or not selection:
            raise ValueError("detection must contain a non-empty selection mapping")

        selection_field, raw_values = next(iter(selection.items()))
        values = raw_values if isinstance(raw_values, list) else [raw_values]

        return UmbraRule(
            rule_id=str(document["id"]),
            title=str(document["title"]),
            description=str(document.get("description", "")),
            status=document.get("status", "experimental"),
            level=document.get("level", "medium"),
            logsource_category=str(logsource.get("category", "process_creation")),
            logsource_product=str(logsource.get("product", "windows")),
            selection_field=str(selection_field),
            selection_values=[str(value) for value in values],
            condition=str(detection.get("condition", "selection")),
            tags=[str(tag) for tag in document.get("tags") or []],
            falsepositives=[str(fp) for fp in document.get("falsepositives") or []],
            date=str(document["date"]),
        )

    def round_trip(self, rule: UmbraRule) -> bool:
        """True when ``to_yaml`` -> ``from_yaml`` reproduces ``rule`` exactly."""
        try:
            return self.from_yaml(self.to_yaml(rule)) == rule
        except (KeyError, TypeError, ValueError, yaml.YAMLError):
            return False
