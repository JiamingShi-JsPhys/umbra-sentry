"""Regression tests for the defects recorded in the umbra-sentry audit.

Each class pins one finding so it cannot silently come back.

* ``TestTextTrailers`` / ``TestJsonTrailers`` — idempotence markers must be
  *structural*.  A bare ``umbra:*`` marker pasted anywhere in an artifact is
  not evidence that hardening ran, and a strategy's own trailer must keep
  working after a later strategy appends its block behind it.
* ``TestChainIdempotence`` — a second pipeline pass over an already hardened
  artifact must be a no-op.  A strictly tail-anchored check failed this
  because the chain (poison -> exhaust -> hallucinate) leaves the earlier
  trailer buried, and a whole-document JSON checksum failed it because the
  later strategy's sibling keys changed the digest.
* ``TestRngIndependence`` — one RNG stream per artifact.  With a shared
  stream, hardening file A shifted every draw made for file B, so the bytes
  written to B depended on which siblings happened to be in the tree.
* OCSF confidence normalization — NaN / inf / bools / strings / containers
  must degrade to "no confidence" instead of poisoning the finding JSON.
* Human approval — approved decisions really execute, denied ones really
  don't, and a decision cannot be resolved twice.
* CLI wiring — every strategy is registered and a clean target exits 0.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import random
from pathlib import Path
from typing import Any

import pytest

from adapters.ocsf_adapter import OcsfAdapter
from cli import _build_pipeline, main
from core.models import (
    ActivityKind,
    Decision,
    DecisionAction,
    DefensePhase,
    DefenseVerdict,
    EventSeverity,
    HardeningEvent,
)
from core.pipeline import HardeningPipeline
from defense.base import StrategyContext
from defense.exhaust import BudgetExhaustStrategy
from defense.hallucinate import ShadowLogicStrategy
from defense.markers import (
    fnv1a64,
    has_json_trailer,
    has_trailer,
    json_trailer_value,
    trailer_line,
)
from defense.native_strategies import NativeExhaustStrategy, NativePoisonStrategy
from defense.poison import CanaryPoisonStrategy
from gates.human_approval import ApprovalState, HumanApprovalGate
from response.bouncer import Bouncer

PY_SOURCE = "def greet(name):\n    return f'hi {name}'\n"
JSON_SOURCE = json.dumps({"name": "demo", "version": 1}, indent=2) + "\n"


def make_ctx(*, seed: int = 1337, intensity: str = "balanced") -> StrategyContext:
    """A strategy context carrying its own RNG, as the pipeline builds it."""
    return StrategyContext(seed=seed, intensity=intensity, rng=random.Random(seed))


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
        "ts_epoch_ms": 1_700_000_000_000,
    }
    base.update(overrides)
    return HardeningEvent(**base)


class TestTextTrailers:
    """``has_trailer`` accepts only a checksum-validated trailer line."""

    def test_trailer_at_eof_is_recognised(self) -> None:
        payload = b"# block\n"
        text = payload.decode() + trailer_line("umbra:test", payload)
        assert has_trailer(text, "umbra:test") is True

    def test_bare_marker_is_not_evidence(self) -> None:
        assert has_trailer("# umbra:test\n", "umbra:test") is False

    def test_forged_tag_is_rejected(self) -> None:
        text = "# block\n# umbra:test:8:0000000000000000\n"
        assert has_trailer(text, "umbra:test") is False

    def test_edit_of_covered_bytes_invalidates_the_trailer(self) -> None:
        tag = f"{fnv1a64(b'# block\n'):016x}"
        # Same byte length, different bytes: only the checksum can tell.
        text = f"# blocc\n# umbra:test:8:{tag}\n"
        assert has_trailer(text, "umbra:test") is False

    def test_trailer_survives_a_block_appended_after_it(self) -> None:
        first, second = b"# first\n", b"# second\n"
        text = (
            first.decode()
            + trailer_line("umbra:one", first)
            + second.decode()
            + trailer_line("umbra:two", second)
        )
        assert has_trailer(text, "umbra:one") is True
        assert has_trailer(text, "umbra:two") is True

    def test_multibyte_payload_is_measured_in_bytes(self) -> None:
        payload = "# 中文注释\n".encode()
        assert len(payload) > len(payload.decode("utf-8"))
        text = payload.decode("utf-8") + trailer_line("umbra:test", payload)
        assert has_trailer(text, "umbra:test") is True

    def test_empty_payload_is_refused(self) -> None:
        assert has_trailer("# umbra:test:0:0000000000000000\n", "umbra:test") is False

    def test_newline_in_marker_is_refused(self) -> None:
        with pytest.raises(ValueError):
            trailer_line("umbra:\ntest", b"# block\n")
        with pytest.raises(ValueError):
            has_trailer("# block\n", "umbra:\ntest")

    def test_html_comment_wrapper_round_trips(self) -> None:
        payload = b"<!-- umbra:canary honeypot markers -->\n"
        text = payload.decode("utf-8") + trailer_line(
            "umbra:test", payload, prefix="<!-- ", suffix=" -->"
        )
        assert has_trailer(text, "umbra:test") is True


class TestJsonTrailers:
    """A JSON trailer hashes this strategy's payload, not the whole document."""

    _KEY = "_umbra_canary"
    _TRAILER = "_umbra_canary_trailer"

    def _signed(self) -> dict[str, Any]:
        document: dict[str, Any] = {
            self._KEY: ["umbra:canary:deadbeef: API_TOKEN=not-a-real-token"]
        }
        document[self._TRAILER] = json_trailer_value(
            "umbra:canary", document, key=self._TRAILER, data_key=self._KEY
        )
        return document

    def test_trailer_survives_a_sibling_key(self) -> None:
        document = self._signed()
        # What the exhaust strategy adds on a later pass.
        document["_umbra_padding"] = ["x" * 40]
        document["_umbra_padding_trailer"] = "umbra:exhaust:1:0000000000000000"
        assert has_json_trailer(
            document, "umbra:canary", key=self._TRAILER, data_key=self._KEY
        )

    def test_own_payload_change_invalidates_the_trailer(self) -> None:
        document = self._signed()
        document[self._KEY].append("umbra:canary:cafebabe: BILLING_KEY=x")
        assert not has_json_trailer(
            document, "umbra:canary", key=self._TRAILER, data_key=self._KEY
        )

    def test_bare_key_is_not_evidence(self) -> None:
        document = {self._KEY: ["x"]}
        assert not has_json_trailer(
            document, "umbra:canary", key=self._TRAILER, data_key=self._KEY
        )


class TestChainIdempotence:
    """A second hardening pass over an already hardened artifact is a no-op."""

    def test_poison_is_idempotent_on_its_own(self, tmp_path: Path) -> None:
        path = tmp_path / "mod.py"
        strategy = CanaryPoisonStrategy()
        first = strategy.apply(path, PY_SOURCE.encode(), make_ctx())
        assert first.verdict is DefenseVerdict.APPLIED
        second = strategy.apply(path, first.data, make_ctx())  # type: ignore[arg-type]
        assert second.verdict is DefenseVerdict.SKIPPED
        assert second.data == first.data

    def test_text_chain_reaches_a_fixed_point(self, tmp_path: Path) -> None:
        path = tmp_path / "mod.py"
        chain = [
            CanaryPoisonStrategy(),
            BudgetExhaustStrategy(),
            ShadowLogicStrategy(),
        ]
        data = PY_SOURCE.encode()
        for strategy in chain:
            result = strategy.apply(path, data, make_ctx())
            assert result.verdict is DefenseVerdict.APPLIED, strategy.name
            assert result.data is not None
            data = result.data

        hardened = data
        for strategy in chain:
            result = strategy.apply(path, hardened, make_ctx())
            assert result.verdict is DefenseVerdict.SKIPPED, strategy.name
            assert result.data == hardened

        # The artifact must still be importable Python after three appends.
        compile(hardened.decode("utf-8"), "mod.py", "exec")

    def test_json_chain_is_idempotent(self, tmp_path: Path) -> None:
        path = tmp_path / "config.json"
        poison, exhaust = CanaryPoisonStrategy(), BudgetExhaustStrategy()
        data = JSON_SOURCE.encode()
        for strategy in (poison, exhaust):
            result = strategy.apply(path, data, make_ctx())
            assert result.verdict is DefenseVerdict.APPLIED, strategy.name
            assert result.data is not None
            data = result.data

        hardened = data
        for strategy in (poison, exhaust):
            result = strategy.apply(path, hardened, make_ctx())
            assert result.verdict is DefenseVerdict.SKIPPED, strategy.name
            assert result.data == hardened

        payload = json.loads(hardened.decode("utf-8"))
        assert "_umbra_canary" in payload
        assert "_umbra_padding" in payload

    def test_author_pasted_marker_does_not_suppress_hardening(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "mod.py"
        data = (PY_SOURCE + "# umbra:canary honeypot markers\n").encode()
        result = CanaryPoisonStrategy().apply(path, data, make_ctx())
        assert result.verdict is DefenseVerdict.APPLIED

    def test_pasted_forged_trailer_does_not_suppress_hardening(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "mod.py"
        data = (PY_SOURCE + "# umbra:canary:12:deadbeefdeadbeef\n").encode()
        result = CanaryPoisonStrategy().apply(path, data, make_ctx())
        assert result.verdict is DefenseVerdict.APPLIED


class TestRngIndependence:
    """Artifact A's output must not depend on whether sibling B exists."""

    def test_sibling_artifact_does_not_shift_the_output(self, tmp_path: Path) -> None:
        alone = tmp_path / "alone"
        pair = tmp_path / "pair"
        alone.mkdir()
        pair.mkdir()
        (alone / "m_target.py").write_text(PY_SOURCE, encoding="utf-8")
        (pair / "a_sibling.py").write_text(PY_SOURCE, encoding="utf-8")
        (pair / "m_target.py").write_text(PY_SOURCE, encoding="utf-8")

        def harden(target: Path) -> None:
            pipeline = HardeningPipeline(
                [
                    CanaryPoisonStrategy(),
                    BudgetExhaustStrategy(),
                    ShadowLogicStrategy(),
                ],
                seed=7,
            )
            pipeline.run(target)

        harden(alone)
        harden(pair)

        # ``a_sibling.py`` sorts before ``m_target.py``: with one shared RNG
        # its draws would shift every value written into the target.
        assert (alone / "m_target.py").read_bytes() == (
            pair / "m_target.py"
        ).read_bytes()


class TestOcsfConfidence:
    """Confidence normalization must be total — no NaN/inf reaches the finding."""

    @pytest.mark.parametrize(
        "raw",
        [
            None,
            True,
            False,
            float("nan"),
            float("inf"),
            float("-inf"),
            "0.9",
            [0.9],
            {"value": 0.9},
        ],
    )
    def test_non_numeric_or_non_finite_confidence_is_dropped(self, raw: Any) -> None:
        event = _event(detail={"confidence": raw})
        assert OcsfAdapter._confidence_score(event) is None
        assert OcsfAdapter._confidence_id(None) is None

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            (0.9, 90),
            (90, 90),
            (1.0, 99),
            (-5, 0),
            (10**9, 99),
            (0.01, 1),
            (0.0, 0),
        ],
    )
    def test_confidence_is_normalised_and_clamped(
        self, raw: float, expected: int
    ) -> None:
        assert OcsfAdapter._confidence_score(_event(detail={"confidence": raw})) == expected

    @pytest.mark.parametrize(
        ("score", "expected"),
        [
            (90, 3),
            (80, 3),
            (79, 2),
            (55, 2),
            (50, 2),
            (49, 1),
            (1, 1),
            (0, 0),
            (None, None),
        ],
    )
    def test_confidence_id_bands(self, score: int | None, expected: int | None) -> None:
        assert OcsfAdapter._confidence_id(score) == expected

    def test_finding_json_stays_serialisable_with_nan_input(self) -> None:
        adapter = OcsfAdapter()
        event = _event(detail={"confidence": math.nan})
        finding = adapter.to_finding(event)
        assert finding.confidence_score is None
        assert finding.confidence_id is None
        # ``allow_nan=False`` is the strict encoder: NaN would raise here.
        json.dumps(adapter.to_finding_json(event), allow_nan=False)


class TestHumanApproval:
    """The gate resolves decisions and the bouncer executes only approvals."""

    def _decision(self, **overrides: Any) -> Decision:
        base: dict[str, Any] = {
            "decision_id": "dec-1",
            "artifact_path": "dist/app.bin",
            "action": DecisionAction.QUARANTINE,
            "reason": "critical event ev-1",
            "triggered_by": "ev-1",
            "confidence": 0.9,
            "requires_human_approval": True,
        }
        base.update(overrides)
        return Decision(**base)

    def test_auto_approval_when_no_human_is_required(self) -> None:
        gate = HumanApprovalGate()
        request = asyncio.run(
            gate.request(self._decision(requires_human_approval=False))
        )
        assert request.state is ApprovalState.APPROVED
        assert request.resolved_by == "auto"

    def test_approved_decision_executes_exactly_once(self) -> None:
        executed: list[str] = []

        async def approver(_request: Any) -> bool:
            return True

        bouncer = Bouncer(HumanApprovalGate(approver))
        bouncer.register_handler(
            DecisionAction.QUARANTINE, lambda d: executed.append(d.decision_id)
        )
        decision = self._decision()

        result = asyncio.run(bouncer.handle_decision(decision))
        again = asyncio.run(bouncer.handle_decision(result))

        assert executed == ["dec-1"]
        assert bouncer.summary()["executed"] == ["dec-1"]
        assert result.executed_at_epoch_ms is not None
        assert again.decision_id == "dec-1"

    def test_denied_decision_is_never_executed(self) -> None:
        executed: list[str] = []

        async def approver(_request: Any) -> bool:
            return False

        bouncer = Bouncer(HumanApprovalGate(approver))
        bouncer.register_handler(
            DecisionAction.QUARANTINE, lambda d: executed.append(d.decision_id)
        )
        result = asyncio.run(bouncer.handle_decision(self._decision(decision_id="dec-2")))

        assert executed == []
        assert bouncer.summary()["rejected"] == ["dec-2"]
        assert result.executed_at_epoch_ms is None

    def test_resolving_an_already_resolved_decision_is_refused(self) -> None:
        gate = HumanApprovalGate()
        asyncio.run(gate.request(self._decision(decision_id="dec-3", requires_human_approval=False)))
        with pytest.raises(RuntimeError):
            gate.approve("dec-3", "operator")


class TestCliWiring:
    """The CLI must register every strategy and exit 0 on a clean target."""

    def test_pipeline_wires_every_strategy(self) -> None:
        args = argparse.Namespace(
            seed=0, intensity="balanced", max_files=8, quarantine_dir=None
        )
        pipeline = _build_pipeline(args)
        # A set, not a list: the pipeline sorts stably by phase and the native
        # strategies share phases with the text ones, so order interleaves.
        assert {type(strategy) for strategy in pipeline.strategies} == {
            CanaryPoisonStrategy,
            BudgetExhaustStrategy,
            ShadowLogicStrategy,
            NativePoisonStrategy,
            NativeExhaustStrategy,
        }

    def test_cli_runs_clean_on_a_python_target(self, tmp_path: Path) -> None:
        target = tmp_path / "app.py"
        target.write_text(PY_SOURCE, encoding="utf-8")
        out = tmp_path / "report.json"

        assert main([str(target), "--out", str(out), "--seed", "3"]) == 0

        payload = json.loads(out.read_text(encoding="utf-8"))
        assert payload["success"] is True
        assert payload["events"]
