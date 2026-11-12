"""Contract tests for the poison, exhaust and hallucinate strategies.

Each strategy is exercised against the BaseDefenseStrategy template method:
applied output validity, idempotence, seed determinism, failure isolation,
format gating, and the exhaust density ladder.
"""

from __future__ import annotations

import ast
import json
import random
from pathlib import Path

import pytest

from core.models import DefenseVerdict
from defense.base import StrategyContext
from defense.exhaust import DENSITY_BY_INTENSITY, BudgetExhaustStrategy
from defense.hallucinate import ShadowLogicStrategy
from defense.poison import CanaryPoisonStrategy

PY_SOURCE = (
    '"""Synthetic module for strategy tests."""\n'
    "\n"
    "\n"
    "def add(left: int, right: int) -> int:\n"
    '    """Add two integers."""\n'
    "    return left + right\n"
    "\n"
    "\n"
    'if __name__ == "__main__":\n'
    "    print(add(1, 2))\n"
)
JSON_SOURCE = json.dumps({"name": "demo", "version": 1}, indent=2) + "\n"
JS_SOURCE = "function add(a, b) { return a + b; }\nconsole.log(add(1, 2));\n"
TS_SOURCE = "function add(a: number, b: number): number { return a + b; }\n"
MD_SOURCE = "# Demo artifact\n\nSome documentation.\n"

SOURCES = {
    ".py": PY_SOURCE,
    ".json": JSON_SOURCE,
    ".js": JS_SOURCE,
    ".ts": TS_SOURCE,
    ".md": MD_SOURCE,
}

ALL_STRATEGIES = (CanaryPoisonStrategy, BudgetExhaustStrategy, ShadowLogicStrategy)


def make_ctx(seed: int = 1337, intensity: str = "balanced") -> StrategyContext:
    return StrategyContext(seed=seed, intensity=intensity, rng=random.Random(seed))


def write_artifact(tmp_path: Path, suffix: str, text: str | None = None) -> Path:
    path = tmp_path / f"artifact{suffix}"
    path.write_text(SOURCES[suffix] if text is None else text, encoding="utf-8")
    return path


def event_with_detail(result, key: str):
    for event in result.events:
        if key in event.detail:
            return event
    raise AssertionError(f"no event carried detail key {key!r}")


def assert_python_parses(payload: bytes) -> None:
    ast.parse(payload.decode("utf-8"))


def assert_json_parses(payload: bytes):
    return json.loads(payload.decode("utf-8"))


def raise_runtime_error(*_args, **_kwargs):
    raise RuntimeError("synthetic failure")


# --------------------------------------------------------------- poison


def test_poison_applies_to_python(tmp_path):
    path = write_artifact(tmp_path, ".py")
    source = path.read_bytes()
    result = CanaryPoisonStrategy().apply(path, source, make_ctx())

    assert result.verdict is DefenseVerdict.APPLIED
    assert result.data is not None and result.data != source
    assert_python_parses(result.data)
    assert "umbra:canary" in result.data.decode("utf-8")
    event = event_with_detail(result, "canaries")
    assert 1 <= event.detail["canaries"] <= 4


def test_poison_applies_to_json(tmp_path):
    path = write_artifact(tmp_path, ".json")
    result = CanaryPoisonStrategy().apply(path, path.read_bytes(), make_ctx())

    assert result.verdict is DefenseVerdict.APPLIED
    payload = assert_json_parses(result.data)
    assert payload["name"] == "demo"
    assert isinstance(payload["_umbra_canary"], list) and payload["_umbra_canary"]
    assert all("umbra:canary" in entry for entry in payload["_umbra_canary"])


def test_poison_applies_to_markdown(tmp_path):
    path = write_artifact(tmp_path, ".md")
    result = CanaryPoisonStrategy().apply(path, path.read_bytes(), make_ctx())

    assert result.verdict is DefenseVerdict.APPLIED
    assert "<!-- umbra:canary" in result.data.decode("utf-8")


def test_poison_is_idempotent(tmp_path):
    path = write_artifact(tmp_path, ".py")
    strategy = CanaryPoisonStrategy()
    first = strategy.apply(path, path.read_bytes(), make_ctx())
    second = strategy.apply(path, first.data, make_ctx())

    assert second.verdict is DefenseVerdict.SKIPPED
    assert second.data == first.data


def test_poison_is_deterministic(tmp_path):
    path = write_artifact(tmp_path, ".py")
    source = path.read_bytes()
    first = CanaryPoisonStrategy().apply(path, source, make_ctx(seed=42))
    second = CanaryPoisonStrategy().apply(path, source, make_ctx(seed=42))

    assert first.verdict is DefenseVerdict.APPLIED
    assert first.data == second.data


def test_poison_supports_gate():
    strategy = CanaryPoisonStrategy()
    assert strategy.supports(Path("module.pyc")) is False
    assert strategy.supports(Path("module.py")) is True


def test_poison_failure_isolation(tmp_path, monkeypatch):
    path = write_artifact(tmp_path, ".py")
    strategy = CanaryPoisonStrategy()
    monkeypatch.setattr(strategy, "_apply", raise_runtime_error)
    result = strategy.apply(path, path.read_bytes(), make_ctx())

    assert result.verdict is DefenseVerdict.FAILED
    assert result.data is None
    assert result.events and "raised" in result.events[0].message


# --------------------------------------------------------------- exhaust


def test_exhaust_applies_to_python(tmp_path):
    path = write_artifact(tmp_path, ".py")
    source = path.read_bytes()
    result = BudgetExhaustStrategy().apply(
        path, source, make_ctx(intensity="balanced")
    )

    assert result.verdict is DefenseVerdict.APPLIED
    assert result.data != source
    assert_python_parses(result.data)
    assert "_UMBRA_GUARD" in result.data.decode("utf-8")
    event = event_with_detail(result, "filler_items")
    assert event.detail["filler_items"] == DENSITY_BY_INTENSITY["balanced"]
    assert event.detail["intensity"] == "balanced"


def test_exhaust_applies_to_json(tmp_path):
    path = write_artifact(tmp_path, ".json")
    result = BudgetExhaustStrategy().apply(
        path, path.read_bytes(), make_ctx(intensity="maximum")
    )

    assert result.verdict is DefenseVerdict.APPLIED
    payload = assert_json_parses(result.data)
    assert payload["name"] == "demo"
    assert len(payload["_umbra_padding"]) == DENSITY_BY_INTENSITY["maximum"]


def test_exhaust_applies_to_javascript(tmp_path):
    path = write_artifact(tmp_path, ".js")
    result = BudgetExhaustStrategy().apply(path, path.read_bytes(), make_ctx())

    assert result.verdict is DefenseVerdict.APPLIED
    text = result.data.decode("utf-8")
    assert "__UMBRA_GUARD__" in text
    assert "function add(a, b)" in text


def test_exhaust_is_idempotent(tmp_path):
    path = write_artifact(tmp_path, ".py")
    strategy = BudgetExhaustStrategy()
    first = strategy.apply(path, path.read_bytes(), make_ctx())
    second = strategy.apply(path, first.data, make_ctx())

    assert second.verdict is DefenseVerdict.SKIPPED
    assert second.data == first.data


def test_exhaust_is_deterministic(tmp_path):
    path = write_artifact(tmp_path, ".py")
    source = path.read_bytes()
    first = BudgetExhaustStrategy().apply(path, source, make_ctx(seed=42))
    second = BudgetExhaustStrategy().apply(path, source, make_ctx(seed=42))

    assert first.verdict is DefenseVerdict.APPLIED
    assert first.data == second.data


def test_exhaust_density_scales_with_intensity(tmp_path):
    path = write_artifact(tmp_path, ".py")
    source = path.read_bytes()
    strategy = BudgetExhaustStrategy()
    stealth = strategy.apply(path, source, make_ctx(intensity="stealth"))
    bankrupt = strategy.apply(path, source, make_ctx(intensity="bankrupt"))

    assert stealth.verdict is DefenseVerdict.APPLIED
    assert bankrupt.verdict is DefenseVerdict.APPLIED
    assert len(bankrupt.data) > len(stealth.data)
    assert event_with_detail(stealth, "filler_items").detail["filler_items"] == 8
    assert event_with_detail(bankrupt, "filler_items").detail["filler_items"] == 1024


def test_exhaust_supports_gate():
    strategy = BudgetExhaustStrategy()
    assert strategy.supports(Path("module.pyc")) is False
    assert strategy.supports(Path("module.ts")) is True


def test_exhaust_failure_isolation(tmp_path, monkeypatch):
    path = write_artifact(tmp_path, ".py")
    strategy = BudgetExhaustStrategy()
    monkeypatch.setattr(strategy, "_apply", raise_runtime_error)
    result = strategy.apply(path, path.read_bytes(), make_ctx())

    assert result.verdict is DefenseVerdict.FAILED
    assert result.data is None


# ----------------------------------------------------------- hallucinate


def test_hallucinate_applies_to_python(tmp_path):
    path = write_artifact(tmp_path, ".py")
    source = path.read_bytes()
    result = ShadowLogicStrategy().apply(path, source, make_ctx())

    assert result.verdict is DefenseVerdict.APPLIED
    assert result.data != source
    assert_python_parses(result.data)
    text = result.data.decode("utf-8")
    assert "umbra:shadow" in text
    event = event_with_detail(result, "decoys")
    assert 2 <= len(event.detail["decoys"]) <= 3
    for name in event.detail["decoys"]:
        assert name in text


def test_hallucinate_applies_to_javascript(tmp_path):
    path = write_artifact(tmp_path, ".js")
    result = ShadowLogicStrategy().apply(path, path.read_bytes(), make_ctx())

    assert result.verdict is DefenseVerdict.APPLIED
    text = result.data.decode("utf-8")
    assert "umbra:shadow" in text
    assert "function add(a, b)" in text


def test_hallucinate_applies_to_typescript(tmp_path):
    path = write_artifact(tmp_path, ".ts")
    result = ShadowLogicStrategy().apply(path, path.read_bytes(), make_ctx())

    assert result.verdict is DefenseVerdict.APPLIED
    assert "umbra:shadow" in result.data.decode("utf-8")


def test_hallucinate_is_idempotent(tmp_path):
    path = write_artifact(tmp_path, ".py")
    strategy = ShadowLogicStrategy()
    first = strategy.apply(path, path.read_bytes(), make_ctx())
    second = strategy.apply(path, first.data, make_ctx())

    assert second.verdict is DefenseVerdict.SKIPPED
    assert second.data == first.data


def test_hallucinate_is_deterministic(tmp_path):
    path = write_artifact(tmp_path, ".py")
    source = path.read_bytes()
    first = ShadowLogicStrategy().apply(path, source, make_ctx(seed=42))
    second = ShadowLogicStrategy().apply(path, source, make_ctx(seed=42))

    assert first.verdict is DefenseVerdict.APPLIED
    assert first.data == second.data


def test_hallucinate_supports_gate():
    strategy = ShadowLogicStrategy()
    assert strategy.supports(Path("module.pyc")) is False
    assert strategy.supports(Path("module.py")) is True


def test_hallucinate_failure_isolation(tmp_path, monkeypatch):
    path = write_artifact(tmp_path, ".py")
    strategy = ShadowLogicStrategy()
    monkeypatch.setattr(strategy, "_apply", raise_runtime_error)
    result = strategy.apply(path, path.read_bytes(), make_ctx())

    assert result.verdict is DefenseVerdict.FAILED
    assert result.data is None


# ------------------------------------------------------------ combined


@pytest.mark.parametrize("strategy_cls", ALL_STRATEGIES)
def test_supports_rejects_bytecode(strategy_cls):
    assert strategy_cls().supports(Path("module.pyc")) is False


def test_chained_strategies_keep_python_valid(tmp_path):
    path = write_artifact(tmp_path, ".py")
    data = path.read_bytes()
    for strategy_cls in ALL_STRATEGIES:
        result = strategy_cls().apply(path, data, make_ctx())
        assert result.verdict is DefenseVerdict.APPLIED
        assert result.data is not None
        data = result.data
    assert_python_parses(data)
