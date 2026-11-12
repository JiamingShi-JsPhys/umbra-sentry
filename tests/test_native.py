"""Contract tests for the polyglot native (Rust kernel) strategies.

The suite covers both worlds: fake engines injected by monkeypatch for the
degradation/idempotence contract (always runnable), and the real ``ctypes``
FFI path when ``cargo build --release`` has produced ``umbra_native.dll``
(skipped otherwise, so CI without a Rust toolchain stays green).
"""

from __future__ import annotations

import argparse
import random
from pathlib import Path

import pytest

from core.models import DefensePhase, DefenseVerdict
from defense import native_bridge
from defense.base import StrategyContext
from defense.native_bridge import (
    INTENSITY_TO_ID,
    NativeCliEngine,
    NativeEngine,
    NativeEngineError,
    find_native_cli,
    find_native_library,
    get_engine,
    reset_engine_cache,
)
from defense.native_strategies import (
    NATIVE_SUFFIXES,
    NativeExhaustStrategy,
    NativePoisonStrategy,
)

PE_BYTES = b"MZ\x90\x00" + bytes(range(64))
ELF_BYTES = b"\x7fELF" + bytes(range(64))
MACHO_BYTES = b"\xcf\xfa\xed\xfe" + bytes(range(64))

NATIVE_STRATEGIES = (NativePoisonStrategy, NativeExhaustStrategy)
REAL_LIBRARY = find_native_library()
requires_native = pytest.mark.skipif(
    REAL_LIBRARY is None,
    reason="umbra_native shared library not built (cargo build --release)",
)
REAL_CLI = find_native_cli()
requires_native_cli = pytest.mark.skipif(
    REAL_CLI is None,
    reason="umbra-native CLI binary not built (cargo build --release)",
)


def make_ctx(seed: int = 1337, intensity: str = "balanced") -> StrategyContext:
    return StrategyContext(seed=seed, intensity=intensity, rng=random.Random(seed))


def install_engine(monkeypatch, engine) -> None:
    """Point the strategy module's engine lookup at a stub."""
    monkeypatch.setattr(native_bridge, "get_engine", lambda: engine)


def event_with_detail(result, key: str):
    for event in result.events:
        if key in event.detail:
            return event
    raise AssertionError(f"no event carried detail key {key!r}")


@pytest.fixture(autouse=True)
def fresh_engine_cache():
    reset_engine_cache()
    yield
    reset_engine_cache()


def _fnv1a64(payload: bytes) -> int:
    """Python mirror of the kernel's FNV-1a-64 trailer checksum."""
    value = 0xCBF29CE484222325
    for byte in payload:
        value ^= byte
        value = (value * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return value


def _has_trailer(data: bytes, marker: bytes) -> bool:
    """Mirror of ``engine.rs::has_trailer``: structural and tail-anchored.

    The marker only counts as the last line of the file, preceded on that same
    line by the payload length and the payload's FNV-1a tag.  A bare marker
    occurrence — in a comment, a string literal, or an unrelated binary — is
    not evidence that this kernel ran.
    """
    if not data.endswith(b"\n"):
        return False
    body = data[:-1]
    needle = b"\n" + marker + b":"
    pos = body.rfind(needle)
    if pos < 0:
        return False
    rest = body[pos + len(needle) :]
    colon = rest.find(b":")
    if colon < 0:
        return False
    len_field, tag_field = rest[:colon], rest[colon + 1 :]
    if not len_field.isdigit() or len(len_field) > 20:
        return False
    if len(tag_field) != 16:
        return False
    if any(byte not in b"0123456789abcdef" for byte in tag_field):
        return False
    payload_len = int(len_field)
    if payload_len < len(marker) or payload_len > pos:
        return False
    return _fnv1a64(body[pos - payload_len : pos]) == int(tag_field, 16)


class FakeNativeEngine:
    """Seed-aware stub mirroring the kernel's trailer-based idempotence."""

    mode = "fake"
    version = "umbra-native fake 0.0.0"

    def __init__(self) -> None:
        self.calls: list[tuple[str, int, str]] = []

    def poison(self, data: bytes, seed: int, intensity: str) -> bytes:
        self.calls.append(("poison", seed, intensity))
        return self._append(data, b"umbra:canary", seed, intensity)

    def exhaust(self, data: bytes, seed: int, intensity: str) -> bytes:
        self.calls.append(("exhaust", seed, intensity))
        return self._append(data, b"umbra:_umbra_padding", seed, intensity)

    @staticmethod
    def _append(data: bytes, marker: bytes, seed: int, intensity: str) -> bytes:
        # Mirrors engine.rs: only a structurally complete trailer suppresses a
        # second pass; a bare marker substring does not.
        if _has_trailer(data, marker):
            return data
        pad = (8 - (len(data) % 8)) % 8
        payload = (
            b"\x00" * pad
            + marker
            + b"|"
            + str(seed).encode()
            + b"|"
            + intensity.encode()
            + b"\n"
        )
        trailer = (
            b"\n"
            + marker
            + b":"
            + str(len(payload)).encode()
            + b":"
            + f"{_fnv1a64(payload):016x}".encode()
            + b"\n"
        )
        return data + payload + trailer


def spoofed_variants(marker: bytes) -> list[bytes]:
    """Two ways to fake a marker without producing a real trailer.

    * a bare comment line — the attack the old kernel fell for, and
    * a structurally shaped trailer whose checksum does not match.
    """
    return [
        b"\n// " + marker + b"\n",
        b"\n" + marker + b":32:" + b"0" * 16 + b"\n",
    ]


class ExplodingNativeEngine:
    mode = "fake"
    version = "umbra-native fake 0.0.0"

    def poison(self, data: bytes, seed: int, intensity: str) -> bytes:
        raise NativeEngineError("synthetic native failure")

    def exhaust(self, data: bytes, seed: int, intensity: str) -> bytes:
        raise NativeEngineError("synthetic native failure")


# ------------------------------------------------------------ identity


def test_native_strategy_identity():
    assert NativePoisonStrategy.name == "native-poison"
    assert NativePoisonStrategy.phase is DefensePhase.POISON
    assert NativeExhaustStrategy.name == "native-exhaust"
    assert NativeExhaustStrategy.phase is DefensePhase.EXHAUST
    for strategy_cls in NATIVE_STRATEGIES:
        assert strategy_cls.SUPPORTED_SUFFIXES == NATIVE_SUFFIXES


@pytest.mark.parametrize("strategy_cls", NATIVE_STRATEGIES)
def test_suffix_gate(strategy_cls):
    strategy = strategy_cls()
    assert strategy.supports(Path("app.exe")) is True
    assert strategy.supports(Path("lib.so")) is True
    assert strategy.supports(Path("module.node")) is True
    assert strategy.supports(Path("module.py")) is False
    assert strategy.supports(Path("notes.md")) is False


def test_unsupported_suffix_never_touches_engine(tmp_path, monkeypatch):
    engine = FakeNativeEngine()
    install_engine(monkeypatch, engine)
    path = tmp_path / "module.py"
    path.write_bytes(b"print('hello')\n")

    result = NativePoisonStrategy().apply(path, path.read_bytes(), make_ctx())

    assert result.verdict is DefenseVerdict.SKIPPED
    assert result.data is None
    assert engine.calls == []


# ------------------------------------------------------- engine absent


@pytest.mark.parametrize("strategy_cls", NATIVE_STRATEGIES)
def test_absent_engine_skips_with_audited_event(tmp_path, monkeypatch, strategy_cls):
    install_engine(monkeypatch, None)
    path = tmp_path / "app.exe"
    path.write_bytes(PE_BYTES)

    result = strategy_cls().apply(path, PE_BYTES, make_ctx())

    assert result.verdict is DefenseVerdict.SKIPPED
    assert result.data is None
    assert path.read_bytes() == PE_BYTES  # artifact untouched
    skipped = [e for e in result.events if "native engine not built" in e.message]
    assert skipped, [e.message for e in result.events]
    assert skipped[0].severity.value == "low"
    assert skipped[0].detail["engine_mode"] == "absent"


# --------------------------------------------------------- fake engine


def test_fake_engine_poison_applied(tmp_path, monkeypatch):
    engine = FakeNativeEngine()
    install_engine(monkeypatch, engine)
    path = tmp_path / "app.exe"

    result = NativePoisonStrategy().apply(path, PE_BYTES, make_ctx(seed=42))

    assert result.verdict is DefenseVerdict.APPLIED
    assert result.data is not None and result.data != PE_BYTES
    assert result.data.startswith(PE_BYTES)  # append-only
    event = event_with_detail(result, "engine_mode")
    assert event.detail["engine_mode"] == "fake"
    assert event.detail["engine_version"] == "umbra-native fake 0.0.0"
    assert event.detail["byte_delta"] == len(result.data) - len(PE_BYTES)
    assert engine.calls == [("poison", 42, "balanced")]


def test_fake_engine_exhaust_applied(tmp_path, monkeypatch):
    engine = FakeNativeEngine()
    install_engine(monkeypatch, engine)
    path = tmp_path / "lib.so"

    result = NativeExhaustStrategy().apply(path, ELF_BYTES, make_ctx(seed=7))

    assert result.verdict is DefenseVerdict.APPLIED
    assert result.data is not None and result.data.startswith(ELF_BYTES)
    assert engine.calls == [("exhaust", 7, "balanced")]


@pytest.mark.parametrize("strategy_cls", NATIVE_STRATEGIES)
def test_fake_engine_is_deterministic(tmp_path, monkeypatch, strategy_cls):
    install_engine(monkeypatch, FakeNativeEngine())
    path = tmp_path / "app.exe"
    source = MACHO_BYTES

    first = strategy_cls().apply(path, source, make_ctx(seed=42))
    second = strategy_cls().apply(path, source, make_ctx(seed=42))

    assert first.verdict is DefenseVerdict.APPLIED
    assert first.data == second.data


@pytest.mark.parametrize("strategy_cls", NATIVE_STRATEGIES)
def test_fake_engine_is_idempotent(tmp_path, monkeypatch, strategy_cls):
    install_engine(monkeypatch, FakeNativeEngine())
    strategy = strategy_cls()
    path = tmp_path / "app.exe"

    first = strategy.apply(path, PE_BYTES, make_ctx(seed=42))
    second = strategy.apply(path, first.data, make_ctx(seed=42))

    assert second.verdict is DefenseVerdict.SKIPPED
    assert second.data is None
    assert any("already hardened" in event.message for event in second.events)


def marker_for(strategy_cls) -> bytes:
    if strategy_cls is NativePoisonStrategy:
        return b"umbra:canary"
    return b"umbra:_umbra_padding"


@pytest.mark.parametrize("strategy_cls", NATIVE_STRATEGIES)
@pytest.mark.parametrize("variant", (0, 1))
def test_spoofed_marker_does_not_suppress_hardening(
    tmp_path, monkeypatch, strategy_cls, variant
):
    """Regression (S1): a bare marker must not fake idempotence.

    The old kernel skipped on any substring match, so appending
    ``\\n// umbra:canary\\n`` to an executable turned every native strategy
    into a no-op.  Only a structurally complete trailer may suppress work.
    """
    engine = FakeNativeEngine()
    install_engine(monkeypatch, engine)
    path = tmp_path / "app.exe"

    tampered = PE_BYTES + spoofed_variants(marker_for(strategy_cls))[variant]
    result = strategy_cls().apply(path, tampered, make_ctx(seed=42))

    assert result.verdict is DefenseVerdict.APPLIED
    assert result.data is not None and result.data != tampered
    assert result.data.startswith(tampered)  # append-only
    assert engine.calls, "the engine must have been consulted, not skipped"


@pytest.mark.parametrize("strategy_cls", NATIVE_STRATEGIES)
def test_trailer_must_be_tail_anchored(tmp_path, monkeypatch, strategy_cls):
    """A genuine trailer followed by new bytes no longer marks the artifact."""
    engine = FakeNativeEngine()
    install_engine(monkeypatch, engine)
    strategy = strategy_cls()

    genuine = strategy.apply(tmp_path / "a.exe", PE_BYTES, make_ctx(seed=42)).data
    assert genuine is not None
    modified = genuine + b"appended by someone else\n"

    result = strategy.apply(tmp_path / "b.exe", modified, make_ctx(seed=42))

    assert result.verdict is DefenseVerdict.APPLIED
    assert result.data is not None and result.data.startswith(modified)


@pytest.mark.parametrize("strategy_cls", NATIVE_STRATEGIES)
def test_engine_error_skips_with_medium_event(tmp_path, monkeypatch, strategy_cls):
    install_engine(monkeypatch, ExplodingNativeEngine())
    path = tmp_path / "app.exe"

    result = strategy_cls().apply(path, PE_BYTES, make_ctx())

    assert result.verdict is DefenseVerdict.SKIPPED
    assert result.data is None
    failed = [e for e in result.events if "native engine error" in e.message]
    assert failed
    assert "synthetic native failure" in failed[0].message
    assert failed[0].severity.value == "medium"


# ------------------------------------------------- real FFI / discovery


def test_intensity_mapping():
    assert INTENSITY_TO_ID == {
        "stealth": 0,
        "balanced": 1,
        "maximum": 2,
        "bankrupt": 3,
    }


def test_finders_never_raise():
    library = find_native_library()
    cli = find_native_cli()
    assert library is None or library.is_file()
    assert cli is None or cli.is_file()


@requires_native
def test_real_ffi_version_and_mode():
    engine = NativeEngine()
    assert engine.mode == "ffi"
    assert engine.version
    assert "umbra-native" in engine.version


@requires_native
def test_real_ffi_poison_deterministic_append_only_idempotent():
    engine = NativeEngine()

    first = engine.poison(PE_BYTES, 42, "balanced")
    second = engine.poison(PE_BYTES, 42, "balanced")

    assert first == second
    assert first.startswith(PE_BYTES)
    assert b"umbra:canary" in first
    assert engine.poison(first, 42, "balanced") == first


@requires_native
def test_real_ffi_exhaust_append_only_idempotent():
    engine = NativeEngine()

    first = engine.exhaust(ELF_BYTES, 7, "stealth")

    assert first.startswith(ELF_BYTES)
    assert b"umbra:_umbra_padding" in first
    assert engine.exhaust(first, 7, "stealth") == first


@requires_native
@pytest.mark.parametrize("strategy_cls", NATIVE_STRATEGIES)
def test_real_ffi_ignores_spoofed_markers(strategy_cls):
    """Regression (S1) against the shipped kernel: spoofed markers must not
    suppress hardening, while a genuine trailer still must."""
    engine = NativeEngine()
    if strategy_cls is NativePoisonStrategy:
        transform = engine.poison
    else:
        transform = engine.exhaust
    marker = marker_for(strategy_cls)

    for spoof in spoofed_variants(marker):
        tampered = PE_BYTES + spoof
        hardened = transform(tampered, 42, "stealth")
        assert hardened != tampered, f"spoof suppressed hardening: {spoof!r}"
        assert hardened.startswith(tampered)
        # The genuine output is still idempotent under a second pass.
        assert transform(hardened, 42, "stealth") == hardened


@requires_native_cli
def test_real_cli_transport_round_trips_the_kernel():
    """The subprocess fallback must behave exactly like the FFI transport.

    Covers the second transport end to end: version banner, determinism,
    append-only idempotence, and the same spoofed-marker resistance the FFI
    suite asserts.  Skipped on a machine where the standalone binary was not
    built, which is why the README states the test count both ways.
    """
    engine = NativeCliEngine()
    assert engine.mode == "cli"
    assert engine.version.startswith("umbra-native")

    poison = engine.poison(PE_BYTES, 42, "stealth")
    assert poison.startswith(PE_BYTES)
    assert b"umbra:canary" in poison
    assert engine.poison(PE_BYTES, 42, "stealth") == poison
    assert engine.poison(poison, 42, "stealth") == poison

    exhaust = engine.exhaust(ELF_BYTES, 7, "balanced")
    assert exhaust.startswith(ELF_BYTES)
    assert engine.exhaust(ELF_BYTES, 7, "balanced") == exhaust
    assert engine.exhaust(exhaust, 7, "balanced") == exhaust

    transports = (
        (NativePoisonStrategy, engine.poison),
        (NativeExhaustStrategy, engine.exhaust),
    )
    for strategy_cls, transform in transports:
        for spoof in spoofed_variants(marker_for(strategy_cls)):
            tampered = PE_BYTES + spoof
            hardened = transform(tampered, 42, "stealth")
            assert hardened != tampered, f"spoof suppressed hardening: {spoof!r}"
            assert hardened.startswith(tampered)


@requires_native
def test_real_engine_drives_the_strategy(tmp_path, monkeypatch):
    install_engine(monkeypatch, NativeEngine())
    path = tmp_path / "app.exe"

    result = NativePoisonStrategy().apply(path, PE_BYTES, make_ctx(seed=42))

    assert result.verdict is DefenseVerdict.APPLIED
    assert result.data is not None and result.data.startswith(PE_BYTES)
    event = event_with_detail(result, "engine_mode")
    assert event.detail["engine_mode"] == "ffi"


@requires_native
def test_get_engine_prefers_ffi():
    engine = get_engine()
    assert engine is not None
    assert engine.mode in {"ffi", "cli"}


def test_cli_pipeline_includes_native_strategies():
    from cli import _build_pipeline

    args = argparse.Namespace(seed=0, intensity="balanced", max_files=8)
    pipeline = _build_pipeline(args)
    names = {strategy.name for strategy in pipeline.strategies}

    assert {"native-poison", "native-exhaust"} <= names
