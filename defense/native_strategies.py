"""Polyglot native strategies: compiled artifacts hardened by a Rust kernel.

Text formats are handled by the Python strategies; compiled artifacts (PE,
ELF, Mach-O and the object/library suffixes below) are delegated over a C ABI
to the optional ``umbra-native`` kernel.  The kernel only ever appends, so a
hardened binary still loads.  Every call is deterministic on ``(seed, input)``,
and every degradation is an audited event instead of an exception.

Concept inspired by: Anchor (AnimusLab) — compiled Rust kernel behind a Python
orchestration layer
"""

from __future__ import annotations

from pathlib import Path

from core.models import DefensePhase
from defense import native_bridge
from defense.base import BaseDefenseStrategy, StrategyContext, StrategyResult

__all__ = ["NativeExhaustStrategy", "NativePoisonStrategy"]

#: Compiled/object suffixes the Rust kernel understands.
NATIVE_SUFFIXES = {
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".bin",
    ".elf",
    ".o",
    ".a",
    ".lib",
    ".node",
}

_NOT_BUILT = (
    "skipped: native engine not built "
    "(run `cargo build --release` in defense/native/umbra-native); "
    "artifact untouched"
)


def _engine_mode(engine: object) -> str:
    try:
        return str(getattr(engine, "mode", "unknown"))
    except Exception:  # noqa: BLE001 — telemetry must never break hardening
        return "unknown"


def _engine_version(engine: object) -> str:
    try:
        return str(getattr(engine, "version", "unknown"))
    except Exception:  # noqa: BLE001 — telemetry must never break hardening
        return "unknown"


class _NativeStrategy(BaseDefenseStrategy):
    """Shared degradation, idempotence and telemetry logic for both verbs."""

    SUPPORTED_SUFFIXES = NATIVE_SUFFIXES
    verb: str = ""

    def _apply(
        self, file_path: Path, data: bytes, ctx: StrategyContext
    ) -> StrategyResult:
        # The pipeline gates on ``supports`` too; gating here as well keeps the
        # contract true when a caller invokes ``apply`` directly.
        if not self.supports(file_path):
            return StrategyResult(data=None)

        engine = native_bridge.get_engine()
        if engine is None:
            return StrategyResult(
                data=None,
                events=[
                    self._event(
                        file_path,
                        data,
                        None,
                        _NOT_BUILT,
                        severity="low",
                        engine_mode="absent",
                    )
                ],
            )

        try:
            transformed = getattr(engine, self.verb)(data, ctx.seed, ctx.intensity)
        except native_bridge.NativeEngineError as exc:
            return StrategyResult(
                data=None,
                events=[
                    self._event(
                        file_path,
                        data,
                        None,
                        f"skipped: native engine error: {exc}",
                        severity="medium",
                        engine_mode=_engine_mode(engine),
                    )
                ],
            )

        if not transformed or transformed == data:
            # The kernel detected its own marker and returned the input
            # unchanged; base.apply downgrades this to SKIPPED.
            return StrategyResult(
                data=None,
                events=[
                    self._event(
                        file_path,
                        data,
                        None,
                        "skipped: already hardened (idempotent)",
                        severity="low",
                        engine_mode=_engine_mode(engine),
                        engine_version=_engine_version(engine),
                    )
                ],
            )

        byte_delta = len(transformed) - len(data)
        return StrategyResult(
            data=transformed,
            events=[
                self._event(
                    file_path,
                    data,
                    transformed,
                    f"appended {byte_delta} byte(s) with the native kernel",
                    severity="low",
                    engine_mode=_engine_mode(engine),
                    engine_version=_engine_version(engine),
                    byte_delta=byte_delta,
                )
            ],
        )


class NativePoisonStrategy(_NativeStrategy):
    """Append deterministic canary decoys to compiled binaries."""

    name = "native-poison"
    phase = DefensePhase.POISON
    SUPPORTED_SUFFIXES = NATIVE_SUFFIXES
    verb = "poison"


class NativeExhaustStrategy(_NativeStrategy):
    """Append seeded dead weight to compiled binaries."""

    name = "native-exhaust"
    phase = DefensePhase.EXHAUST
    SUPPORTED_SUFFIXES = NATIVE_SUFFIXES
    verb = "exhaust"
