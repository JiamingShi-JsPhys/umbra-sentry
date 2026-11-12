"""Static-analysis budget exhaustion through inert, dead filler blocks.

The filler never executes: each language wrapper guards it behind a
predicate that is always false at runtime, while parsers, decompilers and
LLM context windows still have to ingest every byte of it.

# Concept inspired by: bla resource-exhaustion / semantic budget breakers
"""

from __future__ import annotations

import ast
import json
import random
from pathlib import Path
from typing import ClassVar

from core.models import DefensePhase
from defense.base import BaseDefenseStrategy, StrategyContext, StrategyResult
from defense.markers import (
    has_json_trailer,
    has_trailer,
    json_trailer_value,
    trailer_line,
)

__all__ = ["DENSITY_BY_INTENSITY", "BudgetExhaustStrategy"]

DENSITY_BY_INTENSITY: dict[str, int] = {
    "stealth": 8,
    "balanced": 64,
    "maximum": 256,
    "bankrupt": 1024,
}

_MARKER = "umbra:exhaust"
_JSON_KEY = "_umbra_padding"
_JSON_TRAILER_KEY = "_umbra_padding_trailer"

_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def _rng(ctx: StrategyContext) -> random.Random:
    """Return the caller-supplied RNG, or a seed-derived fallback."""
    rng = getattr(ctx, "rng", None)
    if rng is not None and hasattr(rng, "choice"):
        return rng  # type: ignore[return-value]
    return random.Random(ctx.seed)


def _filler_strings(rng: random.Random, count: int) -> list[str]:
    """Build ``count`` deterministic, high-entropy-looking string constants."""
    return [
        "".join(rng.choice(_ALPHABET) for _ in range(rng.randint(40, 72)))
        for _ in range(count)
    ]


def _append(text: str, block: str) -> str:
    """Join ``block`` after ``text`` with clean newline separation."""
    if text and not text.endswith("\n"):
        text += "\n"
    if text and not text.endswith("\n\n"):
        text += "\n"
    return text + block


def _python_block(filler: list[str]) -> str:
    """Dead-branch constant table; the inner guard is never truthy."""
    rows = [f'            "{item[:28]}" "{item[28:]}"' for item in filler]
    index_rows = [f"            {i}: _UMBRA_FILLER[{i}]," for i in range(len(filler))]
    lines = [
        "",
        "# --- umbra:exhaust static-analysis padding ---",
        "_UMBRA_GUARD = False",
        "if not _UMBRA_GUARD:  # opaque-false predicate",
        "    if _UMBRA_GUARD:  # unreachable: the guard never becomes truthy",
        "        _UMBRA_FILLER = (",
        *rows,
        "        )",
        "        _UMBRA_INDEX = {",
        *index_rows,
        "        }",
    ]
    return "\n".join(lines) + "\n"


def _js_block(filler: list[str]) -> str:
    """Dead-branch string tables for JavaScript and TypeScript."""
    rows = "\n".join(f'      "{item}",' for item in filler)
    index_rows = "\n".join(
        f"      {i}: __UMBRA_FILLER__[{i}]," for i in range(len(filler))
    )
    lines = [
        "",
        "// --- umbra:exhaust static-analysis padding ---",
        "if (!globalThis.__UMBRA_GUARD__) {",
        "  // Dead branch: __UMBRA_GUARD__ is never defined.",
        "  if (globalThis.__UMBRA_GUARD__) {",
        "    const __UMBRA_FILLER__ = [",
        rows,
        "    ];",
        "    const __UMBRA_INDEX__ = {",
        index_rows,
        "    };",
        "  }",
        "}",
    ]
    return "\n".join(lines) + "\n"


def _json_has_padding_trailer(text: str) -> bool:
    """True when ``text`` is a JSON object carrying this package's trailer.

    A bare ``_umbra_padding`` key is not enough: an artifact that merely
    mentions the key must still be hardened.
    """
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return False
    if not isinstance(payload, dict):
        return False
    return has_json_trailer(
        payload, _MARKER, key=_JSON_TRAILER_KEY, data_key=_JSON_KEY
    )


class BudgetExhaustStrategy(BaseDefenseStrategy):
    """Inflate static-analysis cost with bounded, never-executed filler."""

    name = "exhaust-budget"
    phase = DefensePhase.EXHAUST
    SUPPORTED_SUFFIXES: ClassVar[set[str] | None] = {".py", ".js", ".ts", ".json"}

    def _apply(
        self, file_path: Path, data: bytes, ctx: StrategyContext
    ) -> StrategyResult:
        suffix = file_path.suffix.lower()
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return StrategyResult(data=None, notes=["artifact is not utf-8 text"])

        # Idempotence is structural, not textual: only a trailer this package
        # wrote, located by scanning back from EOF and validated by the
        # checksum of the exact bytes it describes, suppresses a second pass.
        # For JSON the evidence is a sibling key carrying the checksum of this
        # strategy's own payload (``_umbra_padding``), so a later strategy
        # adding its own keys does not invalidate it.  A bare marker pasted
        # anywhere in the artifact does not suppress hardening.
        if suffix == ".json":
            if _json_has_padding_trailer(text):
                return StrategyResult(data=data, notes=["already padded"])
        elif has_trailer(text, _MARKER):
            return StrategyResult(data=data, notes=["already padded"])

        rng = _rng(ctx)
        intensity = str(ctx.intensity)
        density = DENSITY_BY_INTENSITY.get(
            intensity.lower(), DENSITY_BY_INTENSITY["balanced"]
        )

        if suffix == ".json":
            new_text = self._pad_json(text, rng, density)
            if new_text is None:
                return StrategyResult(
                    data=None, notes=["json top level is not an object"]
                )
        elif suffix == ".py":
            block = _python_block(_filler_strings(rng, density))
            trailer = trailer_line(_MARKER, block.encode("utf-8"), prefix="# ")
            new_text = _append(text, block + trailer)
            try:
                ast.parse(new_text)
            except SyntaxError:
                return StrategyResult(
                    data=None, notes=["python parse failed; skipped"]
                )
        else:
            block = _js_block(_filler_strings(rng, density))
            trailer = trailer_line(_MARKER, block.encode("utf-8"), prefix="// ")
            new_text = _append(text, block + trailer)

        new_bytes = new_text.encode("utf-8")
        event = self._event(
            file_path,
            data,
            new_bytes,
            f"appended {density} inert filler item(s)",
            severity="low",
            filler_items=density,
            intensity=intensity,
        )
        return StrategyResult(data=new_bytes, events=[event])

    def _pad_json(self, text: str, rng: random.Random, density: int) -> str | None:
        """Add a bounded padding array only when round-trip stays valid."""
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return None
        if not isinstance(payload, dict):
            return None
        payload[_JSON_KEY] = _filler_strings(rng, density)
        payload[_JSON_TRAILER_KEY] = json_trailer_value(
            _MARKER, payload, key=_JSON_TRAILER_KEY, data_key=_JSON_KEY
        )
        serialized = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
        try:
            json.loads(serialized)
        except json.JSONDecodeError:
            return None
        return serialized
