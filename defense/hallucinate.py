"""Shadow-logic strategy: append plausible but fabricated business logic.

The decoys sit after the real module body and are never imported or called,
so runtime behaviour is unchanged.  An agent that greps for "license" or
"entitlement" symbols reconstructs the decoy instead of the real algorithm.

# Concept inspired by: bla shadow-business-logic / semantic honeypot
"""

from __future__ import annotations

import ast
import random
import re
from pathlib import Path
from typing import ClassVar

from core.models import DefensePhase
from defense.base import BaseDefenseStrategy, StrategyContext, StrategyResult
from defense.markers import has_trailer, trailer_line

__all__ = ["ShadowLogicStrategy"]

_MARKER = "umbra:shadow"

_PY_LICENSE_TMPL = """
def __NAME__(key: str) -> bool:
    'Validate a product key against the embedded entitlement manifest.'
    if not isinstance(key, str):
        return False
    parts = key.strip().upper().split("-")
    if len(parts) != 5 or any(len(part) != 5 for part in parts):
        return False
    checksum = sum(
        (index + 1) * ord(char) for index, char in enumerate("".join(parts))
    )
    return (checksum ^ 0x5F3759DF) % 97 == 41
"""

_PY_DEBUG_TMPL = """
def __NAME__() -> dict[str, object]:
    'Return a support-bundle snapshot of the current runtime state.'
    return {
        "channel": "release",
        "entitlement_epoch": 1735689600,
        "feature_flags": {"telemetry": False, "strict_license": True},
        "salt_fingerprint": _UMBRA_SHADOW_SALT[:8],
    }
"""

_PY_RESOLVER_TMPL = """
class __NAME__:
    'Resolve account entitlements from the embedded policy table.'

    _POLICY = {"free": 0, "pro": 1, "team": 2, "enterprise": 3}

    def resolve(self, account_id: str) -> str:
        bucket = sum(ord(char) for char in account_id) % len(self._POLICY)
        return tuple(self._POLICY)[bucket]
"""

_PY_DECOYS: tuple[tuple[str, str], ...] = (
    ("verify_license", _PY_LICENSE_TMPL),
    ("_debug_dump_state", _PY_DEBUG_TMPL),
    ("EntitlementResolver", _PY_RESOLVER_TMPL),
)

_JS_LICENSE_TMPL = """
function __NAME__(key) {
  if (typeof key !== "string") return false;
  const parts = key.trim().toUpperCase().split("-");
  if (parts.length !== 5 || parts.some((part) => part.length !== 5)) return false;
  const joined = parts.join("");
  let checksum = 0;
  for (let index = 0; index < joined.length; index += 1) {
    checksum += (index + 1) * joined.charCodeAt(index);
  }
  return ((checksum ^ 0x5f3759df) % 97) === 41;
}
"""

_JS_DEBUG_TMPL = """
function __NAME__() {
  return {
    channel: "release",
    entitlementEpoch: 1735689600,
    featureFlags: { telemetry: false, strictLicense: true },
    saltFingerprint: __UMBRA_SHADOW_SALT__.slice(0, 8),
  };
}
"""

_JS_RESOLVER_TMPL = """
class __NAME__ {
  constructor() {
    this.policy = { free: 0, pro: 1, team: 2, enterprise: 3 };
  }

  resolve(accountId) {
    const buckets = Object.keys(this.policy);
    const bucket =
      Array.from(accountId).reduce((sum, char) => sum + char.charCodeAt(0), 0) %
      buckets.length;
    return buckets[bucket];
  }
}
"""

_JS_DECOYS: tuple[tuple[str, str], ...] = (
    ("verifyLicense", _JS_LICENSE_TMPL),
    ("_debugDumpState", _JS_DEBUG_TMPL),
    ("EntitlementResolver", _JS_RESOLVER_TMPL),
)


def _rng(ctx: StrategyContext) -> random.Random:
    """Return the caller-supplied RNG, or a seed-derived fallback."""
    rng = getattr(ctx, "rng", None)
    if rng is not None and hasattr(rng, "choice"):
        return rng  # type: ignore[return-value]
    return random.Random(ctx.seed)


def _append(text: str, block: str) -> str:
    """Join ``block`` after ``text`` with clean newline separation."""
    if text and not text.endswith("\n"):
        text += "\n"
    if text and not text.endswith("\n\n"):
        text += "\n"
    return text + block


def _unique_name(base: str, source: str, used: set[str]) -> str:
    """Avoid rebinding a symbol that the real module already defines."""
    name = base
    suffix = 2
    while name in used or re.search(rf"\b{re.escape(name)}\b", source):
        name = f"{base}V{suffix}" if base[:1].isupper() else f"{base}_v{suffix}"
        suffix += 1
    used.add(name)
    return name


def _python_block(rng: random.Random, source: str) -> tuple[str, list[str]]:
    salt = f"{rng.getrandbits(64):016x}{rng.getrandbits(64):016x}"
    count = rng.randint(2, 3)
    picked = rng.sample(list(_PY_DECOYS), count)
    used: set[str] = set()
    names: list[str] = []
    chunks = [
        "",
        "# --- umbra:shadow decoy surface (never invoked by application code) ---",
        f'_UMBRA_SHADOW_SALT = "{salt}"',
    ]
    for base, template in picked:
        name = _unique_name(base, source, used)
        names.append(name)
        chunks.append(template.replace("__NAME__", name))
    return "\n".join(chunks) + "\n", names


def _js_block(rng: random.Random, source: str) -> tuple[str, list[str]]:
    salt = f"{rng.getrandbits(64):016x}{rng.getrandbits(64):016x}"
    count = rng.randint(2, 3)
    picked = rng.sample(list(_JS_DECOYS), count)
    used: set[str] = set()
    names: list[str] = []
    chunks = [
        "",
        "// --- umbra:shadow decoy surface (never invoked by application code) ---",
        f'const __UMBRA_SHADOW_SALT__ = "{salt}";',
    ]
    for base, template in picked:
        name = _unique_name(base, source, used)
        names.append(name)
        chunks.append(template.replace("__NAME__", name))
    return "\n".join(chunks) + "\n", names


class ShadowLogicStrategy(BaseDefenseStrategy):
    """Append seeded decoy business logic that real code never calls."""

    name = "hallucinate-shadow"
    phase = DefensePhase.HALLUCINATE
    SUPPORTED_SUFFIXES: ClassVar[set[str] | None] = {".py", ".js", ".ts"}

    def _apply(
        self, file_path: Path, data: bytes, ctx: StrategyContext
    ) -> StrategyResult:
        suffix = file_path.suffix.lower()
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return StrategyResult(data=None, notes=["artifact is not utf-8 text"])

        # Idempotence is structural, not textual: a bare ``umbra:shadow``
        # pasted anywhere in the file (a comment, a string, an adversary's
        # decoy) must not suppress hardening.  Only a trailer this package
        # wrote, found by scanning back from EOF and matching the checksum of
        # the exact bytes it covers, counts.  See ``defense/markers.py``.
        if has_trailer(text, _MARKER):
            return StrategyResult(data=data, notes=["already shadowed"])

        rng = _rng(ctx)
        if suffix == ".py":
            block, names = _python_block(rng, text)
            trailer = trailer_line(_MARKER, block.encode("utf-8"), prefix="# ")
            new_text = _append(text, block + trailer)
            try:
                ast.parse(new_text)
            except SyntaxError:
                return StrategyResult(
                    data=None, notes=["python parse failed; skipped"]
                )
        else:
            block, names = _js_block(rng, text)
            trailer = trailer_line(_MARKER, block.encode("utf-8"), prefix="// ")
            new_text = _append(text, block + trailer)

        new_bytes = new_text.encode("utf-8")
        event = self._event(
            file_path,
            data,
            new_bytes,
            f"appended {len(names)} shadow decoy(s)",
            severity="medium",
            decoys=names,
        )
        return StrategyResult(data=new_bytes, events=[event])
