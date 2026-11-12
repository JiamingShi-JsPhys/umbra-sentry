"""Canary poison strategy: plant decoy credentials that bait AI agents.

Every canary is fabricated from a seed-derived vocabulary; none of it is a
real credential.  Markers carry an ``umbra:canary`` prefix so a second pass
detects already-poisoned artifacts and stays idempotent.

# Concept inspired by: bla canary-honeypot
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

__all__ = ["CanaryPoisonStrategy"]

_MARKER = "umbra:canary"
_JSON_KEY = "_umbra_canary"
_JSON_TRAILER_KEY = "_umbra_canary_trailer"
_KEY_PREFIXES = ("sk_live_", "sk_test_", "pk_live_", "xoxb-", "ghp_")
_TOKEN_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
_AWS_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_SECRET_ALPHABET = _TOKEN_ALPHABET + "+/"


def _rng(ctx: StrategyContext) -> random.Random:
    """Return the caller-supplied RNG, or a seed-derived fallback."""
    rng = getattr(ctx, "rng", None)
    if rng is not None and hasattr(rng, "choice"):
        return rng  # type: ignore[return-value]
    return random.Random(ctx.seed)


def _token(rng: random.Random, length: int, alphabet: str = _TOKEN_ALPHABET) -> str:
    return "".join(rng.choice(alphabet) for _ in range(length))


def _fake_api_key(rng: random.Random) -> str:
    return rng.choice(_KEY_PREFIXES) + _token(rng, rng.randint(24, 40))


def _fake_aws_access_key(rng: random.Random) -> str:
    return "AKIA" + _token(rng, 16, _AWS_ALPHABET)


def _fake_aws_secret(rng: random.Random) -> str:
    return _token(rng, 40, _SECRET_ALPHABET)


def _fake_account_id(rng: random.Random) -> str:
    return "".join(rng.choice("0123456789") for _ in range(12))


def _canary_payload(rng: random.Random) -> str:
    shape = rng.randrange(3)
    if shape == 0:
        return f"API_TOKEN={_fake_api_key(rng)}"
    if shape == 1:
        return (
            f"AWS_ACCESS_KEY_ID={_fake_aws_access_key(rng)} "
            f"AWS_SECRET_ACCESS_KEY={_fake_aws_secret(rng)}"
        )
    return f"BILLING_KEY={_fake_api_key(rng)} ACCOUNT_ID={_fake_account_id(rng)}"


def _canary_lines(rng: random.Random, count: int) -> list[str]:
    lines: list[str] = []
    for _ in range(count):
        token = f"{rng.getrandbits(32):08x}"
        lines.append(f"{_MARKER}:{token}: {_canary_payload(rng)}")
    return lines


def _append(text: str, block: str) -> str:
    """Join ``block`` after ``text`` with clean newline separation."""
    if text and not text.endswith("\n"):
        text += "\n"
    if text and not text.endswith("\n\n"):
        text += "\n"
    return text + block


def _comment_style(suffix: str) -> tuple[str, str]:
    """Return (open, close) comment tokens for a text format."""
    if suffix in {".js", ".ts"}:
        return "// ", ""
    if suffix == ".md":
        return "<!-- ", " -->"
    return "# ", ""


def _json_has_canary_trailer(text: str) -> bool:
    """True when ``text`` is a JSON object carrying this package's trailer.

    A bare ``_umbra_canary`` key is not enough: an artifact that merely
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


class CanaryPoisonStrategy(BaseDefenseStrategy):
    """Append fake credential canaries without changing program behaviour."""

    name = "poison-canary"
    phase = DefensePhase.POISON
    SUPPORTED_SUFFIXES: ClassVar[set[str] | None] = {
        ".py",
        ".json",
        ".js",
        ".ts",
        ".toml",
        ".cfg",
        ".ini",
        ".md",
    }

    def _apply(
        self, file_path: Path, data: bytes, ctx: StrategyContext
    ) -> StrategyResult:
        suffix = file_path.suffix.lower()
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return StrategyResult(data=None, notes=["artifact is not utf-8 text"])

        # Idempotence is structural, not textual.  The strategies used to skip
        # whenever ``umbra:canary`` appeared *anywhere* in the file, so one
        # pasted comment line — by the author, a reviewer, or an adversary —
        # turned hardening into a no-op.  Only a trailer this package wrote,
        # carrying the length and checksum of the exact bytes it describes,
        # may suppress a second pass; it is found by scanning back from EOF,
        # so a later strategy's block appended after it does not blind the
        # check, while editing the bytes it covers does.  See
        # ``defense/markers.py``.
        if suffix == ".json":
            if _json_has_canary_trailer(text):
                return StrategyResult(data=data, notes=["already poisoned"])
        elif has_trailer(text, _MARKER):
            return StrategyResult(data=data, notes=["already poisoned"])

        rng = _rng(ctx)
        count = rng.randint(1, 4)
        lines = _canary_lines(rng, count)

        if suffix == ".json":
            new_text = self._poison_json(text, lines)
            if new_text is None:
                return StrategyResult(
                    data=None, notes=["json top level is not an object"]
                )
        else:
            prefix, closing = _comment_style(suffix)
            body = [f"{prefix}{_MARKER} honeypot markers{closing}"]
            body.extend(f"{prefix}{line}{closing}" for line in lines)
            # The trailer closes the block this strategy appends, and it
            # checksums exactly those bytes, so a later edit anywhere in the
            # file invalidates it and hardening resumes.
            payload = ("\n".join(body) + "\n").encode("utf-8")
            trailer = trailer_line(_MARKER, payload, prefix=prefix, suffix=closing)
            new_text = _append(text, payload.decode("utf-8") + trailer)
            if suffix == ".py":
                try:
                    ast.parse(new_text)
                except SyntaxError:
                    return StrategyResult(
                        data=None, notes=["python parse failed; skipped"]
                    )

        new_bytes = new_text.encode("utf-8")
        event = self._event(
            file_path,
            data,
            new_bytes,
            f"injected {count} canary marker(s)",
            severity="low",
            canaries=count,
        )
        return StrategyResult(data=new_bytes, events=[event])

    def _poison_json(self, text: str, lines: list[str]) -> str | None:
        """Add the top-level canary key only when round-trip stays valid."""
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return None
        if not isinstance(payload, dict):
            return None
        payload[_JSON_KEY] = list(lines)
        payload[_JSON_TRAILER_KEY] = json_trailer_value(
            _MARKER, payload, key=_JSON_TRAILER_KEY, data_key=_JSON_KEY
        )
        serialized = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
        try:
            json.loads(serialized)
        except json.JSONDecodeError:
            return None
        return serialized
