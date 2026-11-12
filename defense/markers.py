"""Structural idempotence trailers for text and JSON artifacts.

This is the pure-Python mirror of ``engine.rs::has_trailer``.  Every text
strategy marks the bytes it appended with a trailer line::

    <comment-prefix><marker>:<payload-len>:<fnv1a64(payload) as 16 hex><suffix>

Why: the strategies used to skip work whenever their marker appeared
*anywhere* in the artifact.  One pasted comment line — by the artifact's own
author, by a reviewer, or by an adversary — therefore turned hardening into a
no-op.  A marker now only counts where this package writes it: on a line
carrying the length and checksum of the exact bytes it describes.  A bare
mention never does, because it cannot satisfy the checksum.

The lookup walks backwards from EOF rather than insisting on the last line.
Strategies run as a chain (poison -> exhaust -> hallucinate) and each appends
its own trailer, so the earlier trailer stops being the file's last line as
soon as a later strategy has run; a strictly tail-anchored check would then
re-apply every strategy on every run and grow the artifact without bound.  The
checksum — not the position — is the guard: a trailer is accepted only when
the ``payload-len`` bytes immediately before it hash to its tag.  Editing the
block it describes therefore invalidates it, while an unrelated block appended
afterwards does not.

This is an idempotence check, **not** proof of authenticity: anyone able to
rewrite the artifact can also recompute the trailer.  It answers "did this
strategy already append its payload here", not "was this artifact produced by
us".

For JSON artifacts the same idea is carried in a sibling key holding the
checksum of the strategy's own payload — the value stored under the payload
key, not the whole document — so a later strategy adding its own sibling keys
does not invalidate it.
"""

from __future__ import annotations

import json
from typing import Any

__all__ = [
    "fnv1a64",
    "has_json_trailer",
    "has_trailer",
    "json_trailer_value",
    "trailer_line",
]

_FNV_OFFSET_BASIS = 0xCBF29CE484222325
_FNV_PRIME = 0x100000001B3
_FNV_MASK = 0xFFFFFFFFFFFFFFFF

# Comment wrappers this package writes, longest prefix first so ``<!-- `` wins
# over ``<!--``.  ``has_trailer`` strips exactly these; anything else is not a
# line this package could have written.
_WRAPPERS: tuple[tuple[str, str], ...] = (
    ("<!-- ", " -->"),
    ("<!--", "-->"),
    ("// ", ""),
    ("//", ""),
    ("# ", ""),
    ("#", ""),
    ("; ", ""),
    (";", ""),
)

_HEX_DIGITS = frozenset(b"0123456789abcdef")


def fnv1a64(payload: bytes) -> int:
    """FNV-1a (64-bit) over ``payload`` — the trailer's structural checksum."""
    value = _FNV_OFFSET_BASIS
    for byte in payload:
        value ^= byte
        value = (value * _FNV_PRIME) & _FNV_MASK
    return value


def trailer_line(
    marker: str, payload: bytes, *, prefix: str = "# ", suffix: str = ""
) -> str:
    """Render the trailer line for ``payload`` as ``marker``'s last line.

    The result ends with ``\\n`` and is meant to be appended *immediately*
    after ``payload`` (which must itself end with ``\\n``), so the bytes
    between the preceding newline and the trailer are exactly ``payload``.
    """
    if "\n" in marker:
        raise ValueError("marker must not contain a newline")
    return f"{prefix}{marker}:{len(payload)}:{fnv1a64(payload):016x}{suffix}\n"


def _unwrap(line: bytes) -> bytes | None:
    """Strip a comment wrapper this package writes, if present."""
    for prefix, suffix in _WRAPPERS:
        start = len(prefix.encode())
        end = len(suffix.encode())
        if len(line) < start + end:
            continue
        if not line.startswith(prefix.encode()):
            continue
        if suffix and not line.endswith(suffix.encode()):
            continue
        return line[start : len(line) - end] if end else line[start:]
    return None


def _verify_trailer_at(data: bytes, line_start: int, line_end: int, marker: bytes) -> bool:
    """True when ``data[line_start:line_end]`` is a valid trailer for ``marker``.

    Validity means: the line unwraps to ``<marker>:<len>:<16 hex>`` and the
    ``len`` bytes immediately preceding ``line_start`` hash to that tag.  Byte
    based on purpose — text strategies operate on UTF-8 source files where a
    character offset and a byte offset diverge, and the trailer records a
    *byte* length.
    """
    core = _unwrap(data[line_start:line_end])
    if core is None:
        return False

    head = marker + b":"
    if not core.startswith(head):
        return False
    rest = core[len(head) :]

    colon = rest.find(b":")
    if colon < 0:
        return False
    len_field, tag_field = rest[:colon], rest[colon + 1 :]

    if not len_field or len(len_field) > 20 or not len_field.isdigit():
        return False
    if len(tag_field) != 16:
        return False
    if any(byte not in _HEX_DIGITS for byte in tag_field):
        return False

    payload_len = int(len_field)
    # Unlike ``engine.rs`` the payload is an arbitrary block and need not
    # contain the marker, so there is no ``marker.len()`` lower bound; the
    # checksum below is the real guard.  An empty payload is still refused.
    if payload_len == 0:
        return False
    # ``trailer_line`` is appended immediately after the payload block, and
    # that block ends with its own newline, so the payload occupies exactly
    # the bytes ending where the trailer line starts.  (``engine.rs`` inserts
    # a dedicated separator newline instead, which is why its slice ends one
    # byte earlier; both forms checksum the bytes the writer appended.)
    if payload_len > line_start:
        return False

    payload = data[line_start - payload_len : line_start]
    return fnv1a64(payload) == int(tag_field, 16)


def _has_trailer_bytes(data: bytes, marker: bytes) -> bool:
    """True when ``data`` carries any valid trailer line for ``marker``.

    Scans backwards from EOF, hopping between occurrences of the marker: a
    bare mention is examined once, fails the checksum, and is skipped.  Work
    is bounded by the number of times the marker appears in the artifact.
    """
    search_end = len(data)
    while search_end > 0:
        index = data.rfind(marker, 0, search_end)
        if index < 0:
            return False
        line_start = data.rfind(b"\n", 0, index) + 1
        newline = data.find(b"\n", index)
        line_end = len(data) if newline < 0 else newline
        if _verify_trailer_at(data, line_start, line_end, marker):
            return True
        search_end = index
    return False


def has_trailer(text: str, marker: str) -> bool:
    """True when ``text`` carries a well-formed trailer for ``marker``.

    A bare occurrence of the marker — in a comment, a string literal, or a
    decoy the artifact's author left behind — is not evidence that this
    package ran, and must not suppress hardening.
    """
    if "\n" in marker:
        raise ValueError("marker must not contain a newline")
    return _has_trailer_bytes(text.encode("utf-8"), marker.encode("utf-8"))


def json_trailer_value(
    marker: str,
    document: dict[str, Any],
    *,
    key: str,
    data_key: str,
) -> str:
    """Trailer string for a JSON document, storing no file bytes at all.

    The checksum covers the strategy's own payload — the value stored under
    ``data_key`` — and nothing else.  Hashing the whole document instead would
    make the trailer depend on keys a *later* strategy adds, so every run
    would invalidate the earlier strategy's trailer and re-apply it.  ``key``
    is accepted for symmetry with :func:`has_json_trailer`, which needs it to
    locate the sibling trailer and must agree on both names.

    The payload is hashed, never the trailer key itself, so the value is
    stable across the write/read round trip and can be recomputed by anyone
    holding the document.
    """
    payload = json.dumps(
        document.get(data_key),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return f"{marker}:{len(payload)}:{fnv1a64(payload):016x}"


def has_json_trailer(
    document: dict[str, Any],
    marker: str,
    *,
    key: str,
    data_key: str,
) -> bool:
    """True when ``document`` carries a trailer this package wrote for it."""
    stored = document.get(key)
    if not isinstance(stored, str):
        return False
    expected = json_trailer_value(marker, document, key=key, data_key=data_key)
    return stored == expected
