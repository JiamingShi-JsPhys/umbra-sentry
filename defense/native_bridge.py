"""Python bridge to the optional Rust hardening kernel.

Binary-targeting strategies (``defense/native_strategies.py``) cannot reuse the
text-oriented Python transform, so they delegate to ``umbra-native``: a
zero-dependency Rust ``cdylib`` reached over a C ABI.  Two transports are tried
in order:

1. **FFI** — ``ctypes`` loads the shared library and calls the four exported
   functions directly (lowest overhead, no process spawn).
2. **CLI** — the same kernel is built as a standalone binary and driven over
   stdin/stdout when the shared library is absent or unloadable.

If neither is available, ``get_engine()`` returns ``None`` and the strategies
degrade to an audited skip — the pipeline never breaks because a toolchain is
missing.

Concept inspired by: Anchor (AnimusLab) — compiled Rust kernel behind a Python
orchestration layer
"""

from __future__ import annotations

import ctypes
import functools
import os
import subprocess
from pathlib import Path

__all__ = [
    "INTENSITY_TO_ID",
    "NativeCliEngine",
    "NativeEngine",
    "NativeEngineError",
    "find_native_cli",
    "find_native_library",
    "get_engine",
    "reset_engine_cache",
]

#: The kernel speaks integer intensities; the Python API speaks preset names.
INTENSITY_TO_ID: dict[str, int] = {
    "stealth": 0,
    "balanced": 1,
    "maximum": 2,
    "bankrupt": 3,
}

_NATIVE_DIR = Path(__file__).resolve().parent / "native" / "umbra-native"
_RELEASE_DIR = _NATIVE_DIR / "target" / "release"
_LIBRARY_NAMES = ("umbra_native.dll", "libumbra_native.so", "libumbra_native.dylib")
_CLI_NAMES = ("umbra-native.exe", "umbra-native")

_U64_MASK = 0xFFFFFFFFFFFFFFFF


class NativeEngineError(RuntimeError):
    """Native kernel missing, unloadable, or returning a bad result."""


def _first_existing(candidates: list[Path]) -> Path | None:
    """Return the first regular file among ``candidates``, else ``None``."""
    for candidate in candidates:
        try:
            if candidate.is_file():
                return candidate
        except OSError:  # pragma: no cover - defensive against broken mounts
            continue
    return None


def find_native_library() -> Path | None:
    """Locate the compiled shared library.

    ``UMBRA_NATIVE_LIB`` wins when it points at a file; otherwise the cargo
    release directory is probed for the platform's library name.  Never raises:
    an absent kernel is a supported state.
    """
    override = os.environ.get("UMBRA_NATIVE_LIB")
    if override:
        path = Path(override)
        if path.is_file():
            return path
    return _first_existing([_RELEASE_DIR / name for name in _LIBRARY_NAMES])


def find_native_cli() -> Path | None:
    """Locate the standalone ``umbra-native`` binary (subprocess fallback)."""
    override = os.environ.get("UMBRA_NATIVE_BIN")
    if override:
        path = Path(override)
        if path.is_file():
            return path
    return _first_existing([_RELEASE_DIR / name for name in _CLI_NAMES])


class NativeEngine:
    """``ctypes`` FFI transport over the Rust ``cdylib``.

    Every exported function has its ``argtypes`` / ``restype`` pinned in
    ``_declare_signatures``; ctypes' default int conversion is unsafe for
    pointers and 64-bit seeds.
    """

    def __init__(self, library_path: Path | None = None) -> None:
        self._path = library_path if library_path is not None else find_native_library()
        if self._path is None:
            raise NativeEngineError("umbra_native shared library not found")
        try:
            self._lib = ctypes.CDLL(str(self._path))
        except OSError as exc:
            raise NativeEngineError(f"cannot load native library {self._path}: {exc}") from exc
        try:
            self._declare_signatures()
        except AttributeError as exc:
            raise NativeEngineError(
                f"native library {self._path} is missing a required symbol: {exc}"
            ) from exc

    def _declare_signatures(self) -> None:
        """Pin the C ABI surface declared in ``umbra-native/src/lib.rs``."""
        lib = self._lib

        lib.umbra_engine_version.argtypes = []
        lib.umbra_engine_version.restype = ctypes.c_char_p

        # (const u8 *data, size_t len, u64 seed, u32 intensity, size_t *out_len)
        binary_args = [
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_uint64,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        lib.umbra_poison_binary.argtypes = binary_args
        lib.umbra_poison_binary.restype = ctypes.c_void_p
        lib.umbra_exhaust_binary.argtypes = binary_args
        lib.umbra_exhaust_binary.restype = ctypes.c_void_p

        # (u8 *ptr, size_t len) — len must be the exact out_len we received.
        lib.umbra_free_buffer.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        lib.umbra_free_buffer.restype = None

    @property
    def mode(self) -> str:
        return "ffi"

    @property
    def version(self) -> str:
        """Read the kernel's static version banner."""
        try:
            raw = self._lib.umbra_engine_version()
        except (OSError, AttributeError) as exc:
            raise NativeEngineError(f"umbra_engine_version failed: {exc}") from exc
        if not raw:
            return "unknown"
        return raw.decode("utf-8", "replace")

    def poison(self, data: bytes, seed: int, intensity: str) -> bytes:
        """Append the canary decoy blob; returns the complete new artifact."""
        return self._invoke("poison", self._lib.umbra_poison_binary, data, seed, intensity)

    def exhaust(self, data: bytes, seed: int, intensity: str) -> bytes:
        """Append seeded dead weight; returns the complete new artifact."""
        return self._invoke("exhaust", self._lib.umbra_exhaust_binary, data, seed, intensity)

    def _invoke(
        self,
        verb: str,
        function: object,
        data: bytes,
        seed: int,
        intensity: str,
    ) -> bytes:
        """Run one FFI transform and always release the returned buffer.

        The Rust side allocates a new ``Vec<u8>`` and transfers ownership; the
        ``finally`` block frees it with the exact reported length, including on
        error paths, so a failed transform cannot leak.
        """
        if not isinstance(data, (bytes, bytearray)) or not data:
            raise NativeEngineError(f"{verb}: input must be a non-empty bytes object")
        intensity_id = INTENSITY_TO_ID.get(str(intensity).lower())
        if intensity_id is None:
            raise NativeEngineError(f"{verb}: unknown intensity {intensity!r}")

        input_buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(bytes(data))
        out_len = ctypes.c_size_t(0)
        out_ptr: int | None = None
        try:
            out_ptr = function(  # type: ignore[operator]
                ctypes.cast(input_buffer, ctypes.c_void_p),
                ctypes.c_size_t(len(data)),
                ctypes.c_uint64(int(seed) & _U64_MASK),
                ctypes.c_uint32(intensity_id),
                ctypes.byref(out_len),
            )
            if not out_ptr:
                raise NativeEngineError(f"{verb}: native kernel returned null")
            return ctypes.string_at(out_ptr, out_len.value)
        except OSError as exc:
            raise NativeEngineError(f"{verb}: FFI call failed: {exc}") from exc
        finally:
            if out_ptr:
                try:
                    self._lib.umbra_free_buffer(out_ptr, out_len.value)
                except OSError:
                    # Freeing must never mask the original outcome.
                    pass


class NativeCliEngine:
    """Subprocess transport over the standalone ``umbra-native`` binary."""

    def __init__(self, cli_path: Path | None = None) -> None:
        self._path = cli_path if cli_path is not None else find_native_cli()
        if self._path is None:
            raise NativeEngineError("umbra-native CLI binary not found")
        self._version: str | None = None

    @property
    def mode(self) -> str:
        return "cli"

    @property
    def version(self) -> str:
        """Parse ``umbra-native --version`` once, then cache the banner."""
        if self._version is None:
            try:
                proc = subprocess.run(
                    [str(self._path), "--version"],
                    capture_output=True,
                    check=False,
                )
            except OSError as exc:
                raise NativeEngineError(f"cannot execute {self._path}: {exc}") from exc
            self._version = proc.stdout.decode("utf-8", "replace").strip() or "unknown"
        return self._version

    def poison(self, data: bytes, seed: int, intensity: str) -> bytes:
        return self._run("poison", data, seed, intensity)

    def exhaust(self, data: bytes, seed: int, intensity: str) -> bytes:
        return self._run("exhaust", data, seed, intensity)

    def _run(self, verb: str, data: bytes, seed: int, intensity: str) -> bytes:
        if not data:
            raise NativeEngineError(f"{verb}: input must be non-empty")
        intensity_name = str(intensity).lower()
        if intensity_name not in INTENSITY_TO_ID:
            raise NativeEngineError(f"{verb}: unknown intensity {intensity!r}")
        try:
            proc = subprocess.run(
                [str(self._path), verb, str(int(seed) & _U64_MASK), intensity_name],
                input=bytes(data),
                capture_output=True,
                check=False,
            )
        except OSError as exc:
            raise NativeEngineError(f"{verb}: cannot execute {self._path}: {exc}") from exc
        if proc.returncode != 0:
            stderr = proc.stderr.decode("utf-8", "replace").strip()
            raise NativeEngineError(
                f"{verb}: native CLI exited {proc.returncode}: {stderr or 'no stderr'}"
            )
        if not proc.stdout:
            raise NativeEngineError(f"{verb}: native CLI produced empty output")
        return proc.stdout


@functools.lru_cache(maxsize=1)
def get_engine() -> NativeEngine | NativeCliEngine | None:
    """Return the best available engine, or ``None``; cached per process."""
    try:
        return NativeEngine()
    except NativeEngineError:
        pass
    try:
        return NativeCliEngine()
    except NativeEngineError:
        return None


def reset_engine_cache() -> None:
    """Drop the cached engine (tests, and after rebuilding the kernel)."""
    get_engine.cache_clear()
