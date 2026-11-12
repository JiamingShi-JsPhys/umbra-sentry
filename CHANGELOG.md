# Changelog

## 1.0.0 — 2026-11-12

First public baseline. `umbra-sentry` hardens a release directory against
automated reverse-engineering agents; it is a defensive tool for artifacts you
own, not a guarantee that the artifact cannot be reversed.

### Added

- **Chain-of-responsibility pipeline** (`core/pipeline.py`): strategies run in
  a deterministic phase order (AUDIT → POISON → EXHAUST → HALLUCINATE →
  VERIFY → RESPONSE); a failing strategy yields a `FAILED` event and the chain
  continues.
- **Five strategies**: `poison-canary`, `exhaust-budget`,
  `hallucinate-shadow`, `native-poison`, `native-exhaust`.
- **`umbra-harden` CLI**: directory discovery, `--out` report,
  `--sigma`/`--ocsf` telemetry export, `--seed` and `--intensity`.
- **Typed IR and adapters**: `HardeningEvent`, `Decision`, `HardeningReport`;
  OCSF v1.5.0 Detection Findings (`class_uid` 2004) and deterministic Sigma
  YAML projection.
- **Event-driven response**: asyncio `EventBus` with backpressure and a
  dead-letter list, a severity decider, and a bouncer that executes only
  decisions approved by the HITL gate.
- **Fail-closed HITL gate**: `PENDING → APPROVED / DENIED / TIMED_OUT`;
  timeout or channel failure denies by default.
- **Optional Rust native kernel** (`defense/native/umbra-native`): zero-
  dependency `cdylib` + CLI for compiled/object artifacts, driven through a
  `ctypes` FFI bridge with a subprocess fallback. Without a build, both native
  strategies emit audited `SKIPPED` events and leave the artifact untouched.
- **Deterministic hardening**: the same seed and input produce byte-identical
  output, so the result is attestable.
- **Tests**: 164 collected; 156 pass and 8 native tests skip when the Rust
  kernel is not built. `ruff check .` passes and `claude plugin validate`
  passes (one icon warning).

### Supported artifacts

- Semantic strategies: `.py`, `.js`, `.ts`, `.json` (canaries also `.toml`,
  `.cfg`, `.ini`, `.md`).
- Native strategies, when built: `.exe`, `.dll`, `.so`, `.dylib`, `.bin`,
  `.elf`, `.o`, `.a`, `.lib`, `.node`.
- Other files pass through untouched and produce no events.

### Known limitations

- **Not a security guarantee.** A patient human reverse engineer can untangle
  every layer; the target is automated analysis, not skilled manual RE.
- Canaries are synthetic, exhaust layers are bounded, and shadow logic is
  appended but never called. No formal runtime-equivalence proof is performed;
  test your build after hardening.
- Sigma rules audit your own hardening activity, not arbitrary third-party
  threats; the OCSF projection covers Detection Findings only.
- The native kernel is optional. Without it, compiled artifacts are not
  hardened. On Windows, the MSVC target needs the Visual Studio C++ build
  tools (`link.exe`); `cargo check --release` still type-checks without them.

### Install

```bash
git clone https://github.com/JiamingShi-JsPhys/umbra-sentry.git
cd umbra-sentry
python -m pip install -e .
umbra-harden --help
```

Claude Code plugin route:

```text
/plugin marketplace add https://github.com/JiamingShi-JsPhys/umbra-sentry.git#v1.0.0
/plugin install umbra-sentry@umbra-sentry-marketplace
```

### License

Apache-2.0. See [LICENSE](LICENSE).
