# Install commands

Every command for the Claude Code plugin route and the manual clone/build path.
Methods 1 and 3 stay in the README: [umbra-sentry](../README.md) · [简体中文](INSTALL_COMMANDS_zh.md)

## Method 2: install with commands

**Claude Code** — from your shell (v2.1.292+), marketplace and install in one step:

```bash
claude plugin install umbra-sentry --marketplace https://github.com/JiamingShi-JsPhys/umbra-sentry.git
```

**Claude Code** — from inside a session (v2.1.275+), add the marketplace from the URL first, pinned to the release tag:

```text
/plugin marketplace add https://github.com/JiamingShi-JsPhys/umbra-sentry.git#v1.0.0
```

Then install the entry it lists:

```text
/plugin install umbra-sentry@umbra-sentry-marketplace
```

**Manual clone** — the plugin ships the `harden` skill; the pipeline itself is a Python package. From a clone:

```bash
git clone https://github.com/JiamingShi-JsPhys/umbra-sentry.git
cd umbra-sentry
python -m pip install -e .
```

The native kernel is optional:

```bash
cd defense/native/umbra-native && cargo build --release && cd ../../..
```

Without it, `native-poison` and `native-exhaust` emit an audited `SKIPPED` event and leave compiled artifacts untouched.

## Requirements

- Python 3.12+.
- Pydantic 2.7+ and PyYAML 6.0+ (installed by `pip install -e .`).
- Rust stable, optional, only for the native kernel.

## Which route should I use?

| Route | Gives you | Needs |
| --- | --- | --- |
| Plugin + clone | the `harden` skill and the CLI | Python package; Rust for the native kernel |
| Plugin only | the skill, but not a working CLI | a clone and `pip install -e .` |
| Manual clone | CLI and Python API, no plugin skill | Python package |
