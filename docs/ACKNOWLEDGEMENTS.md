# Acknowledgements

People and projects that changed this project, with what they contributed.
The README carries the short list; this page carries the detail.

**English** · [简体中文](ACKNOWLEDGEMENTS_zh.md)

## Contributors

No external issue reporters or code contributors yet. When a report changes the project, the person is listed here with the issue or pull request link and the change it caused.

## Architecture and research inspiration

- **bla** — counter-REA shield concepts (canary, budget exhaustion, shadow logic).
- **py-ocsf-models** — typed OCSF models.
- **sigma-cli / pySigma** — Sigma rule emission.
- **CrowdSec** — detector / decider / bouncer decoupling.

All implementations in umbra-sentry are original; no source code was copied from these projects.

## Security references

- **OWASP MASTG** — Android anti-reversing defenses and the "no 100% protection" framing.
- **Check Point Research, Anti-Debug Tricks** — Windows anti-debug technique taxonomy.
- **al-khaser** — an anti-debug / anti-VM test catalogue used to cross-check coverage.

These references informed the threat model and the test cases; they are not vendored dependencies.
