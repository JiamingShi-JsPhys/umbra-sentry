---
name: harden
description: >-
  Harden a release artifact or directory against AI reverse-engineering
  agents using the umbra-sentry semantic defense pipeline. Use when the user
  asks to protect, harden, or obfuscate their own build outputs.
---

# umbra-sentry: harden

Run the umbra-sentry pipeline over the user's build output (the installed
console script works from any directory; `python <repo>/cli.py` only works
from the repository root):

```bash
umbra-harden <target> --out umbra-report.json --intensity balanced
```

With Sigma + OCSF export:

```bash
umbra-harden <target> --sigma sigma-rules/ --ocsf ocsf-findings/ --out umbra-report.json
```

Interpret the report: `applied_events` lists what was done;
`modified_artifacts` lists what changed on disk; `decisions` lists HITL-gated
remediations awaiting human approval. Never approve a quarantine decision
without the user's explicit confirmation.
