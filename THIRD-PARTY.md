# Third-party components

## cloudflare/security-audit-skill

Files under `skills/security-audit/` are vendored from
[cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill).

- License: MIT, Copyright (c) 2025-2026 Cloudflare, Inc. (see the upstream `LICENSE`).
- Upstream path: `skills/security-audit/`.
- Modifications: platform terminology adapted for Kimi Code (`general` → `audit-hunter`,
  `research` → `audit-verifier`, `Task tool` → `Agent tool`), plus an added "Kimi Code binding"
  section in `SKILL.md` describing how to map the workflow onto Kimi's `Agent`/`AgentSwarm` tools,
  the `[secondary_model]` pool, and the static-only default.
- Ports added (new files, upstream untouched): `validate-findings.py`, `validate-coverage-ledger.py`,
  `_validate_common.py` are Python 3 stdlib ports of the two `.cjs` validators; `test_validators.py`
  and `differential_test.py` are ports/new tests. Verified equivalent to the Node originals (65/65
  conformance, 273/273 byte-identical differential). The `.cjs` files remain the source of truth.

To update from upstream, re-copy `skills/security-audit/` from a fresh clone, re-apply the
terminology substitutions, re-add the binding section, and re-run `differential_test.py` against a
Node oracle to confirm the Python ports still match the updated `.cjs`.
