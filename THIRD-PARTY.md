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

To update from upstream, re-copy `skills/security-audit/` from a fresh clone and re-apply those
substitutions, then re-add the binding section.
