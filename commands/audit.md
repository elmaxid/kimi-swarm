---
description: Run the full Cloudflare security-audit workflow over a target codebase
---

Run the vendored `security-audit` skill (see `skills/security-audit/SKILL.md`) over a target
codebase, in full audit mode.

Target: $ARGUMENTS. If no target is given, ask for the repository root before starting.

Before delegating:

1. Confirm the mode. Full audit mode is for an explicit "audit this codebase" or pen-test request;
   a focused security question stays in guidance mode and creates no artifacts.
2. Confirm whether an **OS-enforced sandbox** is available. Unless it is, run **static-only**: read
   source and record every execution-dependent candidate as `needs_validation`. Never execute
   target-controlled code without the sandbox controls the skill requires.
3. Check that `node` is available for `validate-findings.cjs` and `validate-coverage-ledger.cjs`
   (Phases 4–5). If it is missing, report it as a run blocker instead of claiming a passing
   validation.
4. Resolve the skill directory (this plugin's `skills/security-audit`), the target root, the repo
   name, and an output directory **outside** the target (default `~/security-audit-skill/<repo>/run-<N>`).

Then follow the skill's six phases in order:
reconnaissance → coverage-led hunting waves → candidate validation → structured output →
independent record verification → target-neutral report.

Delegation bindings for Kimi:

- Hunters: `Agent`/`AgentSwarm` with `subagent_type: "audit-hunter"` and a fast model alias from the
  `[secondary_model]` pool.
- Reconnaissance agents (Phase 1, also the `audit-verifier` role) may use the **fast** alias: they
  run four in parallel and mostly read source.
- Candidate validation (Phase 3) and record verification (Phase 5): `subagent_type: "audit-verifier"`
  with a **strong alias from a different model family** than the hunter. This is where independence
  pays off, so do not economize here.
- The same persona can take different models in different phases — that is expected and correct.
- `AgentSwarm` is homogeneous: use it for parallel hunter waves over independent units, and separate
  `Agent` calls when a phase mixes roles.
- The parent alone writes the run artifacts; `audit-hunter` and `audit-verifier` have no `Write` or
  `Edit` access.

Finish with the skill's terminal states only: either all report artifacts are written and both
validators pass, or `run_status: "incomplete"` is recorded with its exact reason and the gap is
disclosed. Relay the report path and the coverage statement to the user.
