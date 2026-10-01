---
description: Run a security audit with the swarm-security persona on an independent model
---

Delegate a security audit to the `swarm-security` subagent on a model from a different family than
the reviewer.

1. Determine the scope: $ARGUMENTS
   If none is given, audit the current change (prefer `git diff`, otherwise the diff against the
   default branch), plus any dependency manifest that changed.
2. From the `[secondary_model]` pool, choose a strong alias from a different model family than the
   one used for reviews, so the blind spots do not overlap. If there is no pool, tell the user to run
   `/kimi-swarm:setup` and proceed without a model override.
3. Call the `Agent` tool once with `subagent_type: "swarm-security"` and the chosen `model`. Give the
   scope and the exact commands to obtain the diff; the subagent cannot see this conversation.
4. Relay the findings ranked by severity, with attack scenario and remediation, and state which
   model performed the audit. Do not execute any suggested remediation without asking.
