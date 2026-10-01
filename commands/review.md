---
description: Delegate a code review to the swarm-review persona on a strong model
---

Delegate a code review to the `swarm-review` subagent running on a strong model from the pool.

1. Determine what to review: $ARGUMENTS
   If no target is given, use the current change: prefer `git diff` for uncommitted work, otherwise
   the diff against the default branch (`git diff main...HEAD` or `git diff master...HEAD`).
2. From the `[secondary_model]` pool, choose the strongest reasoning alias (not the worker
   `default_model`). If there is no pool, tell the user to run `/kimi-swarm:setup` and proceed
   without a model override.
3. Call the `Agent` tool once with `subagent_type: "swarm-review"` and the chosen `model`. Put the
   diff, or the exact command to obtain it plus the file list, in the prompt — the subagent cannot
   see this conversation.
4. Relay the findings to the user grouped by severity, without softening or re-ranking them, and
   state which model performed the review.
