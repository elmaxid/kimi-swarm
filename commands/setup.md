---
description: Configure the [secondary_model] subagent model pool, with a thinking effort per model, in config.toml
---

Set up the Kimi Swarm subagent model pool in the user's `config.toml`, including the thinking effort
each pool model runs with.

How effort works in the engine (verified in the binary):

- A subagent's effort is `[secondary_model].default_effort` if set, otherwise the `default_effort`
  declared on the chosen alias in `[models]`. The `Agent` tool has no effort parameter.
- A single global `default_effort` therefore cannot differ per model, and it is validated against
  every pool alias at startup (a model that does not support it fails the whole session).
- Per-model effort is done with **effort variants**: an extra `[models."<alias>@<effort>"]` entry that
  copies the base alias (same `provider`, `model`, `max_context_size`, `capabilities`,
  `support_efforts`, ...) and adds `default_effort = "<effort>"`. The variant goes in the pool, and
  the orchestrator picks it with the `model` parameter. Do not set the global `default_effort` in
  this mode, because it would override every variant.

Steps:

1. Locate the config file. It is `$KIMI_CODE_HOME/config.toml`, defaulting to
   `~/.kimi-code/config.toml`.
2. List the model aliases and their supported efforts, without dumping any secrets (never print
   `api_key` lines or whole provider blocks). Run, adjusting the path if `KIMI_CODE_HOME` is set:
   `awk '/^\[models\."/{a=$0} /^support_efforts/{print a " " $0}' ~/.kimi-code/config.toml`
3. Check whether a `[secondary_model]` section already exists. If it does, read it and propose an
   update instead of appending a second section. Also note any existing `@<effort>` variants.
4. Propose the routing table: one row per persona, each with an alias **and an effort**. Defaults to
   suggest, adjusting to what each model supports:
   - worker / audit-hunter: fast alias, `low` or `medium` (this alias is `default_model`)
   - review / audit-verifier: strong reasoning alias, `high`
   - architect: strongest alias, `max` (or the highest the model supports)
   - security: alias from a different family than the reviewer, `high`
   Ask the user for the effort of each row; do not assume the defaults are accepted.
5. Validate every chosen effort against that alias's `support_efforts`. If it is not listed, say so
   and ask for another one; never write an unsupported effort. If `thinking.enabled = false` in
   `config.toml`, warn that efforts are ignored.
6. Build the exact TOML. For each (alias, effort) pair that is not already the alias's own default,
   a variant block copying the base alias fields, e.g.:

   ```toml
   [models."litellm/claude-opus-5@max"]
   provider = "litellm"
   model = "claude-opus-5"
   max_context_size = 262144
   capabilities = [ "thinking", "tool_use" ]
   support_efforts = [ "none", "minimal", "low", "medium", "high", "xhigh", "max" ]
   default_effort = "max"

   [secondary_model]
   default_model = "litellm/deepseek-v4.1-flash@low"

   [secondary_model.models]
   "litellm/deepseek-v4.1-flash@low" = "Worker rápido, effort low."
   "litellm/claude-opus-5@max"       = "Review/arquitectura, effort max."
   ```

   Pool descriptions must state the effort, because the orchestrator only sees the description.
   Copy the base fields verbatim from the user's existing block; if the base block has a field not
   shown above, keep it.
7. Show the whole block (variants plus pool) and ask for confirmation. Before writing, make a
   timestamped backup of `config.toml`. Then append or edit only the new `[models."...@..."]`
   entries and the `[secondary_model]` section; never modify any other part of the file.

Constraints to respect and state to the user:

- Every pool alias must resolve to a configured `[models]` entry, or session startup fails loudly.
- `default_model` is required when a `models` table is present, and must be one of its keys.
- `force = true` requires `default_model` and cannot be combined with a `models` table. In force
  mode there is one model for all subagents, so a global `default_effort` is the right tool there.
- A global `[secondary_model].default_effort` is an alternative only if the user wants the same
  effort for every model; it must be supported by every pool alias, and it overrides any variant.
- The pool is always active; there is no experimental flag to enable, and the
  `KIMI_SECONDARY_MODEL` / `KIMI_SECONDARY_EFFORT` environment variables are not a supported way to
  configure this.

Finish by telling the user to run `/reload` or start a new session, that the `Agent` tool will then
expose a `model` parameter listing each variant with its effort, and how to verify: spawn one
subagent with a variant and check its reported thinking level.

Optional context from the user: $ARGUMENTS
