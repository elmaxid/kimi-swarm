---
description: Interactive wizard to configure the [secondary_model] pool, choosing model and thinking effort per role. Modes - quick, effort, or one role (worker, reviewer, architect, security)
argument-hint: "[quick | effort | worker | reviewer | architect | security]"
---

Run an interactive wizard that configures the Kimi Swarm subagent pool in the user's `config.toml`.
For each role the user picks a model family, then a model, then an effort, using `AskUserQuestion`. Ask in the user's
language. Never ask the user to type a config block; you build and write it.

How effort works in the engine (verified in the binary):

- A subagent's effort is `[secondary_model].default_effort` if set, otherwise the `default_effort`
  declared on the chosen alias in `[models]`. The `Agent` tool has no effort parameter.
- A global `default_effort` cannot differ per model and is validated against every pool alias at
  startup, so the wizard never sets it.
- Per-model effort is done with **effort variants**: an extra `[models."<alias>@<effort>"]` entry that
  copies the base alias and adds `default_effort = "<effort>"`. The variant goes in the pool and the
  orchestrator picks it with the `model` parameter.

## Keeping the catalog in sync

The wizard only reads `[models]`; it never queries the gateway, and it must not. A model the gateway
announces but `config.toml` is missing has no alias to offer, and inventing one by hand is how a
`max_context_size` ends up missing (the engine refuses to start a model without a positive one). So
before the wizard, run `/kimi-swarm:sync` (or `scripts/sync-models.py --dry-run` and then `--apply`
with the printed plan hash). It previews the diff, adds the missing blocks, and —with
`--refresh-metadata`— widens existing blocks without ever removing a capability.

The division of labour: **sync owns the `[models.*]` catalog**, **the wizard owns the
`[secondary_model]` pool and the `@effort` variants**. Sync never creates a variant and never edits
the pool; it only checks that `default_effort ∈ support_efforts` still holds in each base+variant
group, and omits the changes of a group that breaks it.

## Roles

| Role | Personas it serves | Notes |
| --- | --- | --- |
| worker | `swarm-worker`, `audit-hunter` | becomes `default_model`; fast model |
| reviewer | `swarm-review`, `audit-verifier` | strong reasoning model |
| architect | `swarm-architect` | strongest model |
| security | `swarm-security` | must be from a different family than the reviewer |

Ask the roles in this order, because security depends on the reviewer's choice.

## Modes

Read the first word of `$ARGUMENTS` (below) to pick a mode. Anything else in `$ARGUMENTS` is plain
context. With no recognised word, run the full wizard.

| Argument | What it does |
| --- | --- |
| *(none)* / `full` | Full wizard: family, model and effort for every role. |
| `quick` | Keep each role's current alias and current effort; use the recommended effort only for a role that has none. No questions until the confirmation. |
| `effort` | Keep each role's current alias and ask only the effort question, once per role. |
| `worker`, `reviewer`, `architect`, `security` | Redo that role's three questions and keep the other roles as they are. |

How a role's *current alias* is found: the worker is `[secondary_model].default_model`; for the other
roles, match the pool descriptions (role word such as review/verificación, arquitectura, security) and
take the base alias of that entry. If a role has no current alias, ask that role's family and model
questions even in `quick` and `effort`.

Mode rules:

- A role's current effort is the `default_effort` of its current pool variant. `quick` keeps it;
  the recommended table in step 3 applies only to roles with no effort yet (and in `effort` mode it
  only marks the `(Recommended)` option). `quick` skips the family, model, effort and cleanup questions; it keeps existing base pool
  entries as they are (it does not remove anything) and goes straight to step 5, then confirmation.
- A single-role mode keeps the other roles' current alias and effort untouched. For `security`, the
  reviewer's family is taken from the current reviewer alias.
- Steps 1, 2 (only if a family question will be asked), 5 to 8 always run. The confirmation in step 6
  is never skipped, in any mode.
- The worker safeguard below applies in every mode.

## Steps

1. **Read the state.** The config is `$KIMI_CODE_HOME/config.toml`, default `~/.kimi-code/config.toml`.
   Never print `api_key` lines or whole provider blocks. Run:
   `awk '/^\[models\."/{a=$0} /^support_efforts/{print a " " $0}' ~/.kimi-code/config.toml`
   and read the existing `[secondary_model]` section and `[thinking]`. Treat a model as a *base alias*
   when its name has no `@`. If `thinking.enabled = false`, warn that efforts are ignored.
   If the role the user wants has no alias at all because `[models]` never got that model, stop and
   point them at `/kimi-swarm:sync` instead of writing a block by hand.
2. **Build the families.** `AskUserQuestion` takes 2 to 4 options per question, and the user always
   gets an "Other" field, so you cannot list every alias. The wizard therefore asks for a *family*
   first and then a *model* inside it. The families come from the user's preferences file,
   `$KIMI_CODE_HOME/kimi-swarm.toml` (default `~/.kimi-code/kimi-swarm.toml`), which lives outside the
   plugin because aliases differ between machines:

   ```toml
   [families]
   "Anthropic"  = ["litellm/claude-opus-5", "litellm/claude-sonnet-5-5", "litellm/claude-haiku-4-5"]
   "OpenAI"     = ["litellm/codex-gpt6-sol", "litellm/gpt-oss:120b"]
   "Uso diario" = ["litellm/deepseek-v4.1-flash", "litellm/glm-5.3-flash", "litellm/glm-5.3"]
   ```

   Each family is an ordered list of *base* aliases (no `@`). Rules:
   - Drop, silently, any alias that is not a key in `[models]`, then say once how many were dropped.
     Drop a family that ends up empty.
   - If the file is missing or has no `[families]`, build the families yourself from `[models]`,
     grouping by the name after the provider prefix (claude → Anthropic, codex/gpt → OpenAI, glm,
     deepseek, qwen, kimi and so on), skip image, embedding, rerank, speech and vision-only models,
     and offer to save the result to that file at the end (step 9). Never create it without asking.
   - Show the family order as written in the file. Put the family that holds the role's current alias
     first, even if the file lists it later.
3. **For each role, in order, ask three questions, one after the other:**
   - *Family*: header = role name, options = the families, at most 4. With more than 4 families,
     show 3 plus `More families`, which asks again with the rest. "Other" accepts any alias from
     `[models]` and skips the model question. For security, drop the reviewer's family from the
     options.
   - *Model*: header = role name, options = the aliases of the chosen family. Put the role's current
     alias first as `(Current)` when it belongs to this family. At most 4 options; with more than 4
     aliases show 3 plus `More models`, which asks again with the next page. Give each option a
     one-line description (family, and `fast` or `strong` when the name makes it obvious). For
     security, reject an answer that is in the reviewer's family and ask again.
   - *Effort*: header = `Effort`, one question for the model just chosen. Read its `support_efforts`
     and offer up to 4 of them, spread across the range (for example `low`, `medium`, `high`, and
     `max` or the highest supported). For the worker, do not offer `low` or lower: use `medium`,
     `high`, `xhigh` (and `max` if there is room). Mark one `(Recommended)` and put it first:
     worker `xhigh` for DeepSeek models, `medium` for Claude Sonnet models, `medium` for any other
     model; reviewer `high`; architect the highest supported; security `high`. If the role already
     has an effort, mark that one `(Current)`. "Other" accepts any other level. Reject, and ask again, any
     effort that is not in that model's `support_efforts`; never write an unsupported one.
4. **Ask the cleanup question.** Existing pool entries that are not one of the chosen variants
   (base aliases without effort, such as `provider/model`) can be kept or removed. Ask once, with
   options `Remove them (Recommended)` and `Keep them`. Explain that the orchestrator cannot see
   what effort a base alias would run with.
5. **Build the TOML** from the answers, as variants plus the pool. For each (alias, effort) pair,
   reuse an existing `[models."<alias>@<effort>"]` block if there is one. Otherwise copy the base
   block verbatim, add `default_effort = "<effort>"`, and replace any `default_effort` it already
   has. Keep every field of the base block, including ones this file does not mention. When showing
   the block to the user, mask any secret-looking field (`api_key`, tokens) but still copy it.
   Pool descriptions must state the role and the effort, because the orchestrator only sees the
   description. Example:

   ```toml
   [models."litellm/claude-opus-5@max"]
   provider = "litellm"
   model = "claude-opus-5"
   max_context_size = 1000000
   capabilities = [ "thinking", "tool_use" ]
   support_efforts = [ "none", "minimal", "low", "medium", "high", "xhigh", "max" ]
   default_effort = "max"

   [secondary_model]
   default_model = "litellm/deepseek-v4.1-flash@xhigh"

   [secondary_model.models]
   "litellm/deepseek-v4.1-flash@xhigh" = "Worker y cazador (effort xhigh): implementación, refactors, barrido."
   "litellm/claude-opus-5@max"       = "Arquitectura y diseño (effort max): lo más profundo."
   ```

   `default_model` is the worker variant. Do not write `default_effort` or `force` under
   `[secondary_model]`; if the existing section has a global `default_effort`, tell the user it
   would override every variant and remove it in the new block.
6. **Confirm.** Show a summary table (role, alias, effort) and the exact TOML. Ask with
   `AskUserQuestion`: `Write it (Recommended)`, `Change something`, `Cancel`. On `Change something`,
   ask which role, and redo only that role's three questions.
7. **Write safely.** Make a timestamped backup `config.toml.<YYYYMMDD-HHMMSS>.bak`. Insert only the
   new `[models."...@..."]` blocks (before `[secondary_model]` if it exists, else at the end) and
   replace only the `[secondary_model]` and `[secondary_model.models]` tables; never modify any other
   part of the file.
8. **Validate what you wrote.** Parse the file with `python3 -c 'import tomllib;...'` and check that:
   every pool alias exists in `[models]`; `default_model` is a pool key; every `default_effort` is in
   its model's `support_efforts`; there is exactly one `[secondary_model]` table. If any check fails,
   restore the backup and report the cause.
9. **Offer to save the families.** Only if step 2 had to build them because the preferences file was
   missing or had no `[families]`: ask once, with `Save them (Recommended)` and `Don't save`. On save,
   write `kimi-swarm.toml` with the families you built, so the next run and other machines can start
   from them. Never overwrite an existing file; if it exists without `[families]`, append the table.
   Do not put secrets in it.

## Worker safeguard

A worker on `low`, `minimal` or `none` does poorly (verified with `deepseek-v4.1-flash`). The worker
effort must be `medium` or higher, and the recommendations are `xhigh` for DeepSeek and `medium` for
Claude Sonnet. If the user types a lower effort through "Other", or the current worker variant is
lower, warn once and ask whether to keep it; do not block, since it is the user's decision. The
same applies to `audit-hunter`, which follows the worker.

## Constraints to state to the user

- Every pool alias must resolve to a `[models]` entry, or session startup fails loudly.
- `default_model` is required when a `models` table exists, and must be one of its keys.
- `force = true` requires `default_model` and cannot be combined with a `models` table. In force
  mode there is one model for all subagents, so a global `default_effort` is the right tool there;
  this wizard does not set `force`.
- The pool is always active; there is no experimental flag to enable, and the
  `KIMI_SECONDARY_MODEL` / `KIMI_SECONDARY_EFFORT` environment variables are not a supported way to
  configure this.
- `audit-hunter` follows the worker choice and `audit-verifier` follows the reviewer choice. If the
  user wants them separate, add a role for it.

Finish by telling the user to run `/reload` or start a new session, that the `Agent` tool will then
expose a `model` parameter listing each variant with its effort, and how to verify: spawn one
subagent with a variant and check its reported thinking level.

Optional context from the user: $ARGUMENTS
