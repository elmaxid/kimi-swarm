---
name: kimi-swarm
description: Persona-driven multi-model delegation for Kimi Code. Routes a task to a worker, review, security, or architect subagent and picks a model from the [secondary_model] pool per persona. Use when a task should be delegated to a subagent running a different model than the orchestrator, or when work should be split across specialized personas.
---

# Kimi Swarm

Delegate work to specialized personas, each able to run on a different model than the orchestrator.

## How the pieces fit in Kimi Code

Kimi has native delegation, but the pieces are separate:

- **Delegation**: the `Agent` tool (one task, one subagent) and the `AgentSwarm` tool (many
  subagents from one `{{item}}` template). Both run in isolated contexts and return only a result.
- **Personas**: Markdown agent files with frontmatter. This plugin ships six: `swarm-worker`,
  `swarm-review`, `swarm-security`, `swarm-architect`, `audit-hunter`, `audit-verifier`.
- **Different model**: the `[secondary_model]` section of `config.toml`. It defines a pool of
  candidate model aliases; when the pool exists, the `Agent` and `AgentSwarm` tools gain a `model`
  parameter listing the pool with each alias's hint.

## The hard limit (verified in the official source)

- The model **cannot** be bound to a persona in the agent file. The `model` frontmatter field is
  ignored on purpose; the `AgentProfile` type has no model field.
- The model is chosen **per spawn** by the orchestrator through the tool's `model` parameter, or
  pinned for **every** subagent with `force = true`.
- `AgentSwarm` takes **one** `subagent_type` and **one** `model` for the whole swarm. For different
  personas in parallel, issue several `Agent` calls in one message instead of one swarm.
- Hooks cannot rewrite tool arguments, so a hook cannot inject the `model`.

So persona-to-model binding is **prompt-driven policy**, not a hard binding. That is what this
skill provides.

## Routing matrix

Pass `subagent_type` and `model` together on each `Agent` call:

| Task shape | `subagent_type` | Model |
| --- | --- | --- |
| Implement, refactor, edit files, run tests, fix a bug | `swarm-worker` | pool `default_model` |
| Review a diff, PR, or commit | `swarm-review` | a strong reasoning alias |
| Security audit | `swarm-security` | a strong alias from a **different family** than the reviewer |
| Architecture, design, planning | `swarm-architect` | the strongest reasoning alias |
| Full security audit workflow (hunting waves) | `audit-hunter` | the fast pool `default_model` |
| Full security audit workflow (validate / refute candidates) | `audit-verifier` | a strong alias from a **different family** than the hunter |

Pick the reviewer and auditor from different model families so their blind spots do not overlap.

## Security audits

Two levels, pick by request:

- **Lightweight**: one `swarm-security` subagent reviews a diff or a module. Fast, no artifacts.
- **Full workflow**: the vendored Cloudflare `security-audit` skill
  (`skills/security-audit/`) runs six phases — reconnaissance, coverage-led hunting waves,
  candidate validation, structured output, independent verification, report. Use it for an explicit
  "audit this codebase" or pen-test request. It uses `audit-hunter` for hunting (fast model) and
  `audit-verifier` for validation and record verification (strong, different family). Start it with
  `/kimi-swarm:audit`.

The full workflow has two hard requirements: **Python 3** (or Node.js) for its validator steps
(Phases 4–5), and, to execute target code at all, an **OS-enforced sandbox**. The plugin ships
`scripts/swarm-sandbox.py` for the sandbox (systemd or bubblewrap): `create` a run outside `/tmp`,
`run` a command confined to an agent's scratch, then `promote` only the minimal result. Without a
sandbox, run it static-only — read source and record every execution-dependent candidate as
`needs_validation`; this is a supported mode, not a degraded one.

## Automatic vs forced delegation

Auto-delegation depends on the orchestrator's own judgment, so strength matters:

- With only the routing table, the main agent **knows** the personas but often does the work inline
  anyway — especially when it can read the few files fast. Naming the tool in the prompt
  ("use AgentSwarm for this") is unreliable on its own.
- An **imperative policy** in the system prompt flips this: with wording like "you MUST delegate
  task shape X to persona Y, do not do it inline", the agent delegates on its own and cites the
  policy in its reasoning. This is what `SYSTEM.md` in this plugin provides.
- To force it at the user level, put the same policy in `$KIMI_CODE_HOME/SYSTEM.md` (which fully
  replaces the default main-agent prompt) or in `~/.kimi-code/AGENTS.md` (which is appended as
  instructions).
- For a deterministic single flow, the slash commands (`/kimi-swarm:review`,
  `/kimi-swarm:security-audit`) dispatch explicitly and are not subject to the model's judgment.

## Setting up the pool

The pool lives in `config.toml` and cannot be set by the plugin. Run `/kimi-swarm:setup`, or add
the section by hand:

```toml
[secondary_model]
default_model = "provider/fast-coding-model"
[secondary_model.models]
"provider/fast-coding-model"  = "Worker: implementation, refactors, edits."
"provider/strong-reasoner"    = "Review and architecture: deep reasoning."
"provider/other-family"       = "Security: independent second family."
```

Rules that fail loudly at session startup: every pool alias must resolve to a configured `[models]`
entry, and `force` cannot be combined with a `models` table. When an alias does not resolve because
the block was never added, run `/kimi-swarm:sync` first (see *Keeping `[models]` in sync with the
gateway* below) — do not hand-write a block, the engine rejects one without a positive
`max_context_size`.

### Effort per model

The `Agent` tool has no effort parameter. A subagent's thinking effort is
`[secondary_model].default_effort` if set (one value for every pool model, validated against each),
otherwise the `default_effort` declared on the chosen alias in `[models]`. To give each model its own
effort, add an effort variant per (model, effort) and put the variants in the pool:

```toml
[models."provider/strong-reasoner@max"]
provider = "provider"
model = "strong-reasoner"
max_context_size = 262144
capabilities = [ "thinking", "tool_use" ]
support_efforts = [ "low", "medium", "high", "max" ]
default_effort = "max"

[secondary_model.models]
"provider/strong-reasoner@max" = "Review and architecture, effort max."
```

Do not set the global `default_effort` in this mode: it overrides every variant. `/kimi-swarm:setup`
creates the variants and checks each effort against the model's `support_efforts`.

### Keeping `[models]` in sync with the gateway

`/kimi-swarm:setup` reads `[models]` and never queries the gateway, so it cannot offer a model that
`config.toml` does not have yet. `/kimi-swarm:sync` (backed by `scripts/sync-models.py`) does the
opposite job: it reads the provider's OpenAI-compatible `/v1/models` and `/model/info`, previews the
diff and, once confirmed, writes it.

| Command | Owns | Never does |
| --- | --- | --- |
| `/kimi-swarm:sync` | the `[models.*]` catalog, and the `[families]` table of `kimi-swarm.toml` | create `@effort` variants, edit `[secondary_model]`, delete a model block |
| `/kimi-swarm:setup` | the `[secondary_model]` pool and the `@effort` variants | talk to the gateway, invent a `[models]` block |

Sync adds only what the gateway announces, widens existing blocks by union (a capability is never
removed — `supports_function_calling` is unreliable, so an unconfirmed capability is only reported),
and fills a scalar only when it is absent. It also checks the invariant `default_effort ∈
support_efforts` on every base+variant group and omits the changes of a broken group instead of
writing an effort the model does not support.

### Using `/kimi-swarm:setup`

| Command | What it does |
| --- | --- |
| `/kimi-swarm:setup` | Full wizard: family, model and effort for worker, reviewer, architect and security. |
| `/kimi-swarm:setup quick` | Keeps current models and efforts; only asks for the final confirmation. |
| `/kimi-swarm:setup effort` | Keeps current models; asks only the effort of each role. |
| `/kimi-swarm:setup worker` (or `reviewer`, `architect`, `security`) | Redoes one role and leaves the rest. |

Every mode backs up `config.toml`, validates the result and asks for confirmation before writing.
Run `/reload` or start a new session afterwards. Security must come from a different family than the
reviewer. Never run the worker (or `audit-hunter`) at `low` or below: weak models do poorly there; use
`xhigh` with DeepSeek or `medium` with Claude Sonnet. To verify, spawn one subagent with a variant and
check its reported thinking level.

## Invocation

Let the main agent route automatically (it reads this skill and the system prompt), or name the
persona explicitly:

- "Use swarm-review with the strong model to review the current diff."
- "Spawn swarm-worker to implement X, then swarm-security on the result."
- `/kimi-swarm:review`, `/kimi-swarm:security-audit`

## Cost and safety

- Every subagent has its own context window and bills separately; it cannot see the conversation.
  Give it a self-contained brief.
- `swarm-review` and `swarm-security` are read-only (no `Write`/`Edit`) and cannot dispatch further
  subagents.
- If the `Agent` tool shows no `model` parameter, no pool is configured: subagents inherit the
  orchestrator's model and routing degrades silently. Run `/kimi-swarm:setup`.
