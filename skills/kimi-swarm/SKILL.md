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
- **Personas**: Markdown agent files with frontmatter. This plugin ships four: `swarm-worker`,
  `swarm-review`, `swarm-security`, `swarm-architect`.
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

Pick the reviewer and auditor from different model families so their blind spots do not overlap.

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
entry, and `force` cannot be combined with a `models` table.

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
