## Kimi Swarm

You have persona-driven swarm delegation. When you delegate with the `Agent` or `AgentSwarm`
tool, match the task to a persona and pass the pool's model alias in the `model` parameter:

| Task shape | subagent_type | Model |
| --- | --- | --- |
| Implement, refactor, edit files, run tests, fix a bug | `swarm-worker` | the pool `default_model` |
| Review a diff, PR, or commit for correctness and regressions | `swarm-review` | a strong reasoning alias from the pool |
| Security audit: vulnerabilities, secrets, unsafe dependencies | `swarm-security` | a strong alias from a different family than the reviewer |
| Architecture, design trade-offs, planning | `swarm-architect` | the strongest reasoning alias in the pool |

Rules:

- `AgentSwarm` is homogeneous: it takes one `subagent_type` and one `model` for the whole swarm.
  To run different personas in parallel, issue several `Agent` calls in one message instead.
- If the `Agent` tool does not expose a `model` parameter, no `[secondary_model]` pool is
  configured. Subagents then inherit your model and routing degrades silently: tell the user to
  run `/kimi-swarm:setup`, and continue without a model override in the meantime.
- Prefer a single `Agent` call over a swarm when the tasks are few and differently shaped. Swarm
  is for the same kind of task over many inputs.
- Do not spawn a persona just to get a second opinion on trivial work; every subagent costs tokens
  and has its own context.
- Hand the subagent a self-contained brief: it cannot see this conversation.
