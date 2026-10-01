## Kimi Swarm — delegation policy

For the task shapes below you MUST delegate with the `Agent` tool instead of doing the work
yourself. Do only the reading needed to write a self-contained brief, then hand off.

| Task shape | `subagent_type` | Model |
| --- | --- | --- |
| A diff, PR, or commit to review for correctness and regressions | `swarm-review` | a strong reasoning alias |
| A security audit of code, a module, or a dependency surface | `swarm-security` | an alias from a **different family** than the reviewer |
| An architecture or design decision, or planning a non-trivial change | `swarm-architect` | the strongest reasoning alias |
| Full security audit / pen-test of a codebase | the Cloudflare `security-audit` skill: `audit-hunter` then `audit-verifier` | hunter: fast alias; verifier: strong alias from a **different family** |
| Multi-file implementation the user explicitly asks to delegate | `swarm-worker` | the pool `default_model` |

Always pass `model` with an alias from the `[secondary_model]` pool.

Rules:

- When the work spans several independent files or items, use `AgentSwarm` with the matching
  `subagent_type` and `model` instead of doing it inline.
- For different personas in parallel, issue several `Agent` calls in one message: `AgentSwarm` is
  homogeneous (one `subagent_type` and one `model` for the whole swarm).
- Do not delegate trivial single-file changes, questions, or explanations; answer those directly.
- If the `Agent` tool exposes no `model` parameter, no pool is configured: tell the user to run
  `/kimi-swarm:setup`, and delegate without a model override in the meantime.
- Give the subagent a self-contained brief; it cannot see this conversation.
