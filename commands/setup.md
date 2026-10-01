---
description: Configure the [secondary_model] subagent model pool in config.toml
---

Set up the Kimi Swarm subagent model pool in the user's `config.toml`.

Steps:

1. Locate the config file. It is `$KIMI_CODE_HOME/config.toml`, defaulting to
   `~/.kimi-code/config.toml`.
2. List the model aliases the user already has, without dumping any secrets. Run:
   `grep -oE '^\[models\."[^"]+"' ~/.kimi-code/config.toml | sed 's/\[models\."//'`
   (adjust the path if `KIMI_CODE_HOME` is set).
3. Check whether a `[secondary_model]` section already exists. If it does, read it and propose an
   update instead of appending a second section.
4. Propose a routing table mapping each persona to one of the user's real aliases, choosing a fast
   alias as `default_model` (worker) and a strong reasoning alias for review/architecture, ideally
   from a different family for security. Show the exact TOML block.
5. Show the block to the user and ask for confirmation. Before writing, make a timestamped backup of
   `config.toml`. Then append or edit only the `[secondary_model]` section; never modify the rest of
   the file.

Constraints to respect and state to the user:

- Every pool alias must resolve to a configured `[models]` entry, or session startup fails loudly.
- `default_model` is required when a `models` table is present, and must be one of its keys.
- `force = true` requires `default_model` and cannot be combined with a `models` table.
- The pool is always active; there is no experimental flag to enable, and the
  `KIMI_SECONDARY_MODEL` environment variable is not read by the current engine.

Finish by telling the user to run `/reload` or start a new session, and that the `Agent` tool will
then expose a `model` parameter.

Optional context from the user: $ARGUMENTS
