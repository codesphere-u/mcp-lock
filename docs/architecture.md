# Architecture — `mcp-lock`

- `mcp_lock.locker`: Canonical JSON SHA-256 tool-definition hashing, `mcp-lock.json` lockfile generator, post-install rug-pull/addition/removal diff engine, zero-width & prompt-injection poisoning scanner, and capability surface policy checker.
- `mcp_lock.cli`: CI lockfile CLI (`pin`, `verify`, `demo`).
