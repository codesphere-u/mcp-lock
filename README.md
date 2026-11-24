# mcp-lock

**Cryptographic `mcp-lock.json` tool-schema pinning, anti-rug-pull drift verification, tool-description poisoning detection, and least-privilege capability auditor for MCP servers.**

Zero runtime dependencies. Pure Python 3.11+. Protects AI coding agents and developer workstations from silent post-install MCP tool description mutations and covert exfiltration directives.

## Quick Start

```bash
uv sync --extra dev
mcp-lock demo
mcp-lock pin server_tools.json --out mcp-lock.json
mcp-lock verify mcp-lock.json live_tools.json
```

## License

MIT License — see [LICENSE](LICENSE).
