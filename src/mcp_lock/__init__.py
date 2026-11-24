"""mcp-lock — Cryptographic MCP tool-schema lockfile & rug-pull verifier."""

from mcp_lock.locker import (
    LockVerificationReport,
    ToolAuditFinding,
    audit_tool_definition,
    canonical_tool_hash,
    generate_lockfile,
    infer_capabilities,
    verify_against_lockfile,
)

__version__ = "0.1.0"

__all__ = [
    "LockVerificationReport",
    "ToolAuditFinding",
    "__version__",
    "audit_tool_definition",
    "canonical_tool_hash",
    "generate_lockfile",
    "infer_capabilities",
    "verify_against_lockfile",
]
