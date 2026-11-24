"""Cryptographic MCP tool-schema lockfile, rug-pull drift detector & capability auditor."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

# Covert tool-poisoning / prompt-injection patterns hidden inside MCP tool descriptions
_POISON_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "MCP-POISON-001",
        re.compile(
            r"(?i)(<IMPORTANT>|ignore\s+previous\s+instructions?|"
            r"do\s+not\s+tell\s+the\s+user|before\s+calling\s+this\s+tool\s+read|"
            r"pass\s+its\s+contents\s+in)"
        ),
    ),
    (
        "MCP-POISON-002",
        re.compile(r"(?i)(~/\.ssh|~/\.aws|/etc/passwd|\.env\b|id_rsa|secret\s+key|bearer\s+token)"),
    ),
    (
        "MCP-POISON-003",
        re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]"),  # Invisible zero-width steganography
    ),
)

_HIGH_RISK_CAPABILITY_KEYWORDS: dict[str, tuple[str, ...]] = {
    "shell_exec": ("bash", "shell", "exec", "spawn", "subprocess", "terminal", "command"),
    "fs_write": ("write_file", "delete", "remove", "unlink", "chmod", "patch", "rm"),
    "network_egress": ("http", "fetch", "webhook", "curl", "upload", "post", "email", "send"),
    "credential_access": ("secret", "token", "keychain", "password", "env", "ssh"),
}


@dataclass(frozen=True)
class ToolAuditFinding:
    rule_id: str
    severity: str  # critical | high | warning
    server_name: str
    tool_name: str
    message: str


@dataclass(frozen=True)
class LockVerificationReport:
    passed: bool
    servers_checked: int
    tools_checked: int
    added_tools: tuple[str, ...]
    removed_tools: tuple[str, ...]
    mutated_tools: tuple[str, ...]
    findings: tuple[ToolAuditFinding, ...]


def canonical_tool_hash(tool_def: dict[str, Any]) -> str:
    """Compute canonical SHA-256 fingerprint of an MCP tool's name, description & inputSchema."""
    normalized = {
        "name": str(tool_def.get("name", "")),
        "description": str(tool_def.get("description", "")),
        "inputSchema": tool_def.get("inputSchema") or {},
        "annotations": tool_def.get("annotations") or {},
    }
    raw = json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def infer_capabilities(tool_def: dict[str, Any]) -> tuple[str, ...]:
    """Infer security capability surface from an MCP tool definition."""
    blob = f"{tool_def.get('name', '')} {tool_def.get('description', '')}".lower()
    caps: list[str] = []
    for cap, kws in _HIGH_RISK_CAPABILITY_KEYWORDS.items():
        if any(k in blob for k in kws):
            caps.append(cap)
    return tuple(sorted(caps))


def audit_tool_definition(server_name: str, tool_def: dict[str, Any]) -> list[ToolAuditFinding]:
    """Scan a single MCP tool schema/description for poisoning and over-privileged capabilities."""
    name = str(tool_def.get("name", "<unnamed>"))
    desc = str(tool_def.get("description", ""))
    schema_str = json.dumps(tool_def.get("inputSchema") or {}, sort_keys=True)
    combined = f"{desc}\n{schema_str}"
    findings: list[ToolAuditFinding] = []

    for rule_id, pat in _POISON_PATTERNS:
        if pat.search(combined):
            findings.append(
                ToolAuditFinding(
                    rule_id=rule_id,
                    severity="critical",
                    server_name=server_name,
                    tool_name=name,
                    message=f"Tool '{server_name}.{name}' matched poisoning signature {rule_id}.",
                )
            )

    caps = set(infer_capabilities(tool_def))
    # Lethal trifecta check: credential/filesystem access combined with external network egress
    if "credential_access" in caps and "network_egress" in caps:
        findings.append(
            ToolAuditFinding(
                rule_id="MCP-CAP-001",
                severity="high",
                server_name=server_name,
                tool_name=name,
                message=f"Tool '{server_name}.{name}' combines credential_access with network_egress.",
            )
        )
    return findings


def generate_lockfile(servers: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    """Create a deterministic `mcp-lock.json` document pinning every server tool hash."""
    locked_servers: dict[str, dict[str, Any]] = {}
    for srv_name in sorted(servers):
        tools_map: dict[str, dict[str, Any]] = {}
        for t in sorted(servers[srv_name], key=lambda x: str(x.get("name", ""))):
            t_name = str(t.get("name", ""))
            tools_map[t_name] = {
                "sha256": canonical_tool_hash(t),
                "capabilities": list(infer_capabilities(t)),
                "description_len": len(str(t.get("description", ""))),
            }
        locked_servers[srv_name] = {"tools": tools_map}

    body = {"lockfile_version": 1, "generated_at": datetime.now(UTC).isoformat(), "servers": locked_servers}
    body_sha = hashlib.sha256(
        json.dumps(locked_servers, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    body["servers_sha256"] = body_sha
    return body


def verify_against_lockfile(
    lockfile: dict[str, Any],
    live_servers: dict[str, list[dict[str, Any]]],
    *,
    allowed_capabilities: set[str] | None = None,
) -> LockVerificationReport:
    """Detect post-install rug-pull tool mutations, added/removed tools, and capability violations."""
    locked_servers: dict[str, Any] = lockfile.get("servers") or {}
    findings: list[ToolAuditFinding] = []
    added: list[str] = []
    removed: list[str] = []
    mutated: list[str] = []
    tools_checked = 0

    all_server_names = sorted(set(locked_servers.keys()) | set(live_servers.keys()))
    for srv in all_server_names:
        pinned_tools: dict[str, Any] = (locked_servers.get(srv) or {}).get("tools") or {}
        live_map = {str(t.get("name", "")): t for t in live_servers.get(srv, [])}

        for t_name in sorted(set(pinned_tools) - set(live_map)):
            removed.append(f"{srv}.{t_name}")

        for t_name, t_def in sorted(live_map.items()):
            tools_checked += 1
            findings.extend(audit_tool_definition(srv, t_def))
            live_hash = canonical_tool_hash(t_def)
            fq = f"{srv}.{t_name}"

            if t_name not in pinned_tools:
                added.append(fq)
                findings.append(
                    ToolAuditFinding(
                        rule_id="MCP-LOCK-ADDED",
                        severity="high",
                        server_name=srv,
                        tool_name=t_name,
                        message=f"Unpinned new tool '{fq}' appeared (not in mcp-lock.json).",
                    )
                )
            elif pinned_tools[t_name].get("sha256") != live_hash:
                mutated.append(fq)
                findings.append(
                    ToolAuditFinding(
                        rule_id="MCP-LOCK-RUGPULL",
                        severity="critical",
                        server_name=srv,
                        tool_name=t_name,
                        message=f"RUG-PULL DRIFT: tool '{fq}' definition changed since lockfile pinning.",
                    )
                )

            if allowed_capabilities is not None:
                disallowed = sorted(set(infer_capabilities(t_def)) - allowed_capabilities)
                if disallowed:
                    findings.append(
                        ToolAuditFinding(
                            rule_id="MCP-CAP-POLICY",
                            severity="high",
                            server_name=srv,
                            tool_name=t_name,
                            message=f"Tool '{fq}' uses disallowed capabilities: {disallowed}.",
                        )
                    )

    passed = not any(f.severity in ("critical", "high") for f in findings)
    return LockVerificationReport(
        passed=passed,
        servers_checked=len(all_server_names),
        tools_checked=tools_checked,
        added_tools=tuple(added),
        removed_tools=tuple(removed),
        mutated_tools=tuple(mutated),
        findings=tuple(findings),
    )
