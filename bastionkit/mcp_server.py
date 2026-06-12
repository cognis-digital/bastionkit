"""bastionkit MCP server.

Exposes the baseline assessor (and the deterministic generator) as MCP
capabilities over stdio using newline-delimited JSON-RPC 2.0. Standard library
only — no SDK required — so it runs anywhere Python does and can be wired into
Cognis.Studio, Claude Desktop, or Cursor as a local MCP server:

    {"command": "python", "args": ["-m", "bastionkit", "mcp"]}

Implemented methods:
  * initialize   — handshake, advertises the tools capability
  * tools/list   — describes the `assess` and `generate_baseline` tools
  * tools/call   — runs a tool and returns results as JSON text

Each line on stdin is one JSON-RPC request; each response is one JSON line on
stdout.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import ManifestError, assess_to_dict
from .generate import generate_bundle

PROTOCOL_VERSION = "2024-11-05"

_TOOLS = [
    {
        "name": "assess",
        "description": "Assess Kubernetes manifests (a file or directory) "
                       "against the hardened baseline: default-deny "
                       "NetworkPolicy, PodSecurity restricted, ResourceQuota/"
                       "LimitRange, RBAC least-privilege, ServiceAccount "
                       "automount, and workload securityContext controls. "
                       "Returns prioritized findings grouped by namespace.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Path to a manifest file or a directory.",
                },
                "namespace": {
                    "type": "string",
                    "description": "Assume this namespace for unscoped objects.",
                },
            },
            "required": ["target"],
            "additionalProperties": False,
        },
    },
    {
        "name": "generate_baseline",
        "description": "Generate a hardened baseline YAML bundle for a "
                       "namespace (default-deny NetworkPolicy, restricted "
                       "PodSecurity labels, ResourceQuota, LimitRange, "
                       "least-privilege RBAC, ServiceAccount, admission stub).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "namespace": {"type": "string"},
                "cpu_quota": {"type": "string"},
                "memory_quota": {"type": "string"},
                "pod_quota": {"type": "integer"},
            },
            "required": ["namespace"],
            "additionalProperties": False,
        },
    },
]


def _result(req_id: Any, result: Dict[str, Any]) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _error(req_id: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _call_tool(name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    if name == "assess":
        target = arguments.get("target")
        if not isinstance(target, str) or not target:
            raise ValueError("`target` (string path) is required")
        ns = arguments.get("namespace") or ""
        payload = assess_to_dict(target, namespace_hint=str(ns))
        return {
            "content": [{"type": "text", "text": json.dumps(payload, indent=2)}],
            "isError": bool(payload.get("failed")),
        }
    if name == "generate_baseline":
        ns = arguments.get("namespace")
        if not isinstance(ns, str) or not ns:
            raise ValueError("`namespace` (string) is required")
        kwargs: Dict[str, Any] = {}
        if isinstance(arguments.get("cpu_quota"), str):
            kwargs["cpu_quota"] = arguments["cpu_quota"]
        if isinstance(arguments.get("memory_quota"), str):
            kwargs["memory_quota"] = arguments["memory_quota"]
        if isinstance(arguments.get("pod_quota"), int):
            kwargs["pod_quota"] = arguments["pod_quota"]
        bundle = generate_bundle(ns, **kwargs)
        return {"content": [{"type": "text", "text": bundle}], "isError": False}
    raise ValueError(f"unknown tool: {name}")


def handle_request(req: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Dispatch a single JSON-RPC request. Returns None for notifications."""
    method = req.get("method")
    req_id = req.get("id")
    params = req.get("params") or {}
    is_notification = "id" not in req

    if method == "initialize":
        res = _result(req_id, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": TOOL_NAME, "version": TOOL_VERSION},
        })
        return None if is_notification else res

    if method in ("notifications/initialized", "initialized"):
        return None

    if method == "ping":
        return None if is_notification else _result(req_id, {})

    if method == "tools/list":
        return _result(req_id, {"tools": _TOOLS})

    if method == "tools/call":
        name = params.get("name", "")
        arguments = params.get("arguments") or {}
        try:
            return _result(req_id, _call_tool(name, arguments))
        except (ValueError, OSError, ManifestError) as exc:
            return _error(req_id, -32602, str(exc))
        except Exception as exc:  # pragma: no cover - defensive
            return _error(req_id, -32603, f"internal error: {exc}")

    if is_notification:
        return None
    return _error(req_id, -32601, f"method not found: {method}")


def run_mcp_server(stdin=None, stdout=None) -> None:
    """Read newline-delimited JSON-RPC from stdin, write responses to stdout."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            stdout.write(json.dumps(_error(None, -32700, "parse error")) + "\n")
            stdout.flush()
            continue
        response = handle_request(req)
        if response is not None:
            stdout.write(json.dumps(response) + "\n")
            stdout.flush()


if __name__ == "__main__":
    run_mcp_server()
