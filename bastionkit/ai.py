"""Opt-in AI layer for bastionkit (OFF by default).

Reuses the canonical Cognis shared AI backend pattern (local, OpenAI-compatible
llama.cpp / Ollama endpoints — nothing leaves the box). With no configuration
``is_enabled()`` is False and every function degrades gracefully:

  * ``explain_findings`` returns ``[]``
  * ``draft_network_policy`` returns ``None``

Enable by setting COGNIS_AI_BACKEND / COGNIS_AI_ENDPOINT (see
cognis_ai_backend.py). The deterministic assess/generate paths never depend on
this module.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from .cognis_ai_backend import CognisAIBackend

_EXPLAIN_SYSTEM = (
    "You are a Kubernetes security engineer hardening clusters for "
    "air-gapped / regulated environments. Given baseline findings, explain in "
    "plain language WHY each matters and the concrete attacker path it opens, "
    "then give a precise remediation. Respond with a STRICT JSON array (and "
    "nothing else); each object has keys: \"rule\" (string, echo the input "
    "rule), \"explanation\" (string), \"remediation\" (string). Return [] if "
    "there are no findings."
)

_NETPOL_SYSTEM = (
    "You are a Kubernetes network-policy author. Convert the user's plain-English "
    "intent into a single valid Kubernetes NetworkPolicy. Default to deny: only "
    "open exactly what is requested. Respond with STRICT JSON (one object, no "
    "prose) representing the NetworkPolicy manifest with keys apiVersion, kind, "
    "metadata, spec."
)


def is_enabled() -> bool:
    return CognisAIBackend().is_enabled()


def _chat_json(system: str, user: str) -> Optional[str]:
    backend = CognisAIBackend()
    if not backend.is_enabled():
        return None
    try:
        return backend._chat(system, user)  # noqa: SLF001 — reuse shared client
    except Exception:
        return None


def explain_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Explain a list of finding dicts. Returns [] when the backend is off."""
    if not findings:
        return []
    backend = CognisAIBackend()
    if not backend.is_enabled():
        return []
    payload = [{"rule": f.get("rule"), "severity": f.get("severity"),
                "message": f.get("message")} for f in findings]
    content = _chat_json(_EXPLAIN_SYSTEM, json.dumps(payload, indent=2))
    if not content:
        return []
    arr = CognisAIBackend._extract_json_array(content)  # noqa: SLF001
    if not arr:
        return []
    try:
        parsed = json.loads(arr)
    except Exception:
        return []
    out: List[Dict[str, Any]] = []
    if isinstance(parsed, list):
        for item in parsed:
            if isinstance(item, dict):
                out.append({
                    "rule": str(item.get("rule", "")),
                    "explanation": str(item.get("explanation", "")),
                    "remediation": str(item.get("remediation", "")),
                })
    return out


def draft_network_policy(intent: str, namespace: str = "default") -> Optional[Dict[str, Any]]:
    """Draft a NetworkPolicy from plain English. Returns None when off/failed."""
    if not intent or not intent.strip():
        return None
    backend = CognisAIBackend()
    if not backend.is_enabled():
        return None
    user = f"Namespace: {namespace}\nIntent: {intent.strip()}"
    content = _chat_json(_NETPOL_SYSTEM, user)
    if not content:
        return None
    obj = _extract_json_object(content)
    if obj is None:
        return None
    if obj.get("kind") != "NetworkPolicy":
        return None
    return obj


def _extract_json_object(text: str) -> Optional[Dict[str, Any]]:
    text = CognisAIBackend._strip_think(text)  # noqa: SLF001
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, flags=re.DOTALL | re.IGNORECASE)
    if fence:
        text = fence.group(1)
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    obj = json.loads(text[start:i + 1])
                    return obj if isinstance(obj, dict) else None
                except Exception:
                    return None
    return None
