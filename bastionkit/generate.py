"""Hardened baseline bundle generator for bastionkit.

Emits a ready-to-apply, multi-document YAML bundle that establishes the
baseline controls bastionkit assesses for, scoped to a single namespace:

  * Namespace labelled with the PodSecurity 'restricted' profile
  * default-deny NetworkPolicy (ingress + egress)
  * ResourceQuota bounding aggregate requests/limits + object counts
  * LimitRange supplying default container requests/limits
  * a least-privilege Role + RoleBinding scaffold (read-only, namespaced)
  * a dedicated ServiceAccount with token automount disabled
  * a ValidatingAdmissionPolicy stub denying privileged pods

The YAML is hand-serialized (standard library only) so the bundle is
deterministic and dependency-free. Output is valid Kubernetes YAML.
"""

from __future__ import annotations

from typing import Any, Dict, List

from .core import parse_yaml_documents


def _q(v: Any) -> str:
    """Serialize a scalar, quoting strings that need it."""
    if isinstance(v, bool):
        return "true" if v else "false"
    if v is None:
        return "null"
    if isinstance(v, (int, float)):
        return str(v)
    s = str(v)
    needs = (s == "" or s[0] in "!&*?{}[],#|>@`\"'%" or ":" in s or s.strip() != s
             or s.lower() in ("true", "false", "null", "yes", "no"))
    if needs:
        return '"' + s.replace('"', '\\"') + '"'
    return s


def _dump(obj: Any, indent: int = 0) -> List[str]:
    """Serialize a Python object into YAML lines (block style)."""
    pad = "  " * indent
    lines: List[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, dict):
                if v:
                    lines.append(f"{pad}{k}:")
                    lines.extend(_dump(v, indent + 1))
                else:
                    lines.append(f"{pad}{k}: {{}}")
            elif isinstance(v, list):
                if v:
                    lines.append(f"{pad}{k}:")
                    lines.extend(_dump_list(v, indent))
                else:
                    lines.append(f"{pad}{k}: []")
            else:
                lines.append(f"{pad}{k}: {_q(v)}")
    return lines


def _dump_list(items: List[Any], indent: int) -> List[str]:
    pad = "  " * indent
    lines: List[str] = []
    for item in items:
        if isinstance(item, dict):
            sub = _dump(item, indent + 1)
            if sub:
                first = sub[0].lstrip()
                lines.append(f"{pad}- {first}")
                lines.extend(sub[1:])
            else:
                lines.append(f"{pad}- {{}}")
        elif isinstance(item, list):
            lines.append(f"{pad}-")
            lines.extend(_dump_list(item, indent + 1))
        else:
            lines.append(f"{pad}- {_q(item)}")
    return lines


def dump_documents(docs: List[Dict[str, Any]]) -> str:
    """Serialize a list of manifest dicts into a multi-document YAML stream."""
    blocks: List[str] = []
    for doc in docs:
        blocks.append("\n".join(_dump(doc, 0)))
    return "---\n" + "\n---\n".join(blocks) + "\n"


def baseline_documents(namespace: str, *,
                       cpu_quota: str = "4",
                       memory_quota: str = "8Gi",
                       pod_quota: int = 50) -> List[Dict[str, Any]]:
    """Build the in-memory baseline documents for a namespace."""
    labels = {
        "pod-security.kubernetes.io/enforce": "restricted",
        "pod-security.kubernetes.io/enforce-version": "latest",
        "pod-security.kubernetes.io/audit": "restricted",
        "pod-security.kubernetes.io/warn": "restricted",
        "app.kubernetes.io/managed-by": "bastionkit",
    }
    docs: List[Dict[str, Any]] = []

    docs.append({
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {"name": namespace, "labels": labels},
    })

    docs.append({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": "default-deny-all", "namespace": namespace},
        "spec": {
            "podSelector": {},
            "policyTypes": ["Ingress", "Egress"],
        },
    })

    # Allow intra-namespace DNS egress so workloads can still resolve names —
    # a default-deny baseline that breaks DNS is unusable in practice.
    docs.append({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": "allow-dns-egress", "namespace": namespace},
        "spec": {
            "podSelector": {},
            "policyTypes": ["Egress"],
            "egress": [{
                "to": [{"namespaceSelector": {}}],
                "ports": [
                    {"protocol": "UDP", "port": 53},
                    {"protocol": "TCP", "port": 53},
                ],
            }],
        },
    })

    docs.append({
        "apiVersion": "v1",
        "kind": "ResourceQuota",
        "metadata": {"name": "baseline-quota", "namespace": namespace},
        "spec": {
            "hard": {
                "requests.cpu": cpu_quota,
                "requests.memory": memory_quota,
                "limits.cpu": cpu_quota,
                "limits.memory": memory_quota,
                "pods": pod_quota,
                "count/services.loadbalancers": 0,
            },
        },
    })

    docs.append({
        "apiVersion": "v1",
        "kind": "LimitRange",
        "metadata": {"name": "baseline-limits", "namespace": namespace},
        "spec": {
            "limits": [{
                "type": "Container",
                "default": {"cpu": "500m", "memory": "512Mi"},
                "defaultRequest": {"cpu": "100m", "memory": "128Mi"},
                "max": {"cpu": "2", "memory": "2Gi"},
            }],
        },
    })

    docs.append({
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": {"name": "baseline-sa", "namespace": namespace},
        "automountServiceAccountToken": False,
    })

    docs.append({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": {"name": "baseline-readonly", "namespace": namespace},
        "rules": [{
            "apiGroups": [""],
            "resources": ["pods", "configmaps", "services", "endpoints"],
            "verbs": ["get", "list", "watch"],
        }],
    })

    docs.append({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "RoleBinding",
        "metadata": {"name": "baseline-readonly-binding", "namespace": namespace},
        "roleRef": {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "Role",
            "name": "baseline-readonly",
        },
        "subjects": [{
            "kind": "ServiceAccount",
            "name": "baseline-sa",
            "namespace": namespace,
        }],
    })

    # Admission policy stub denying privileged pods (concept-level scaffold).
    docs.append({
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicy",
        "metadata": {"name": "baseline-deny-privileged"},
        "spec": {
            "failurePolicy": "Fail",
            "matchConstraints": {
                "resourceRules": [{
                    "apiGroups": [""],
                    "apiVersions": ["v1"],
                    "operations": ["CREATE", "UPDATE"],
                    "resources": ["pods"],
                }],
            },
            "validations": [{
                "expression":
                    "!object.spec.containers.exists(c, "
                    "has(c.securityContext) && c.securityContext.privileged == true)",
                "message": "privileged containers are denied by the bastionkit baseline",
            }],
        },
    })

    return docs


def generate_bundle(namespace: str, **kwargs: Any) -> str:
    """Return the hardened baseline as a multi-document YAML string."""
    docs = baseline_documents(namespace, **kwargs)
    return dump_documents(docs)


def validate_yaml(text: str) -> int:
    """Round-trip the generated YAML through the parser; return doc count.

    Raises if the emitted YAML cannot be parsed back, so the CLI/tests can use
    it as a self-check that the generator emits valid YAML.
    """
    docs = parse_yaml_documents(text)
    if not docs:
        raise ValueError("generated bundle parsed to zero documents")
    for d in docs:
        if not isinstance(d, dict) or "kind" not in d or "apiVersion" not in d:
            raise ValueError("generated document missing apiVersion/kind")
    return len(docs)
