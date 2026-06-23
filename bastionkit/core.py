"""Core baseline engine for bastionkit.

bastionkit assesses Kubernetes manifests against a hardened security baseline
suited to disconnected / air-gapped / regulated clusters, and generates a
ready-to-apply baseline bundle for a namespace.

The engine is original: it parses Kubernetes YAML documents with a small
dependency-free YAML reader (a pragmatic subset sufficient for the manifest
shapes Kubernetes emits) and applies a catalogue of baseline controls. Each
control maps to widely published hardening guidance (the CIS Kubernetes
Benchmark families and the NSA/CISA Kubernetes Hardening Guidance) by concept;
no third-party text or code is reproduced.

Domains covered:
  * network    — default-deny NetworkPolicy present per namespace
  * podsec     — PodSecurity "restricted" enforced (namespace labels)
  * resources  — ResourceQuota + LimitRange present; containers set limits
  * rbac       — least-privilege (no cluster-admin binding, no wildcard verbs)
  * serviceacct— default ServiceAccount token automount disabled
  * workload   — non-root, read-only rootfs, dropped capabilities, no privilege

No network access; everything is computed locally from the manifests.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

# Tool identity (re-exported from the package __init__).
TOOL_NAME = "bastionkit"
TOOL_VERSION = "0.1.1"

# Severity ordering, highest first. Used for sorting + exit-code policy.
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# The dangerous RBAC verbs / wildcards that defeat least-privilege.
_WILDCARD = "*"
_WRITE_VERBS = {"create", "update", "patch", "delete", "deletecollection"}


# --------------------------------------------------------------------------
# Minimal YAML reader (dependency-free)
# --------------------------------------------------------------------------
#
# Kubernetes manifests use a regular, indentation-driven subset of YAML:
# mappings, block sequences, multi-doc streams (``---``), scalars and inline
# flow collections (``[a, b]`` / ``{k: v}``). We parse exactly that subset.
# This is a clean original implementation, not a vendored library.

class ManifestError(ValueError):
    """Raised when a manifest cannot be parsed or is structurally invalid."""


def _strip_comment(line: str) -> str:
    out = []
    in_s = False
    in_d = False
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == "'" and not in_d:
            in_s = not in_s
        elif ch == '"' and not in_s:
            in_d = not in_d
        elif ch == "#" and not in_s and not in_d:
            # comment only if preceded by whitespace or at start
            if i == 0 or line[i - 1] in " \t":
                break
        out.append(ch)
        i += 1
    return "".join(out).rstrip()


def _scalar(token: str) -> Any:
    t = token.strip()
    if t == "" or t == "~" or t.lower() == "null":
        return None
    if t.lower() in ("true", "yes", "on"):
        return True
    if t.lower() in ("false", "no", "off"):
        return False
    if len(t) >= 2 and t[0] == t[-1] and t[0] in ("'", '"'):
        return t[1:-1]
    # numbers
    try:
        if t.lstrip("-").isdigit():
            return int(t)
        return float(t)
    except ValueError:
        return t


def _parse_flow(token: str) -> Any:
    """Parse an inline flow collection like [a, b] or {k: v}.

    Falls back to JSON for well-formed JSON, then to a tolerant splitter.
    """
    t = token.strip()
    try:
        return json.loads(t)
    except Exception:
        pass
    if t.startswith("[") and t.endswith("]"):
        inner = t[1:-1].strip()
        if not inner:
            return []
        return [_scalar(p) for p in _split_top(inner)]
    if t.startswith("{") and t.endswith("}"):
        inner = t[1:-1].strip()
        d: Dict[str, Any] = {}
        if not inner:
            return d
        for part in _split_top(inner):
            if ":" in part:
                k, v = part.split(":", 1)
                d[k.strip().strip("'\"")] = _scalar(v)
        return d
    return _scalar(t)


def _split_top(s: str) -> List[str]:
    """Split on commas not nested inside brackets/braces/quotes."""
    parts: List[str] = []
    depth = 0
    in_s = in_d = False
    cur = []
    for ch in s:
        if ch == "'" and not in_d:
            in_s = not in_s
        elif ch == '"' and not in_s:
            in_d = not in_d
        elif not in_s and not in_d:
            if ch in "[{":
                depth += 1
            elif ch in "]}":
                depth -= 1
            elif ch == "," and depth == 0:
                parts.append("".join(cur).strip())
                cur = []
                continue
        cur.append(ch)
    if cur:
        parts.append("".join(cur).strip())
    return parts


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


class _Reader:
    def __init__(self, lines: List[str]):
        self.lines = lines
        self.i = 0

    def _peek(self) -> Optional[Tuple[int, str]]:
        while self.i < len(self.lines):
            raw = self.lines[self.i]
            stripped = _strip_comment(raw)
            if stripped.strip() == "":
                self.i += 1
                continue
            return _indent(stripped), stripped
        return None

    def parse_block(self, min_indent: int) -> Any:
        peeked = self._peek()
        if peeked is None:
            return None
        indent, line = peeked
        if indent < min_indent:
            return None
        body = line.strip()
        if body.startswith("- "):
            return self._parse_seq(indent)
        if body == "-":
            return self._parse_seq(indent)
        return self._parse_map(indent)

    def _parse_seq(self, indent: int) -> List[Any]:
        items: List[Any] = []
        while True:
            peeked = self._peek()
            if peeked is None:
                break
            cur_indent, line = peeked
            if cur_indent != indent or not (line.strip() == "-" or line.strip().startswith("- ")):
                break
            self.i += 1
            rest = line.strip()[1:].strip()
            if rest == "":
                val = self.parse_block(indent + 1)
                items.append(val)
            elif ":" in rest and not (rest.startswith("[") or rest.startswith("{")):
                # inline map start on same line as dash; reparse as a map whose
                # first key sits at indent+2
                key, _, after = rest.partition(":")
                m: Dict[str, Any] = {}
                self._assign(m, key.strip(), after.strip(), indent + 2)
                # continue collecting sibling keys deeper than the dash
                more = self._parse_map_continuation(indent + 2)
                m.update(more)
                items.append(m)
            else:
                items.append(_parse_flow(rest) if rest[:1] in "[{" else _scalar(rest))
        return items

    def _parse_map(self, indent: int) -> Dict[str, Any]:
        m: Dict[str, Any] = {}
        while True:
            peeked = self._peek()
            if peeked is None:
                break
            cur_indent, line = peeked
            if cur_indent != indent:
                break
            body = line.strip()
            if body.startswith("- "):
                break
            if ":" not in body:
                # stray scalar; stop
                break
            self.i += 1
            key, _, after = body.partition(":")
            self._assign(m, key.strip().strip("'\""), after.strip(), indent)
        return m

    def _parse_map_continuation(self, indent: int) -> Dict[str, Any]:
        return self._parse_map(indent)

    def _assign(self, m: Dict[str, Any], key: str, after: str, indent: int) -> None:
        if after == "" or after == "|" or after == ">":
            if after in ("|", ">"):
                m[key] = self._read_block_scalar(indent)
                return
            # A block sequence may be indented at the SAME column as its key
            # (valid YAML), or deeper. Peek: if the next content line is a
            # sequence dash at >= the key indent, parse it at that indent.
            peeked = self._peek()
            if peeked is not None:
                child_indent, child_line = peeked
                body = child_line.strip()
                is_seq = body == "-" or body.startswith("- ")
                if is_seq and child_indent >= indent:
                    m[key] = self._parse_seq(child_indent)
                    return
            child = self.parse_block(indent + 1)
            m[key] = child
        elif after[:1] in "[{":
            m[key] = _parse_flow(after)
        else:
            m[key] = _scalar(after)

    def _read_block_scalar(self, indent: int) -> str:
        out = []
        while self.i < len(self.lines):
            raw = self.lines[self.i]
            if raw.strip() == "":
                out.append("")
                self.i += 1
                continue
            if _indent(raw) <= indent:
                break
            out.append(raw[indent + 1:])
            self.i += 1
        return "\n".join(out).strip()


def parse_yaml_documents(text: str) -> List[Any]:
    """Parse a (possibly multi-document) YAML stream into Python objects.

    Supports the Kubernetes-manifest subset of YAML. Raises ManifestError on
    structurally impossible input.
    """
    docs: List[Any] = []
    chunks: List[List[str]] = [[]]
    for line in text.splitlines():
        if line.strip() in ("---", "...") or line.strip().startswith("--- "):
            chunks.append([])
            continue
        chunks[-1].append(line)
    for chunk in chunks:
        if not any(_strip_comment(l).strip() for l in chunk):
            continue
        reader = _Reader(chunk)
        try:
            obj = reader.parse_block(0)
        except Exception as exc:  # pragma: no cover - defensive
            raise ManifestError(f"could not parse YAML document: {exc}") from exc
        if obj is not None:
            docs.append(obj)
    return docs


def load_documents(path: str) -> List[Any]:
    """Read a YAML/JSON manifest file into a list of documents."""
    with open(path, "r", encoding="utf-8") as fh:
        raw = fh.read()
    stripped = raw.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ManifestError(f"invalid JSON in {path}: {exc}") from exc
        return data if isinstance(data, list) else [data]
    return parse_yaml_documents(raw)


# --------------------------------------------------------------------------
# Findings / reports
# --------------------------------------------------------------------------

@dataclass
class Finding:
    rule: str
    severity: str
    message: str
    location: str = ""
    remediation: str = ""
    guidance: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Report:
    source: str
    namespace: str
    findings: List[Finding] = field(default_factory=list)

    @property
    def counts(self) -> Dict[str, int]:
        c = {k: 0 for k in SEVERITY_ORDER}
        for f in self.findings:
            c[f.severity] = c.get(f.severity, 0) + 1
        return c

    @property
    def score(self) -> int:
        """0-100 hardening score; critical/high dominate the penalty."""
        weights = {"critical": 40, "high": 20, "medium": 8, "low": 3, "info": 0}
        penalty = sum(weights[f.severity] for f in self.findings)
        return max(0, 100 - penalty)

    @property
    def failed(self) -> bool:
        c = self.counts
        return c["critical"] > 0 or c["high"] > 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "namespace": self.namespace,
            "score": self.score,
            "failed": self.failed,
            "counts": self.counts,
            "findings": [f.to_dict() for f in self.findings],
        }


# --------------------------------------------------------------------------
# Manifest helpers
# --------------------------------------------------------------------------

def _kind(doc: Any) -> str:
    return str(doc.get("kind", "")) if isinstance(doc, dict) else ""


def _name(doc: Any) -> str:
    meta = doc.get("metadata") if isinstance(doc, dict) else None
    if isinstance(meta, dict):
        return str(meta.get("name", ""))
    return ""


def _namespace(doc: Any) -> str:
    meta = doc.get("metadata") if isinstance(doc, dict) else None
    if isinstance(meta, dict) and meta.get("namespace"):
        return str(meta.get("namespace"))
    return ""


def _pod_spec(doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Locate the PodSpec for any workload kind."""
    kind = _kind(doc)
    spec = doc.get("spec")
    if not isinstance(spec, dict):
        return None
    if kind == "Pod":
        return spec
    if kind in ("Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"):
        tmpl = spec.get("template")
        if isinstance(tmpl, dict):
            ts = tmpl.get("spec")
            return ts if isinstance(ts, dict) else None
    if kind == "CronJob":
        jt = spec.get("jobTemplate", {})
        if isinstance(jt, dict):
            jspec = jt.get("spec", {})
            if isinstance(jspec, dict):
                tmpl = jspec.get("template", {})
                if isinstance(tmpl, dict):
                    ts = tmpl.get("spec")
                    return ts if isinstance(ts, dict) else None
    return None


_WORKLOAD_KINDS = {"Pod", "Deployment", "StatefulSet", "DaemonSet",
                   "ReplicaSet", "Job", "CronJob"}


# --------------------------------------------------------------------------
# Baseline control catalogue
# --------------------------------------------------------------------------
# Each entry: (rule_id, severity, title, guidance-tag)
CONTROLS = [
    ("network.default_deny_missing", "high",
     "Namespace has no default-deny NetworkPolicy.",
     "NSA/CISA: network separation & firewalling; CIS 5.3 (Network Policies)"),
    ("podsec.restricted_missing", "high",
     "Namespace does not enforce the PodSecurity 'restricted' profile.",
     "NSA/CISA: Pod Security; CIS 5.2 (Pod Security Standards)"),
    ("resources.quota_missing", "medium",
     "Namespace has no ResourceQuota.",
     "NSA/CISA: resource limits to bound DoS; CIS 5.7 (General Policies)"),
    ("resources.limitrange_missing", "medium",
     "Namespace has no LimitRange default requests/limits.",
     "NSA/CISA: resource limits; CIS 5.7"),
    ("rbac.cluster_admin_binding", "critical",
     "A binding grants cluster-admin / wildcard cluster privileges.",
     "NSA/CISA: RBAC least privilege; CIS 5.1 (RBAC and Service Accounts)"),
    ("rbac.wildcard_rule", "high",
     "A Role/ClusterRole uses wildcard verbs, resources, or apiGroups.",
     "NSA/CISA: RBAC least privilege; CIS 5.1"),
    ("rbac.write_to_default_sa", "medium",
     "A binding targets the 'default' ServiceAccount.",
     "NSA/CISA: minimize default service account use; CIS 5.1.5"),
    ("serviceacct.automount_enabled", "medium",
     "ServiceAccount token automount is not disabled.",
     "NSA/CISA: disable token automount when unused; CIS 5.1.6"),
    ("workload.run_as_root", "high",
     "Container may run as root (runAsNonRoot not set true).",
     "NSA/CISA: non-root containers; CIS 5.2.6"),
    ("workload.privileged", "critical",
     "Container requests privileged mode.",
     "NSA/CISA: deny privileged containers; CIS 5.2.1"),
    ("workload.privilege_escalation", "high",
     "Container allows privilege escalation.",
     "NSA/CISA: allowPrivilegeEscalation=false; CIS 5.2.5"),
    ("workload.writable_rootfs", "medium",
     "Container root filesystem is writable.",
     "NSA/CISA: immutable runtime; CIS 5.2.x (read-only root FS)"),
    ("workload.caps_not_dropped", "medium",
     "Container does not drop ALL Linux capabilities.",
     "NSA/CISA: drop capabilities; CIS 5.2.7-9"),
    ("workload.no_resource_limits", "low",
     "Container sets no CPU/memory limits.",
     "NSA/CISA: resource limits; CIS 5.7"),
    ("workload.host_namespace", "high",
     "Workload shares a host namespace (hostNetwork/hostPID/hostIPC).",
     "NSA/CISA: avoid host namespaces; CIS 5.2.2-4"),
    ("workload.host_path", "high",
     "Workload mounts a hostPath volume.",
     "NSA/CISA: restrict hostPath; CIS 5.2.x"),
]

_CONTROL_GUIDANCE = {c[0]: c[3] for c in CONTROLS}


def _g(rule: str) -> str:
    return _CONTROL_GUIDANCE.get(rule, "")


# --------------------------------------------------------------------------
# Assessment
# --------------------------------------------------------------------------

def assess_documents(docs: List[Any], source: str,
                     namespace_hint: str = "") -> List[Report]:
    """Assess a list of parsed manifest documents, grouped by namespace.

    Namespace-scoped controls (default-deny NetworkPolicy, PodSecurity labels,
    ResourceQuota, LimitRange) are evaluated per namespace observed. Workload
    and RBAC controls are evaluated per object. Findings are then bucketed into
    a Report per namespace (objects with no namespace land in '(default)').
    """
    docs = [d for d in docs if isinstance(d, dict)]

    # Discover namespaces from Namespace objects + object metadata.
    ns_objects: Dict[str, Dict[str, Any]] = {}
    observed: set = set()
    for d in docs:
        if _kind(d) == "Namespace":
            ns_objects[_name(d)] = d
            observed.add(_name(d))
        ns = _namespace(d)
        if ns:
            observed.add(ns)
    if namespace_hint:
        observed.add(namespace_hint)
    if not observed:
        observed.add("(default)")

    # Index namespace-scoped baseline objects.
    netpols_by_ns: Dict[str, List[Dict[str, Any]]] = {}
    quotas_by_ns: Dict[str, bool] = {}
    limitranges_by_ns: Dict[str, bool] = {}
    for d in docs:
        k = _kind(d)
        ns = _namespace(d) or namespace_hint or "(default)"
        if k == "NetworkPolicy":
            netpols_by_ns.setdefault(ns, []).append(d)
        elif k == "ResourceQuota":
            quotas_by_ns[ns] = True
        elif k == "LimitRange":
            limitranges_by_ns[ns] = True

    findings_by_ns: Dict[str, List[Finding]] = {ns: [] for ns in observed}

    def _bucket(ns: str) -> List[Finding]:
        return findings_by_ns.setdefault(ns, [])

    # Namespace-scoped controls.
    for ns in sorted(observed):
        out = _bucket(ns)
        # default-deny NetworkPolicy
        if not _has_default_deny(netpols_by_ns.get(ns, [])):
            out.append(Finding(
                "network.default_deny_missing", "high",
                f"Namespace '{ns}' lacks a default-deny NetworkPolicy; all pod "
                "ingress/egress is allowed by default.",
                f"namespace/{ns}",
                "Apply a NetworkPolicy with an empty podSelector and "
                "policyTypes [Ingress, Egress] and no allow rules.",
                _g("network.default_deny_missing"),
            ))
        # PodSecurity restricted label (only checkable when a Namespace object exists)
        nsobj = ns_objects.get(ns)
        if nsobj is not None and not _enforces_restricted(nsobj):
            out.append(Finding(
                "podsec.restricted_missing", "high",
                f"Namespace '{ns}' does not set "
                "pod-security.kubernetes.io/enforce=restricted.",
                f"namespace/{ns}",
                "Label the namespace "
                "pod-security.kubernetes.io/enforce=restricted (and audit/warn).",
                _g("podsec.restricted_missing"),
            ))
        if ns not in quotas_by_ns:
            out.append(Finding(
                "resources.quota_missing", "medium",
                f"Namespace '{ns}' has no ResourceQuota to bound aggregate usage.",
                f"namespace/{ns}",
                "Apply a ResourceQuota capping requests/limits and object counts.",
                _g("resources.quota_missing"),
            ))
        if ns not in limitranges_by_ns:
            out.append(Finding(
                "resources.limitrange_missing", "medium",
                f"Namespace '{ns}' has no LimitRange providing default "
                "container requests/limits.",
                f"namespace/{ns}",
                "Apply a LimitRange with default and defaultRequest cpu/memory.",
                _g("resources.limitrange_missing"),
            ))

    # Object-scoped controls.
    for d in docs:
        ns = _namespace(d) or namespace_hint or "(default)"
        k = _kind(d)
        if k in _WORKLOAD_KINDS:
            _assess_workload(d, ns, _bucket(ns))
        elif k == "ServiceAccount":
            _assess_service_account(d, _bucket(ns))
        elif k in ("Role", "ClusterRole"):
            _assess_role(d, _bucket(ns if k == "Role" else "(cluster)"))
        elif k in ("RoleBinding", "ClusterRoleBinding"):
            _assess_binding(d, _bucket(ns if k == "RoleBinding" else "(cluster)"))

    reports: List[Report] = []
    for ns in sorted(findings_by_ns):
        fnds = findings_by_ns[ns]
        if not fnds and ns in ("(cluster)",):
            continue
        fnds.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.rule))
        reports.append(Report(source=source, namespace=ns, findings=fnds))
    if not reports:
        reports.append(Report(source=source, namespace="(default)", findings=[]))
    return reports


def _has_default_deny(netpols: List[Dict[str, Any]]) -> bool:
    for np in netpols:
        spec = np.get("spec")
        if not isinstance(spec, dict):
            continue
        sel = spec.get("podSelector")
        # empty podSelector ({} or matchLabels:{}) selects all pods
        empty = sel == {} or (isinstance(sel, dict) and not sel.get("matchLabels")
                              and not sel.get("matchExpressions"))
        ptypes = spec.get("policyTypes") or []
        has_ingress = "Ingress" in ptypes
        has_egress = "Egress" in ptypes
        # default-deny = selects all pods, names a policy type, and has no
        # corresponding allow rules.
        ingress_rules = spec.get("ingress")
        egress_rules = spec.get("egress")
        denies_ingress = has_ingress and not ingress_rules
        denies_egress = has_egress and not egress_rules
        if empty and (denies_ingress or denies_egress):
            return True
    return False


def _enforces_restricted(nsobj: Dict[str, Any]) -> bool:
    meta = nsobj.get("metadata", {})
    labels = meta.get("labels", {}) if isinstance(meta, dict) else {}
    if not isinstance(labels, dict):
        return False
    return labels.get("pod-security.kubernetes.io/enforce") == "restricted"


def _containers(pod_spec: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for key in ("initContainers", "containers", "ephemeralContainers"):
        items = pod_spec.get(key)
        if isinstance(items, list):
            out.extend([c for c in items if isinstance(c, dict)])
    return out


def _assess_workload(doc: Dict[str, Any], ns: str, out: List[Finding]) -> None:
    pod_spec = _pod_spec(doc)
    if pod_spec is None:
        return
    obj = f"{_kind(doc)}/{_name(doc)}"

    # Host namespaces
    for hk, label in (("hostNetwork", "hostNetwork"), ("hostPID", "hostPID"),
                      ("hostIPC", "hostIPC")):
        if pod_spec.get(hk) is True:
            out.append(Finding(
                "workload.host_namespace", "high",
                f"{obj} sets {label}=true, breaking pod isolation.",
                obj, f"Remove {label}; do not share host namespaces.",
                _g("workload.host_namespace")))

    # hostPath volumes
    for vol in pod_spec.get("volumes", []) or []:
        if isinstance(vol, dict) and "hostPath" in vol:
            out.append(Finding(
                "workload.host_path", "high",
                f"{obj} mounts hostPath volume '{vol.get('name', '?')}'.",
                obj, "Replace hostPath with a PVC, configMap, or emptyDir.",
                _g("workload.host_path")))

    pod_sc = pod_spec.get("securityContext", {}) or {}
    pod_nonroot = pod_sc.get("runAsNonRoot") is True

    for c in _containers(pod_spec):
        cname = c.get("name", "?")
        cobj = f"{obj}:{cname}"
        sc = c.get("securityContext", {}) or {}

        if sc.get("privileged") is True:
            out.append(Finding(
                "workload.privileged", "critical",
                f"{cobj} runs privileged.",
                cobj, "Set securityContext.privileged=false.",
                _g("workload.privileged")))

        if not (sc.get("runAsNonRoot") is True or pod_nonroot):
            out.append(Finding(
                "workload.run_as_root", "high",
                f"{cobj} may run as root (runAsNonRoot not true).",
                cobj, "Set securityContext.runAsNonRoot=true and a non-zero runAsUser.",
                _g("workload.run_as_root")))

        if sc.get("allowPrivilegeEscalation") is not False:
            out.append(Finding(
                "workload.privilege_escalation", "high",
                f"{cobj} permits privilege escalation.",
                cobj, "Set securityContext.allowPrivilegeEscalation=false.",
                _g("workload.privilege_escalation")))

        if sc.get("readOnlyRootFilesystem") is not True:
            out.append(Finding(
                "workload.writable_rootfs", "medium",
                f"{cobj} has a writable root filesystem.",
                cobj, "Set securityContext.readOnlyRootFilesystem=true.",
                _g("workload.writable_rootfs")))

        caps = sc.get("capabilities", {}) or {}
        drop = caps.get("drop", []) or []
        drop_norm = {str(x).upper() for x in drop} if isinstance(drop, list) else set()
        if "ALL" not in drop_norm:
            out.append(Finding(
                "workload.caps_not_dropped", "medium",
                f"{cobj} does not drop ALL capabilities.",
                cobj, "Set securityContext.capabilities.drop=[ALL].",
                _g("workload.caps_not_dropped")))

        res = c.get("resources", {}) or {}
        limits = res.get("limits", {}) or {}
        if not (limits.get("cpu") and limits.get("memory")):
            out.append(Finding(
                "workload.no_resource_limits", "low",
                f"{cobj} does not set both cpu and memory limits.",
                cobj, "Set resources.limits.cpu and resources.limits.memory.",
                _g("workload.no_resource_limits")))


def _assess_service_account(doc: Dict[str, Any], out: List[Finding]) -> None:
    if doc.get("automountServiceAccountToken") is not False:
        out.append(Finding(
            "serviceacct.automount_enabled", "medium",
            f"ServiceAccount '{_name(doc)}' does not disable token automount.",
            f"ServiceAccount/{_name(doc)}",
            "Set automountServiceAccountToken=false unless the pod calls the API.",
            _g("serviceacct.automount_enabled")))


def _assess_role(doc: Dict[str, Any], out: List[Finding]) -> None:
    rules = doc.get("rules") or []
    obj = f"{_kind(doc)}/{_name(doc)}"
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        verbs = [str(v) for v in (rule.get("verbs") or [])]
        resources = [str(r) for r in (rule.get("resources") or [])]
        groups = [str(g) for g in (rule.get("apiGroups") or [])]
        if (_WILDCARD in verbs or _WILDCARD in resources or _WILDCARD in groups):
            out.append(Finding(
                "rbac.wildcard_rule", "high",
                f"{obj} grants a wildcard (verbs/resources/apiGroups), defeating "
                "least privilege.",
                obj, "Enumerate explicit verbs, resources, and apiGroups.",
                _g("rbac.wildcard_rule")))


def _assess_binding(doc: Dict[str, Any], out: List[Finding]) -> None:
    role_ref = doc.get("roleRef", {}) or {}
    obj = f"{_kind(doc)}/{_name(doc)}"
    ref_name = str(role_ref.get("name", ""))
    if ref_name in ("cluster-admin", "admin") and _kind(doc) == "ClusterRoleBinding":
        out.append(Finding(
            "rbac.cluster_admin_binding", "critical",
            f"{obj} binds the '{ref_name}' ClusterRole, granting broad cluster "
            "control.",
            obj, "Bind a narrowly scoped Role instead of cluster-admin/admin.",
            _g("rbac.cluster_admin_binding")))
    for subj in doc.get("subjects") or []:
        if not isinstance(subj, dict):
            continue
        if subj.get("kind") == "ServiceAccount" and subj.get("name") == "default":
            out.append(Finding(
                "rbac.write_to_default_sa", "medium",
                f"{obj} grants permissions to the 'default' ServiceAccount.",
                obj, "Create a dedicated, named ServiceAccount and bind to it.",
                _g("rbac.write_to_default_sa")))


# --------------------------------------------------------------------------
# High-level entry points
# --------------------------------------------------------------------------

def _iter_manifest_files(target: str) -> List[str]:
    """Resolve target to a sorted list of manifest files (.yaml/.yml/.json)."""
    exts = (".yaml", ".yml", ".json")
    if os.path.isfile(target):
        return [target]
    if not os.path.isdir(target):
        raise ManifestError(f"no such file or directory: {target}")
    found: List[str] = []
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d != "node_modules"]
        for fn in files:
            if fn.lower().endswith(exts):
                found.append(os.path.join(root, fn))
    return sorted(found)


def assess(target: str, namespace_hint: str = "") -> List[Report]:
    """Assess a manifest file or a directory of manifests.

    All documents across all files are pooled so namespace-scoped baseline
    objects (a NetworkPolicy in one file, the Deployment it protects in
    another) are correctly correlated. Unreadable files surface as a finding.
    """
    docs: List[Any] = []
    sources: List[str] = []
    errors: List[Finding] = []
    for path in _iter_manifest_files(target):
        try:
            docs.extend(load_documents(path))
            sources.append(path)
        except (OSError, ManifestError) as exc:
            errors.append(Finding(
                "manifest.unreadable", "high",
                f"Manifest could not be parsed: {exc}", path,
                "Ensure the file is valid Kubernetes YAML/JSON.", ""))
    source_label = target
    reports = assess_documents(docs, source=source_label, namespace_hint=namespace_hint)
    if errors:
        reports.append(Report(source=source_label, namespace="(errors)",
                              findings=errors))
    return reports


def assess_to_dict(target: str, namespace_hint: str = "") -> Dict[str, Any]:
    """Run assess() and return a single JSON-serializable aggregate object."""
    reports = assess(target, namespace_hint=namespace_hint)
    agg = {k: 0 for k in SEVERITY_ORDER}
    for r in reports:
        for sev, n in r.counts.items():
            agg[sev] += n
    return {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "target": target,
        "namespaces_assessed": len(reports),
        "namespaces_failed": sum(1 for r in reports if r.failed),
        "total_findings": sum(len(r.findings) for r in reports),
        "counts": agg,
        "failed": any(r.failed for r in reports),
        "reports": [r.to_dict() for r in reports],
    }


# --------------------------------------------------------------------------
# Serializers
# --------------------------------------------------------------------------

_SARIF_LEVEL = {
    "critical": "error", "high": "error",
    "medium": "warning", "low": "note", "info": "note",
}


def _security_severity(sev: str) -> str:
    return {"critical": "9.5", "high": "8.0", "medium": "5.0",
            "low": "3.0", "info": "0.0"}.get(sev, "5.0")


def _uri(path: str) -> str:
    return path.replace(os.sep, "/")


def to_sarif(reports: List[Report]) -> Dict[str, Any]:
    """Render assessment reports as a SARIF 2.1.0 log (code-scanning ready)."""
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []
    for report in reports:
        for f in report.findings:
            if f.rule not in rules:
                rules[f.rule] = {
                    "id": f.rule,
                    "name": f.rule,
                    "shortDescription": {"text": f.rule},
                    "fullDescription": {"text": f.guidance or f.remediation or f.message},
                    "defaultConfiguration": {
                        "level": _SARIF_LEVEL.get(f.severity, "warning")
                    },
                    "properties": {"security-severity": _security_severity(f.severity)},
                }
            results.append({
                "ruleId": f.rule,
                "level": _SARIF_LEVEL.get(f.severity, "warning"),
                "message": {"text": f.message
                            + (f"\nRemediation: {f.remediation}" if f.remediation else "")
                            + (f"\nGuidance: {f.guidance}" if f.guidance else "")},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": _uri(report.source)},
                        "region": {"startLine": 1},
                    },
                    "logicalLocations": [{"fullyQualifiedName": f.location or report.namespace}],
                }],
                "properties": {"severity": f.severity, "namespace": report.namespace},
            })
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": TOOL_NAME,
                "version": TOOL_VERSION,
                "informationUri": "https://github.com/cognis-digital/bastionkit",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
