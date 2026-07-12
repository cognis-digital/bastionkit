"""
polyglot/python/pod_security_scanner.py

Hardened security baseline for air-gapped/regulated Kubernetes.
Assess + generate NetworkPolicy/PodSecurity/RBAC/quota controls.

Air-gapped friendly: works with local files, minimal external dependencies.
"""

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class SecurityIssue:
    """Represents a single security finding."""
    severity: str  # critical, high, medium, low, info
    category: str  # pod_security, network_policy, rbac, quota
    rule_id: str
    description: str
    resource: str = ""  # e.g., "pod/nginx-abc123" or "namespace/production"
    field_path: str = ""  # JSON path like "spec.containers[0].securityContext.privileged"
    current_value: Any = None
    recommended_fix: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "severity": self.severity,
            "category": self.category,
            "rule_id": self.rule_id,
            "description": self.description,
            "resource": self.resource,
            "field_path": self.field_path,
            "current_value": self.current_value,
            "recommended_fix": self.recommended_fix,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SecurityIssue":
        return cls(**d)


@dataclass
class ScanResult:
    """Aggregated results of a security scan."""
    namespace: str = ""
    total_pods_scanned: int = 0
    issues_found: int = 0
    critical_issues: int = 0
    high_issues: int = 0
    medium_issues: int = 0
    low_issues: int = 0
    info_issues: int = 0
    issues: List[SecurityIssue] = field(default_factory=list)
    scan_time: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "namespace": self.namespace,
            "total_pods_scanned": self.total_pods_scanned,
            "issues_found": self.issues_found,
            "critical_issues": self.critical_issues,
            "high_issues": self.high_issues,
            "medium_issues": self.medium_issues,
            "low_issues": self.low_issues,
            "info_issues": self.info_issues,
            "issues": [i.to_dict() for i in self.issues],
            "scan_time": self.scan_time,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ScanResult":
        result = cls(**d)
        if "issues" in d and isinstance(d["issues"], list):
            result.issues = [SecurityIssue.from_dict(i) for i in d["issues"]]
        return result


class PodSecurityScanner:
    """
    Hardened security scanner for air-gapped Kubernetes environments.
    
    Supports scanning from:
    - Live K8s API (via kubectl output files)
    - Local YAML/JSON manifests
    - Raw pod specification JSON
    
    Baseline levels: "restricted" (default), "baseline", "privileged"
    """

    # PSS Restricted baseline rules
    RESTRICTED_PSS = {
        "001": ("Privileged container", "spec.containers[].securityContext.privileged"),
        "002": ("RunAsRoot", "spec.containers[].securityContext.runAsUser=0 or runAsNonRoot=false"),
        "003": ("Host namespaces", "spec.hostNetwork, spec.hostPID, spec.hostIPC"),
        "004": ("AllowPrivilegeEscalation", "spec.containers[].securityContext.allowPrivilegeEscalation=true"),
        "005": ("CAP_ADD", "spec.containers[].securityContext.capabilities.add contains NET_ADMIN, SYS_ADMIN, etc."),
        "006": ("ReadOnlyRootFilesystem", "spec.containers[].securityContext.readOnlyRootFilesystem=false or not set"),
        "007": ("DropAllCapabilities", "spec.containers[].securityContext.capabilities.drop does not include ALL"),
        "008": ("RunAsNonRoot", "spec.containers[].securityContext.runAsNonRoot=false"),
        "010": ("SELinuxOptions", "spec.containers[].securityContext.seLinuxOptions with type=privileged or sro/sr"),
    }

    # Critical capabilities that indicate high risk
    CRITICAL_CAPS = {"NET_ADMIN", "SYS_ADMIN", "SYS_PTRACE", "DAC_OVERRIDE", "MKNOD"}

    def __init__(self, baseline: str = "restricted"):
        self.baseline = baseline  # restricted, baseline, privileged
        self.issues: List[SecurityIssue] = []

    def set_baseline(self, level: str) -> None:
        """Set the PSS baseline level."""
        valid_levels = {"restricted", "baseline", "privileged"}
        if level not in valid_levels:
            raise ValueError(f"Invalid baseline level. Must be one of {valid_levels}")
        self.baseline = level

    def _parse_pod_spec(self, pod_json: str) -> Dict[str, Any]:
        """Parse a raw JSON string into a pod specification dict."""
        try:
            return json.loads(pod_json)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in pod spec: {e}")

    def _get_container_security_context(self, container: Dict[str, Any]) -> Optional[Dict]:
        """Extract security context from a container."""
        return container.get("securityContext")

    def _check_pss_rules(
        self,
        pod_spec: Dict[str, Any],
        namespace: str = "",
        resource_name: str = ""
    ) -> List[SecurityIssue]:
        """Check pods against PSS baseline rules."""
        issues = []
        
        # Determine which rules apply based on baseline level
        active_rules = self._get_active_pss_rules()

        containers = pod_spec.get("spec", {}).get("containers", [])
        init_containers = pod_spec.get("spec", {}).get("initContainers", [])
        all_containers = containers + init_containers

        for container in all_containers:
            sec_ctx = self._get_container_security_context(container) or {}

            # Rule 001: Privileged container
            if sec_ctx.get("privileged") is True:
                issues.append(SecurityIssue(
                    severity="critical",
                    category="pod_security",
                    rule_id="PSS-001",
                    description=f"Container runs in privileged mode (full host access)",
                    resource=f"{namespace}/{resource_name}",
                    field_path="spec.containers[].securityContext.privileged",
                    current_value=True,
                    recommended_fix='Set "privileged: false"',
                ))

            # Rule 002: RunAsRoot
            if sec_ctx.get("runAsUser") == 0 or (sec_ctx.get("runAsNonRoot") is False):
                issues.append(SecurityIssue(
                    severity="critical",
                    category="pod_security",
                    rule_id="PSS-002",
                    description=f"Container may run as root user",
                    resource=f"{namespace}/{resource_name}",
                    field_path="spec.containers[].securityContext.runAsUser/runAsNonRoot",
                    current_value=sec_ctx.get("runAsUser"),
                    recommended_fix='Set "runAsNonRoot: true"',
                ))

            # Rule 003: Host namespaces
            host_specs = pod_spec.get("spec", {}).get("hostNetwork") or \
                        pod_spec.get("spec", {}).get("hostPID") or \
                        pod_spec.get("spec", {}).get("hostIPC")
            
            if any([pod_spec.get("spec", {}).get("hostNetwork"),
                    pod_spec.get("spec", {}).get("hostPID"),
                    pod_spec.get("spec", {}).get("hostIPC")]):
                issues.append(SecurityIssue(
                    severity="critical",
                    category="pod_security",
                    rule_id="PSS-003",
                    description=f"Container shares host namespace (network/pid/ipc)",
                    resource=f"{namespace}/{resource_name}",
                    field_path="spec.hostNetwork/hostPID/hostIPC",
                    current_value=host_specs,
                    recommended_fix='Set "hostNetwork: false, hostPID: false, hostIPC: false"',
                ))

            # Rule 004: AllowPrivilegeEscalation
            if sec_ctx.get("allowPrivilegeEscalation") is True:
                issues.append(SecurityIssue(
                    severity="high",
                    category="pod_security",
                    rule_id="PSS-004",
                    description=f"Container allows privilege escalation",
                    resource=f"{namespace}/{resource_name}",
                    field_path="spec.containers[].securityContext.allowPrivilegeEscalation",
                    current_value=True,
                    recommended_fix='Set "allowPrivilegeEscalation: false"',
                ))

            # Rule 005: Dangerous capabilities
            added_caps = sec_ctx.get("capabilities", {}).get("add", []) or []
            dropped_caps = sec_ctx.get("capabilities", {}).get("drop", []) or []
            
            dangerous_found = any(cap in self.CRITICAL_CAPS for cap in added_caps)
            if dangerous_found:
                issues.append(SecurityIssue(
                    severity="critical" if "SYS_ADMIN" in added_caps else "high",
                    category="pod_security",
                    rule_id="PSS-005",
                    description=f"Container adds dangerous capability: {', '.join([c for c in added_caps if c in self.CRITICAL_CAPS])}",
                    resource=f"{namespace}/{resource_name}",
                    field_path="spec.containers[].securityContext.capabilities.add",
                    current_value=added_caps,
                    recommended_fix='Remove or minimize "capabilities.add"',
                ))

            # Rule 006: ReadOnlyRootFilesystem
            if not sec_ctx.get("readOnlyRootFilesystem"):
                issues.append(SecurityIssue(
                    severity="medium",
                    category="pod_security",
                    rule_id="PSS-006",
                    description=f"Container does not use read-only root filesystem",
                    resource=f"{namespace}/{resource_name}",
                    field_path="spec.containers[].securityContext.readOnlyRootFilesystem",
                    current_value=sec_ctx.get("readOnlyRootFilesystem"),
                    recommended_fix='Set "readOnlyRootFilesystem: true"',
                ))

            # Rule 007: DropAllCapabilities
            if not any("ALL" in d for d in dropped_caps):
                issues.append(SecurityIssue(
                    severity="medium",
                    category="pod_security",
                    rule_id="PSS-007",
                    description=f"Container does not drop ALL capabilities",
                    resource=f"{namespace}/{resource_name}",
                    field_path="spec.containers[].securityContext.capabilities.drop",
                    current_value=dropped_caps,
                    recommended_fix='Add "ALL" to "capabilities.drop"',
                ))

            # Rule 008: RunAsNonRoot
            if not sec_ctx.get("runAsNonRoot"):
                issues.append(SecurityIssue(
                    severity="medium",
                    category="pod_security",
                    rule_id="PSS-008",
                    description=f"Container does not enforce non-root user",
                    resource=f"{namespace}/{resource_name}",
                    field_path="spec.containers[].securityContext.runAsNonRoot",
                    current_value=sec_ctx.get("runAsNonRoot"),
                    recommended_fix='Set "runAsNonRoot: true"',
                ))

            # Rule 010: SELinuxOptions
            selinux = sec_ctx.get("seLinuxOptions") or {}
            if selinux.get("type"):
                type_val = selinux["type"]
                if type_val in ["privileged", "sro", "sr"]:
                    issues.append(SecurityIssue(
                        severity="high" if type_val == "privileged" else "medium",
                        category="pod_security",
                        rule_id="PSS-010",
                        description=f"Container uses potentially privileged SELinux context: {type_val}",
                        resource=f"{namespace}/{resource_name}",
                        field_path="spec.containers[].securityContext.seLinuxOptions.type",
                        current_value=selinux.get("type"),
                        recommended_fix='Use least-privilege SELinux type',
                    ))

        return issues

    def _get_active_pss_rules(self) -> Dict[str, Tuple[str, str]]:
        """Return rules active for the configured baseline level."""
        if self.baseline == "privileged":
            # All rules disabled (except critical ones like privileged containers)
            return {}
        elif self.baseline == "baseline":
            # Medium and low severity rules only
            return {k: v for k, v in self.RESTRICTED_PSS.items() 
                    if v[0] not in ["Privileged container", "RunAsRoot", "Host namespaces"]}
        else:  # restricted (default)
            return self.RESTRICTED_PSS

    def _check_service_accounts(
        self,
        namespace: str = "",
        sa_list: Optional[List[Dict]] = None
    ) -> List[SecurityIssue]:
        """Check ServiceAccounts for overly permissive configurations."""
        issues = []
        
        if not sa_list:
            # Assume default service account exists
            sa_list = [{"metadata": {"name": "default"}}]

        for sa in sa_list:
            name = sa.get("metadata", {}).get("name") or "unknown"
            
            # Check automountServiceAccountToken
            automount = sa.get("automountServiceAccountToken")
            if automount is True:  # Default behavior, but explicit true is less secure
                issues.append(SecurityIssue(
                    severity="low",
                    category="rbac",
                    rule_id="RBAC-001",
                    description=f"ServiceAccount {name} has automountServiceAccountToken explicitly set to true",
                    resource=f"namespace/{namespace}/serviceaccount/{name}",
                    field_path="spec.automountServiceAccountToken",
                    current_value=automount,
                    recommended_fix='Set "automountServiceAccountToken: false" unless needed',
                ))

            # Check secrets/roles bindings (would need to fetch from API)
            roles = sa.get("roleRef") or {}
            if roles.get("name") == "cluster-admin":
                issues.append(SecurityIssue(
                    severity="critical",
                    category="rbac",
                    rule_id="RBAC-002",
                    description=f"ServiceAccount {name} bound to cluster-admin role",
                    resource=f"namespace/{namespace}/serviceaccount/{name}",
                    field_path="spec.roleRef.name",
                    current_value=roles.get("name"),
                    recommended_fix='Create a custom Role with minimal permissions',
                ))

        return issues

    def _check_resource_quotas(
        self,
        namespace: str = "",
        quota_spec: Optional[Dict] = None
    ) -> List[SecurityIssue]:
        """Check ResourceQuota configurations."""
        issues = []

        if not quota_spec:
            # Assume no quota exists (common issue)
            issues.append(SecurityIssue(
                severity="medium",
                category="quota",
                rule_id="QUOTA-001",
                description=f"Namespace {namespace} may lack ResourceQuota limits",
                resource=f"namespace/{namespace}",
                field_path="",
                current_value=None,
                recommended_fix='Create a ResourceQuota with reasonable limits',
            ))

        if quota_spec:
            # Check for missing hard limits
            requests = quota_spec.get("hard", {}) or {}
            
            cpu_limit = requests.get("requests.cpu")
            memory_limit = requests.get("requests.memory")

            if not cpu_limit:
                issues.append(SecurityIssue(
                    severity="medium",
                    category="quota",
                    rule_id="QUOTA-002",
                    description=f"Namespace {namespace} lacks CPU request quota",
                    resource=f"namespace/{namespace}",
                    field_path="spec.hard.requests.cpu",
                    current_value=cpu_limit,
                    recommended_fix='Add "requests: cpu: 100m (minimum)"',
                ))

            if not memory_limit:
                issues.append(SecurityIssue(
                    severity="medium",
                    category="quota",
                    rule_id="QU