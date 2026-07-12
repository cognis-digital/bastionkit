"""
polyglot/python/network_policy_analyzer.py

Hardened security baseline for air-gapped/regulated Kubernetes.
Assess and generate NetworkPolicy/PodSecurity/RBAC/quota controls.

This module provides:
- YAML parsing of existing policies
- Validation against best practices (deny-all default, least privilege)
- Gap analysis - what's missing vs recommended
- Generation of remediation policies
"""

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Set


# =============================================================================
# CONSTANTS & CONFIGURATION
# =============================================================================

DEFAULT_DENY_ALL_PORTS = [80, 443, 53]  # HTTP/HTTPS/DNS - default allow ports
DEFAULT_DENY_ALL_NAMESPACES = ["kube-system", "kube-public"]
MIN_RECOMMENDED_POLICY_COUNT = 1
MAX_RULES_PER_NAMESPACE = 20

# PodSecurity Standards (Kubernetes 1.24+)
POD_SECURITY_STANDARDS = {
    "restricted": {"runAsNonRoot": True, "allowPrivilegeEscalation": False},
    "baseline": {"runAsNonRoot": False, "allowPrivilegeEscalation": True},
}

# RBAC Best Practices
RBAC_MIN_GROUPS_REQUIRED = ["view", "edit"]


# =============================================================================
# DATA MODELS
# =============================================================================

class PolicyStatus(Enum):
    """Status of a policy rule after analysis."""
    COMPLIANT = auto()
    WARNING = auto()
    ERROR = auto()
    INFO = auto()


@dataclass(frozen=True)
class PortRule:
    """Represents a port-based network rule."""
    name: str
    protocol: str  # "TCP", "UDP", or "*"
    port: int
    action: str  # "Allow" or "Deny"
    from_namespaces: List[str] = field(default_factory=list)
    to_namespaces: List[str] = field(default_factory=list)
    
    @property
    def is_default_port(self) -> bool:
        return self.port in DEFAULT_DENY_ALL_PORTS


@dataclass(frozen=True)
class NamespaceRule:
    """Represents a namespace-based network rule."""
    name: str
    action: str  # "Allow" or "Deny"
    from_namespaces: List[str] = field(default_factory=list)
    to_namespaces: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class PolicyRule:
    """Represents a single rule within a NetworkPolicy."""
    name: str
    kind: str  # "Ingress" or "Egress"
    ports: List[PortRule] = field(default_factory=list)
    from_namespaces: List[NamespaceRule] = field(default_factory=list)
    to_namespaces: List[NamespaceRule] = field(default_factory=list)


@dataclass(frozen=True)
class NetworkPolicy:
    """Represents a Kubernetes NetworkPolicy object."""
    name: str
    namespace: str
    kind: str  # "NetworkPolicy" or "PodSecurityPolicy"
    spec: Dict[str, Any] = field(default_factory=dict)
    rules: List[PolicyRule] = field(default_factory=list)
    
    @property
    def has_default_deny(self) -> bool:
        """Check if policy has a default deny rule."""
        ingress_rules = [r for r in self.rules if r.kind == "Ingress"]
        egress_rules = [r for r in self.rules if r.kind == "Egress"]
        
        # Check for explicit deny-all rules
        for rule in ingress_rules + egress_rules:
            if not rule.ports and not rule.from_namespaces:
                return True
        
        return False


@dataclass(frozen=True)
class AnalysisResult:
    """Container for analysis results."""
    policies_analyzed: int = 0
    total_rules: int = 0
    compliant_policies: int = 0
    warning_count: int = 0
    error_count: int = 0
    
    findings: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[Dict[str, Any]] = field(default_factory=list)
    
    @property
    def score(self) -> float:
        """Calculate compliance score (0-100)."""
        total = self.compliant_policies + self.warning_count + max(0, self.error_count - 5)
        if total == 0:
            return 100.0
        
        compliant_ratio = self.compliant_policies / total
        warning_penalty = min(self.warning_count * 2, 30)
        error_penalty = min(self.error_count * 5, 40)
        
        score = max(0, (compliant_ratio * 100) - warning_penalty - error_penalty)
        return round(score, 1)


# =============================================================================
# YAML PARSING & LOADING
# =============================================================================

def load_policy_from_yaml(yaml_content: str) -> Optional[NetworkPolicy]:
    """Parse a single NetworkPolicy from YAML content."""
    try:
        import yaml
        
        data = yaml.safe_load(yaml_content)
        
        if not isinstance(data, dict):
            return None
            
        kind = data.get("kind", "")
        if kind != "NetworkPolicy":
            return None
            
        name = data.get("metadata", {}).get("name", "unnamed")
        namespace = data.get("metadata", {}).get("namespace", "default")
        
        spec = data.get("spec", {})
        policy_rules = []
        
        # Parse ingress rules
        for rule in spec.get("ingress", []):
            ports = parse_port_list(rule.get("ports", []))
            from_ns = parse_namespace_list(rule.get("from", []))
            
            policy_rules.append(PolicyRule(
                name=f"{name}-ingress-{rule.get('name', 'unnamed')}",
                kind="Ingress",
                ports=ports,
                from_namespaces=from_ns,
                to_namespaces=[]
            ))
        
        # Parse egress rules
        for rule in spec.get("egress", []):
            ports = parse_port_list(rule.get("ports", []))
            to_ns = parse_namespace_list(rule.get("to", []))
            
            policy_rules.append(PolicyRule(
                name=f"{name}-egress-{rule.get('name', 'unnamed')}",
                kind="Egress",
                ports=ports,
                from_namespaces=[],
                to_namespaces=to_ns
            ))
        
        return NetworkPolicy(
            name=name,
            namespace=namespace,
            kind="NetworkPolicy",
            spec=spec,
            rules=policy_rules
        )
    except Exception as e:
        print(f"Error parsing YAML: {e}")
        return None


def load_policies_from_file(filepath: str) -> List[NetworkPolicy]:
    """Load all NetworkPolicies from a file path."""
    filepath = Path(filepath).resolve()
    
    if not filepath.exists():
        raise FileNotFoundError(f"File not found: {filepath}")
    
    policies = []
    
    try:
        with open(filepath, "r") as f:
            content = f.read()
            
        # Try to parse as single policy first
        policy = load_policy_from_yaml(content)
        if policy:
            return [policy]
        
        # Otherwise assume multi-document YAML (list of policies)
        import yaml
        
        documents = list(yaml.safe_load_all(content))
        
        for doc in documents:
            if not isinstance(doc, dict):
                continue
                
            kind = doc.get("kind", "")
            if kind == "NetworkPolicy":
                policy = load_policy_from_yaml(yaml.dump([doc]))
                policies.append(policy)
                
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML format: {e}")
    
    return policies


# =============================================================================
# PORT & NAMESPACE PARSING HELPERS
# =============================================================================

def parse_port_list(ports_data: List[Dict]) -> List[PortRule]:
    """Parse Kubernetes port specification into PortRule objects."""
    ports = []
    
    for port_spec in ports_data:
        if not isinstance(port_spec, dict):
            continue
            
        protocol = port_spec.get("protocol", "TCP")
        
        # Handle named port (e.g., 80:http)
        port_str = str(port_spec.get("port"))
        if ":" in port_str:
            parts = port_str.rsplit(":", 1)
            try:
                port = int(parts[0])
                name = parts[1]
            except ValueError:
                continue
        else:
            try:
                port = int(port_spec.get("port", 80))
                name = str(port)
            except (ValueError, TypeError):
                continue
        
        ports.append(PortRule(
            name=name,
            protocol=protocol.upper(),
            port=port,
            action="Allow"
        ))
    
    return ports


def parse_namespace_list(nss_data: List[Dict]) -> List[NamespaceRule]:
    """Parse Kubernetes namespace specification into NamespaceRule objects."""
    namespaces = []
    
    for ns_spec in nss_data:
        if not isinstance(ns_spec, dict):
            continue
            
        # Handle named port (e.g., 80:http)
        ns_str = str(ns_spec.get("namespace"))
        
        # Parse namespace and optional selector
        parts = ns_str.rsplit(":", 1)
        try:
            name = int(parts[0])
            selector = parts[1] if len(parts) > 1 else None
        except ValueError:
            name = ns_spec.get("namespace", "default")
            selector = None
        
        namespaces.append(NamespaceRule(
            name=name,
            action="Allow"
        ))
    
    return namespaces


# =============================================================================
# VALIDATION LOGIC
# =============================================================================

class ValidationError(Exception):
    """Raised when a policy fails validation."""
    def __init__(self, message: str, severity: PolicyStatus = PolicyStatus.ERROR):
        super().__init__(message)
        self.severity = severity


def validate_policy(policy: NetworkPolicy) -> Tuple[bool, List[str]]:
    """Validate a single NetworkPolicy against best practices."""
    issues = []
    
    # Check for default deny (ingress or egress with no ports/namespaces)
    has_default_deny = policy.has_default_deny
    
    # Check rule complexity
    total_rules = sum(1 for r in policy.rules if r.kind == "Ingress") + \
                   sum(1 for r in policy.rules if r.kind == "Egress")
    
    if total_rules > MAX_RULES_PER_NAMESPACE:
        issues.append(f"Too many rules ({total_rules} > {MAX_RULES_PER_NAMESPACE})")
    
    # Check for overly permissive ingress (allows all namespaces)
    for rule in policy.rules:
        if rule.kind == "Ingress":
            if not rule.from_namespaces or any(
                ns.name == "*" or ns.name == "" 
                for ns in rule.from_namespaces
            ):
                issues.append(f"Rule {rule.name} allows ingress from all namespaces")
    
    # Check for overly permissive egress (allows all namespaces)
    for rule in policy.rules:
        if rule.kind == "Egress":
            if not rule.to_namespaces or any(
                ns.name == "*" or ns.name == "" 
                for ns in rule.to_namespaces
            ):
                issues.append(f"Rule {rule.name} allows egress to all namespaces")
    
    # Check for default ports that should be restricted
    default_ports_found = []
    for rule in policy.rules:
        if rule.kind == "Ingress":
            for port in rule.ports:
                if port.is_default_port and not port.name.startswith("http"):
                    default_ports_found.append(port)
    
    return len(issues) == 0, issues


def validate_namespace_policy(policies: List[NetworkPolicy]) -> AnalysisResult:
    """Validate a collection of policies against the security baseline."""
    result = AnalysisResult()
    
    for policy in policies:
        result.policies_analyzed += 1
        result.total_rules += sum(
            1 for r in policy.rules if r.kind == "Ingress"
        ) + sum(
            1 for r in policy.rules if r.kind == "Egress"
        )
        
        is_valid, issues = validate_policy(policy)
        
        if is_valid:
            result.compliant_policies += 1
            
        # Add findings
        for issue in issues:
            finding = {
                "policy": policy.name,
                "namespace": policy.namespace,
                "issue": issue,
                "severity": PolicyStatus.WARNING.value,
                "recommendation": get_recommendation(issue)
            }
            
            if "all namespaces" in issue.lower():
                finding["severity"] = PolicyStatus.ERROR.value
            
            result.findings.append(finding)
            result.warning_count += 1
    
    # Calculate final score
    result.score = result.compliant_policies / max(result.policies_analyzed, 1) * 100
    
    return result


def get_recommendation(issue: str) -> Optional[str]:
    """Get a remediation recommendation for an issue."""
    recommendations = {
        "all namespaces": f"Restrict to specific namespaces. Example:\n  from:\n  - namespaceSelector:\n      matchLabels:\n        name: <specific-namespace>",
        "default deny": "Add explicit default-deny rules at the end of your policy list.",
        "too many rules": "Consolidate similar rules or use label selectors for grouping.",
    }
    
    return recommendations.get(issue.lower().split()[0], None)


# =============================================================================
# GAP ANALYSIS & GENERATION
# =============================================================================

def analyze_gaps(policies: List[NetworkPolicy]) -> Dict[str, Any]:
    """Analyze gaps between current state and recommended baseline."""
    result = {
        "current_state": {
            "policies_count": len(policies),
            "total_rules": sum(
                1 for r in policy.rules if r.kind == "Ingress"
                for p in [policy] + policies
            )
        },
        "gaps": [],
        "recommended_policies": []
    }
    
    # Check for missing default-deny patterns
    has_default_deny_any = any(
        policy.has_default_deny for policy in policies
    )
    
    if not has_default_deny_any:
        result["gaps"].append({
            "type": "missing_default_deny",
            "description": "No explicit default-deny rules found across all policies",
            "severity": "HIGH"
        })
    
    # Check for namespace isolation gaps
    namespaces_used = set()
    for policy in policies:
        namespaces_used.add(policy.namespace)
        for rule in policy.rules:
            if rule.kind == "Ingress":
                for ns in rule.from_namespaces:
                    namespaces_used.add(ns.name)
            if rule.kind == "Egress":
                for ns in rule.to_namespaces:
                    namespaces_used.add(ns.name)
    
    # Check against recommended namespace isolation
    isolated_namespaces = [ns for ns in namespaces_used 
                          if not any("kube" in n.lower() or "default" in n.lower() 
                                    for n in DEFAULT_DENY_ALL_NAMESPACES)]
    
    result["gaps"].append({
        "type": "namespace_coverage",
        "description": f"Found {len(isolated_namespaces)} isolated namespaces: {', '.join(sorted(isolated_namespaces))}",
        "severity": "MEDIUM" if len(isolated_namespaces) < 3 else "LOW"
    })
    
    # Generate recommended policies
    result["recommended_policies"] = generate_recommended_policies(policies, namespaces_used)
    
    return result


def generate_recommended_policies(
    existing: List[NetworkPolicy], 
    namespaces: Set[str]
) -> List[Dict[str, Any]]:
    """Generate recommended NetworkPolicy YAML configurations."""
    recommendations = []
    
    # 1. Default-deny ingress policy (applied to each namespace)
    default_deny_ingress = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": "default-deny-ingress",
            "namespace": "<NAMESPACE>"  # User must replace this
        },
        "spec": {
            "podSelector": {},  # Apply to all pods
            "policyTypes": ["Ingress"],
            "ingress": []  # No ingress = deny all by default
        }
    }
    
    # 2. Default-deny egress policy (applied to each namespace)
    default_deny_egress = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": "default-deny-egress",
            "namespace": "<NAMESPACE>"  # User must replace this
        },
        "spec": {
            "pod