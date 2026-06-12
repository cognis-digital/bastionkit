"""bastionkit — hardened security baseline for air-gapped/regulated Kubernetes.

Part of the Cognis Neural Suite. Assess Kubernetes manifests against a baseline
of network, pod-security, RBAC, quota, and workload controls, and generate a
ready-to-apply hardened baseline bundle for a namespace.
"""

from bastionkit.core import (
    TOOL_NAME,
    TOOL_VERSION,
    CONTROLS,
    SEVERITY_ORDER,
    Finding,
    Report,
    ManifestError,
    assess,
    assess_documents,
    assess_to_dict,
    load_documents,
    parse_yaml_documents,
    to_sarif,
)
from bastionkit.generate import (
    baseline_documents,
    generate_bundle,
    dump_documents,
    validate_yaml,
)

__version__ = TOOL_VERSION

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "__version__",
    "CONTROLS",
    "SEVERITY_ORDER",
    "Finding",
    "Report",
    "ManifestError",
    "assess",
    "assess_documents",
    "assess_to_dict",
    "load_documents",
    "parse_yaml_documents",
    "to_sarif",
    "baseline_documents",
    "generate_bundle",
    "dump_documents",
    "validate_yaml",
]
