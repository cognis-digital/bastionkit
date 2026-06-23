//! bastionkit (Rust port) — hardened security baseline for air-gapped/regulated
//! Kubernetes. Mirrors the primary command surface of the Python reference:
//!
//! ```text
//! bastionkit baseline                  list the baseline controls
//! bastionkit generate --namespace NS   emit a hardened baseline YAML bundle
//! ```
//!
//! Standard library only; offline; no network access. The control catalogue and
//! generated bundle are kept in lock-step with core.py / generate.py.

use std::process::exit;

pub const TOOL_NAME: &str = "bastionkit";
pub const TOOL_VERSION: &str = "0.1.1";

/// A single baseline control (rule id, severity, title, guidance).
pub struct Control {
    pub rule: &'static str,
    pub severity: &'static str,
    pub title: &'static str,
    pub guidance: &'static str,
}

/// The baseline control catalogue (lock-step with core.py CONTROLS).
pub const CONTROLS: &[Control] = &[
    Control { rule: "network.default_deny_missing", severity: "high",
        title: "Namespace has no default-deny NetworkPolicy.",
        guidance: "NSA/CISA: network separation & firewalling; CIS 5.3 (Network Policies)" },
    Control { rule: "podsec.restricted_missing", severity: "high",
        title: "Namespace does not enforce the PodSecurity 'restricted' profile.",
        guidance: "NSA/CISA: Pod Security; CIS 5.2 (Pod Security Standards)" },
    Control { rule: "resources.quota_missing", severity: "medium",
        title: "Namespace has no ResourceQuota.",
        guidance: "NSA/CISA: resource limits to bound DoS; CIS 5.7 (General Policies)" },
    Control { rule: "resources.limitrange_missing", severity: "medium",
        title: "Namespace has no LimitRange default requests/limits.",
        guidance: "NSA/CISA: resource limits; CIS 5.7" },
    Control { rule: "rbac.cluster_admin_binding", severity: "critical",
        title: "A binding grants cluster-admin / wildcard cluster privileges.",
        guidance: "NSA/CISA: RBAC least privilege; CIS 5.1 (RBAC and Service Accounts)" },
    Control { rule: "rbac.wildcard_rule", severity: "high",
        title: "A Role/ClusterRole uses wildcard verbs, resources, or apiGroups.",
        guidance: "NSA/CISA: RBAC least privilege; CIS 5.1" },
    Control { rule: "rbac.write_to_default_sa", severity: "medium",
        title: "A binding targets the 'default' ServiceAccount.",
        guidance: "NSA/CISA: minimize default service account use; CIS 5.1.5" },
    Control { rule: "serviceacct.automount_enabled", severity: "medium",
        title: "ServiceAccount token automount is not disabled.",
        guidance: "NSA/CISA: disable token automount when unused; CIS 5.1.6" },
    Control { rule: "workload.run_as_root", severity: "high",
        title: "Container may run as root (runAsNonRoot not set true).",
        guidance: "NSA/CISA: non-root containers; CIS 5.2.6" },
    Control { rule: "workload.privileged", severity: "critical",
        title: "Container requests privileged mode.",
        guidance: "NSA/CISA: deny privileged containers; CIS 5.2.1" },
    Control { rule: "workload.privilege_escalation", severity: "high",
        title: "Container allows privilege escalation.",
        guidance: "NSA/CISA: allowPrivilegeEscalation=false; CIS 5.2.5" },
    Control { rule: "workload.writable_rootfs", severity: "medium",
        title: "Container root filesystem is writable.",
        guidance: "NSA/CISA: immutable runtime; CIS 5.2.x (read-only root FS)" },
    Control { rule: "workload.caps_not_dropped", severity: "medium",
        title: "Container does not drop ALL Linux capabilities.",
        guidance: "NSA/CISA: drop capabilities; CIS 5.2.7-9" },
    Control { rule: "workload.no_resource_limits", severity: "low",
        title: "Container sets no CPU/memory limits.",
        guidance: "NSA/CISA: resource limits; CIS 5.7" },
    Control { rule: "workload.host_namespace", severity: "high",
        title: "Workload shares a host namespace (hostNetwork/hostPID/hostIPC).",
        guidance: "NSA/CISA: avoid host namespaces; CIS 5.2.2-4" },
    Control { rule: "workload.host_path", severity: "high",
        title: "Workload mounts a hostPath volume.",
        guidance: "NSA/CISA: restrict hostPath; CIS 5.2.x" },
];

fn sev_label(sev: &str) -> String {
    match sev {
        "critical" => "CRIT".into(),
        "high" => "HIGH".into(),
        "medium" => "MED ".into(),
        "low" => "LOW ".into(),
        "info" => "INFO".into(),
        other => other.to_uppercase(),
    }
}

/// Build the hardened baseline as a deterministic multi-document YAML string.
pub fn generate_bundle(ns: &str, cpu: &str, mem: &str, pods: i64) -> String {
    let docs = [
        format!(
"apiVersion: v1
kind: Namespace
metadata:
  name: {ns}
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
    app.kubernetes.io/managed-by: bastionkit"),
        format!(
"apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: {ns}
spec:
  podSelector: {{}}
  policyTypes:
  - Ingress
  - Egress"),
        format!(
"apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns-egress
  namespace: {ns}
spec:
  podSelector: {{}}
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector: {{}}
    ports:
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 53"),
        format!(
"apiVersion: v1
kind: ResourceQuota
metadata:
  name: baseline-quota
  namespace: {ns}
spec:
  hard:
    requests.cpu: \"{cpu}\"
    requests.memory: \"{mem}\"
    limits.cpu: \"{cpu}\"
    limits.memory: \"{mem}\"
    pods: {pods}
    count/services.loadbalancers: 0"),
        format!(
"apiVersion: v1
kind: ServiceAccount
metadata:
  name: baseline-sa
  namespace: {ns}
automountServiceAccountToken: false"),
        format!(
"apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: baseline-readonly
  namespace: {ns}
rules:
- apiGroups:
  - \"\"
  resources:
  - pods
  - configmaps
  - services
  - endpoints
  verbs:
  - get
  - list
  - watch"),
    ];
    let mut out = String::new();
    for d in docs.iter() {
        out.push_str("---\n");
        out.push_str(d.trim_end());
        out.push('\n');
    }
    out
}

fn run_baseline() -> i32 {
    println!("{} {} — {} baseline controls", TOOL_NAME, TOOL_VERSION, CONTROLS.len());
    println!("{}", "=".repeat(72));
    for c in CONTROLS {
        println!("[{}] {}", sev_label(c.severity), c.rule);
        println!("        {}", c.title);
        println!("        maps to: {}", c.guidance);
    }
    0
}

fn arg<'a>(args: &'a [String], name: &str, fallback: &'a str) -> &'a str {
    for i in 0..args.len().saturating_sub(1) {
        if args[i] == name {
            return &args[i + 1];
        }
    }
    fallback
}

pub fn run(args: &[String]) -> i32 {
    match args.first().map(|s| s.as_str()) {
        Some("--version") => {
            println!("{} {}", TOOL_NAME, TOOL_VERSION);
            0
        }
        Some("baseline") => run_baseline(),
        Some("generate") => {
            let ns = arg(args, "--namespace", "");
            if ns.is_empty() {
                eprintln!("error: generate requires --namespace");
                return 2;
            }
            let pods: i64 = arg(args, "--pod-quota", "50").parse().unwrap_or(50);
            print!("{}", generate_bundle(
                ns,
                arg(args, "--cpu-quota", "4"),
                arg(args, "--memory-quota", "8Gi"),
                pods,
            ));
            0
        }
        _ => {
            eprintln!("usage: bastionkit {{baseline|generate --namespace NS|--version}}");
            2
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    exit(run(&args));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_count_is_16() {
        assert_eq!(CONTROLS.len(), 16);
    }

    #[test]
    fn every_severity_valid() {
        let valid = ["critical", "high", "medium", "low", "info"];
        for c in CONTROLS {
            assert!(valid.contains(&c.severity), "{} bad severity", c.rule);
            assert!(!c.title.is_empty());
            assert!(!c.guidance.is_empty());
        }
    }

    #[test]
    fn rule_ids_unique() {
        let mut seen = std::collections::HashSet::new();
        for c in CONTROLS {
            assert!(seen.insert(c.rule), "duplicate {}", c.rule);
        }
    }

    #[test]
    fn bundle_contains_baseline_kinds() {
        let out = generate_bundle("prod", "4", "8Gi", 50);
        for k in ["kind: Namespace", "kind: NetworkPolicy", "kind: ResourceQuota",
                  "kind: ServiceAccount", "kind: Role"] {
            assert!(out.contains(k), "missing {k}");
        }
    }

    #[test]
    fn bundle_enforces_restricted() {
        let out = generate_bundle("prod", "4", "8Gi", 50);
        assert!(out.contains("pod-security.kubernetes.io/enforce: restricted"));
    }

    #[test]
    fn bundle_default_deny_selects_all() {
        let out = generate_bundle("prod", "4", "8Gi", 50);
        assert!(out.contains("name: default-deny-all"));
        assert!(out.contains("podSelector: {}"));
    }

    #[test]
    fn bundle_disables_automount() {
        let out = generate_bundle("prod", "4", "8Gi", 50);
        assert!(out.contains("automountServiceAccountToken: false"));
    }

    #[test]
    fn bundle_custom_pod_quota() {
        let out = generate_bundle("prod", "4", "8Gi", 7);
        assert!(out.contains("pods: 7"));
    }

    #[test]
    fn bundle_namespace_propagates() {
        let out = generate_bundle("payments", "4", "8Gi", 50);
        assert!(out.contains("namespace: payments"));
    }

    #[test]
    fn run_baseline_exits_zero() {
        assert_eq!(run(&["baseline".to_string()]), 0);
    }

    #[test]
    fn run_generate_requires_namespace() {
        assert_eq!(run(&["generate".to_string()]), 2);
    }

    #[test]
    fn run_version_exits_zero() {
        assert_eq!(run(&["--version".to_string()]), 0);
    }
}
