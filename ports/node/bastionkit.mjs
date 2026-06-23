#!/usr/bin/env node
// bastionkit (Node port) — hardened security baseline for air-gapped/regulated
// Kubernetes. Mirrors the primary command surface of the Python reference:
//
//   bastionkit baseline                     list the baseline controls
//   bastionkit generate --namespace NS      emit a hardened baseline YAML bundle
//
// Standard library only (no npm deps). Offline / no network. The control
// catalogue and generated bundle are kept byte-for-concept identical to the
// Python implementation so the ports stay in lock-step.

const TOOL_NAME = "bastionkit";
const TOOL_VERSION = "0.1.1";

const SEV_LABEL = {
  critical: "CRIT",
  high: "HIGH",
  medium: "MED ",
  low: "LOW ",
  info: "INFO",
};

// (ruleId, severity, title, guidance) — mirrors CONTROLS in core.py.
const CONTROLS = [
  ["network.default_deny_missing", "high",
   "Namespace has no default-deny NetworkPolicy.",
   "NSA/CISA: network separation & firewalling; CIS 5.3 (Network Policies)"],
  ["podsec.restricted_missing", "high",
   "Namespace does not enforce the PodSecurity 'restricted' profile.",
   "NSA/CISA: Pod Security; CIS 5.2 (Pod Security Standards)"],
  ["resources.quota_missing", "medium",
   "Namespace has no ResourceQuota.",
   "NSA/CISA: resource limits to bound DoS; CIS 5.7 (General Policies)"],
  ["resources.limitrange_missing", "medium",
   "Namespace has no LimitRange default requests/limits.",
   "NSA/CISA: resource limits; CIS 5.7"],
  ["rbac.cluster_admin_binding", "critical",
   "A binding grants cluster-admin / wildcard cluster privileges.",
   "NSA/CISA: RBAC least privilege; CIS 5.1 (RBAC and Service Accounts)"],
  ["rbac.wildcard_rule", "high",
   "A Role/ClusterRole uses wildcard verbs, resources, or apiGroups.",
   "NSA/CISA: RBAC least privilege; CIS 5.1"],
  ["rbac.write_to_default_sa", "medium",
   "A binding targets the 'default' ServiceAccount.",
   "NSA/CISA: minimize default service account use; CIS 5.1.5"],
  ["serviceacct.automount_enabled", "medium",
   "ServiceAccount token automount is not disabled.",
   "NSA/CISA: disable token automount when unused; CIS 5.1.6"],
  ["workload.run_as_root", "high",
   "Container may run as root (runAsNonRoot not set true).",
   "NSA/CISA: non-root containers; CIS 5.2.6"],
  ["workload.privileged", "critical",
   "Container requests privileged mode.",
   "NSA/CISA: deny privileged containers; CIS 5.2.1"],
  ["workload.privilege_escalation", "high",
   "Container allows privilege escalation.",
   "NSA/CISA: allowPrivilegeEscalation=false; CIS 5.2.5"],
  ["workload.writable_rootfs", "medium",
   "Container root filesystem is writable.",
   "NSA/CISA: immutable runtime; CIS 5.2.x (read-only root FS)"],
  ["workload.caps_not_dropped", "medium",
   "Container does not drop ALL Linux capabilities.",
   "NSA/CISA: drop capabilities; CIS 5.2.7-9"],
  ["workload.no_resource_limits", "low",
   "Container sets no CPU/memory limits.",
   "NSA/CISA: resource limits; CIS 5.7"],
  ["workload.host_namespace", "high",
   "Workload shares a host namespace (hostNetwork/hostPID/hostIPC).",
   "NSA/CISA: avoid host namespaces; CIS 5.2.2-4"],
  ["workload.host_path", "high",
   "Workload mounts a hostPath volume.",
   "NSA/CISA: restrict hostPath; CIS 5.2.x"],
];

// --- minimal YAML emitter (block style, deterministic) -------------------
function q(v) {
  if (typeof v === "boolean") return v ? "true" : "false";
  if (v === null || v === undefined) return "null";
  if (typeof v === "number") return String(v);
  const s = String(v);
  const needs =
    s === "" ||
    "!&*?{}[],#|>@`\"'%".includes(s[0]) ||
    s.includes(":") ||
    s.trim() !== s ||
    ["true", "false", "null", "yes", "no"].includes(s.toLowerCase());
  return needs ? '"' + s.replace(/"/g, '\\"') + '"' : s;
}

function dump(obj, indent = 0) {
  const pad = "  ".repeat(indent);
  const lines = [];
  for (const [k, v] of Object.entries(obj)) {
    if (v !== null && typeof v === "object" && !Array.isArray(v)) {
      if (Object.keys(v).length) {
        lines.push(`${pad}${k}:`);
        lines.push(...dump(v, indent + 1));
      } else {
        lines.push(`${pad}${k}: {}`);
      }
    } else if (Array.isArray(v)) {
      if (v.length) {
        lines.push(`${pad}${k}:`);
        lines.push(...dumpList(v, indent));
      } else {
        lines.push(`${pad}${k}: []`);
      }
    } else {
      lines.push(`${pad}${k}: ${q(v)}`);
    }
  }
  return lines;
}

function dumpList(items, indent) {
  const pad = "  ".repeat(indent);
  const lines = [];
  for (const item of items) {
    if (item !== null && typeof item === "object" && !Array.isArray(item)) {
      const sub = dump(item, indent + 1);
      if (sub.length) {
        lines.push(`${pad}- ${sub[0].trimStart()}`);
        lines.push(...sub.slice(1));
      } else {
        lines.push(`${pad}- {}`);
      }
    } else {
      lines.push(`${pad}- ${q(item)}`);
    }
  }
  return lines;
}

function dumpDocuments(docs) {
  return "---\n" + docs.map((d) => dump(d, 0).join("\n")).join("\n---\n") + "\n";
}

function baselineDocuments(ns, { cpuQuota = "4", memoryQuota = "8Gi", podQuota = 50 } = {}) {
  const labels = {
    "pod-security.kubernetes.io/enforce": "restricted",
    "pod-security.kubernetes.io/enforce-version": "latest",
    "pod-security.kubernetes.io/audit": "restricted",
    "pod-security.kubernetes.io/warn": "restricted",
    "app.kubernetes.io/managed-by": "bastionkit",
  };
  return [
    { apiVersion: "v1", kind: "Namespace", metadata: { name: ns, labels } },
    {
      apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy",
      metadata: { name: "default-deny-all", namespace: ns },
      spec: { podSelector: {}, policyTypes: ["Ingress", "Egress"] },
    },
    {
      apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy",
      metadata: { name: "allow-dns-egress", namespace: ns },
      spec: {
        podSelector: {}, policyTypes: ["Egress"],
        egress: [{
          to: [{ namespaceSelector: {} }],
          ports: [{ protocol: "UDP", port: 53 }, { protocol: "TCP", port: 53 }],
        }],
      },
    },
    {
      apiVersion: "v1", kind: "ResourceQuota",
      metadata: { name: "baseline-quota", namespace: ns },
      spec: {
        hard: {
          "requests.cpu": cpuQuota, "requests.memory": memoryQuota,
          "limits.cpu": cpuQuota, "limits.memory": memoryQuota,
          pods: podQuota, "count/services.loadbalancers": 0,
        },
      },
    },
    {
      apiVersion: "v1", kind: "LimitRange",
      metadata: { name: "baseline-limits", namespace: ns },
      spec: {
        limits: [{
          type: "Container",
          default: { cpu: "500m", memory: "512Mi" },
          defaultRequest: { cpu: "100m", memory: "128Mi" },
          max: { cpu: "2", memory: "2Gi" },
        }],
      },
    },
    {
      apiVersion: "v1", kind: "ServiceAccount",
      metadata: { name: "baseline-sa", namespace: ns },
      automountServiceAccountToken: false,
    },
    {
      apiVersion: "rbac.authorization.k8s.io/v1", kind: "Role",
      metadata: { name: "baseline-readonly", namespace: ns },
      rules: [{
        apiGroups: [""], resources: ["pods", "configmaps", "services", "endpoints"],
        verbs: ["get", "list", "watch"],
      }],
    },
    {
      apiVersion: "rbac.authorization.k8s.io/v1", kind: "RoleBinding",
      metadata: { name: "baseline-readonly-binding", namespace: ns },
      roleRef: {
        apiGroup: "rbac.authorization.k8s.io", kind: "Role", name: "baseline-readonly",
      },
      subjects: [{ kind: "ServiceAccount", name: "baseline-sa", namespace: ns }],
    },
    {
      apiVersion: "admissionregistration.k8s.io/v1", kind: "ValidatingAdmissionPolicy",
      metadata: { name: "baseline-deny-privileged" },
      spec: {
        failurePolicy: "Fail",
        matchConstraints: {
          resourceRules: [{
            apiGroups: [""], apiVersions: ["v1"],
            operations: ["CREATE", "UPDATE"], resources: ["pods"],
          }],
        },
        validations: [{
          expression:
            "!object.spec.containers.exists(c, has(c.securityContext) && " +
            "c.securityContext.privileged == true)",
          message: "privileged containers are denied by the bastionkit baseline",
        }],
      },
    },
  ];
}

function generateBundle(ns, opts) {
  return dumpDocuments(baselineDocuments(ns, opts));
}

function runBaseline() {
  console.log(`${TOOL_NAME} ${TOOL_VERSION} — ${CONTROLS.length} baseline controls`);
  console.log("=".repeat(72));
  for (const [rule, sev, title, guidance] of CONTROLS) {
    console.log(`[${SEV_LABEL[sev] || sev.toUpperCase()}] ${rule}`);
    console.log(`        ${title}`);
    console.log(`        maps to: ${guidance}`);
  }
  return 0;
}

function parseArg(argv, name, fallback) {
  const i = argv.indexOf(name);
  return i >= 0 && i + 1 < argv.length ? argv[i + 1] : fallback;
}

function main(argv) {
  const cmd = argv[0];
  if (cmd === "--version") {
    console.log(`${TOOL_NAME} ${TOOL_VERSION}`);
    return 0;
  }
  if (cmd === "baseline") return runBaseline();
  if (cmd === "generate") {
    const ns = parseArg(argv, "--namespace");
    if (!ns) {
      console.error("error: generate requires --namespace");
      return 2;
    }
    process.stdout.write(generateBundle(ns, {
      cpuQuota: parseArg(argv, "--cpu-quota", "4"),
      memoryQuota: parseArg(argv, "--memory-quota", "8Gi"),
      podQuota: Number(parseArg(argv, "--pod-quota", "50")),
    }));
    return 0;
  }
  console.error("usage: bastionkit {baseline|generate --namespace NS|--version}");
  return 2;
}

export { CONTROLS, TOOL_NAME, TOOL_VERSION, baselineDocuments, generateBundle, dumpDocuments, q, main };

import { fileURLToPath } from "node:url";
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  process.exit(main(process.argv.slice(2)));
}
