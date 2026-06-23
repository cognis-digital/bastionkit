// Command bastionkit (Go port) — hardened security baseline for
// air-gapped/regulated Kubernetes. Mirrors the primary command surface of the
// Python reference implementation:
//
//	bastionkit baseline                  list the baseline controls
//	bastionkit generate --namespace NS   emit a hardened baseline YAML bundle
//
// Standard library only; offline; no network access. The control catalogue and
// the generated bundle mirror core.py / generate.py so the ports stay in
// lock-step with the reference implementation.
package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	toolName    = "bastionkit"
	toolVersion = "0.1.1"
)

var sevLabel = map[string]string{
	"critical": "CRIT", "high": "HIGH", "medium": "MED ",
	"low": "LOW ", "info": "INFO",
}

// Control mirrors one entry of CONTROLS in core.py.
type Control struct {
	Rule, Severity, Title, Guidance string
}

// Controls is the baseline catalogue (kept in lock-step with core.py).
var Controls = []Control{
	{"network.default_deny_missing", "high",
		"Namespace has no default-deny NetworkPolicy.",
		"NSA/CISA: network separation & firewalling; CIS 5.3 (Network Policies)"},
	{"podsec.restricted_missing", "high",
		"Namespace does not enforce the PodSecurity 'restricted' profile.",
		"NSA/CISA: Pod Security; CIS 5.2 (Pod Security Standards)"},
	{"resources.quota_missing", "medium",
		"Namespace has no ResourceQuota.",
		"NSA/CISA: resource limits to bound DoS; CIS 5.7 (General Policies)"},
	{"resources.limitrange_missing", "medium",
		"Namespace has no LimitRange default requests/limits.",
		"NSA/CISA: resource limits; CIS 5.7"},
	{"rbac.cluster_admin_binding", "critical",
		"A binding grants cluster-admin / wildcard cluster privileges.",
		"NSA/CISA: RBAC least privilege; CIS 5.1 (RBAC and Service Accounts)"},
	{"rbac.wildcard_rule", "high",
		"A Role/ClusterRole uses wildcard verbs, resources, or apiGroups.",
		"NSA/CISA: RBAC least privilege; CIS 5.1"},
	{"rbac.write_to_default_sa", "medium",
		"A binding targets the 'default' ServiceAccount.",
		"NSA/CISA: minimize default service account use; CIS 5.1.5"},
	{"serviceacct.automount_enabled", "medium",
		"ServiceAccount token automount is not disabled.",
		"NSA/CISA: disable token automount when unused; CIS 5.1.6"},
	{"workload.run_as_root", "high",
		"Container may run as root (runAsNonRoot not set true).",
		"NSA/CISA: non-root containers; CIS 5.2.6"},
	{"workload.privileged", "critical",
		"Container requests privileged mode.",
		"NSA/CISA: deny privileged containers; CIS 5.2.1"},
	{"workload.privilege_escalation", "high",
		"Container allows privilege escalation.",
		"NSA/CISA: allowPrivilegeEscalation=false; CIS 5.2.5"},
	{"workload.writable_rootfs", "medium",
		"Container root filesystem is writable.",
		"NSA/CISA: immutable runtime; CIS 5.2.x (read-only root FS)"},
	{"workload.caps_not_dropped", "medium",
		"Container does not drop ALL Linux capabilities.",
		"NSA/CISA: drop capabilities; CIS 5.2.7-9"},
	{"workload.no_resource_limits", "low",
		"Container sets no CPU/memory limits.",
		"NSA/CISA: resource limits; CIS 5.7"},
	{"workload.host_namespace", "high",
		"Workload shares a host namespace (hostNetwork/hostPID/hostIPC).",
		"NSA/CISA: avoid host namespaces; CIS 5.2.2-4"},
	{"workload.host_path", "high",
		"Workload mounts a hostPath volume.",
		"NSA/CISA: restrict hostPath; CIS 5.2.x"},
}

// QuotaOpts configures the generated ResourceQuota.
type QuotaOpts struct {
	CPU, Memory string
	Pods        int
}

// GenerateBundle returns the hardened baseline as a deterministic multi-document
// YAML string. The serializer is hand-written to avoid third-party deps and to
// match the byte layout of the Python generator.
func GenerateBundle(ns string, o QuotaOpts) string {
	if o.CPU == "" {
		o.CPU = "4"
	}
	if o.Memory == "" {
		o.Memory = "8Gi"
	}
	if o.Pods == 0 {
		o.Pods = 50
	}
	var b strings.Builder
	doc := func(s string) {
		b.WriteString("---\n")
		b.WriteString(strings.TrimRight(s, "\n"))
		b.WriteString("\n")
	}
	doc(fmt.Sprintf(`apiVersion: v1
kind: Namespace
metadata:
  name: %s
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
    app.kubernetes.io/managed-by: bastionkit`, ns))
	doc(fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: %s
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress`, ns))
	doc(fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns-egress
  namespace: %s
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector: {}
    ports:
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 53`, ns))
	doc(fmt.Sprintf(`apiVersion: v1
kind: ResourceQuota
metadata:
  name: baseline-quota
  namespace: %s
spec:
  hard:
    requests.cpu: %q
    requests.memory: %q
    limits.cpu: %q
    limits.memory: %q
    pods: %d
    count/services.loadbalancers: 0`, ns, o.CPU, o.Memory, o.CPU, o.Memory, o.Pods))
	doc(fmt.Sprintf(`apiVersion: v1
kind: ServiceAccount
metadata:
  name: baseline-sa
  namespace: %s
automountServiceAccountToken: false`, ns))
	doc(fmt.Sprintf(`apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: baseline-readonly
  namespace: %s
rules:
- apiGroups:
  - ""
  resources:
  - pods
  - configmaps
  - services
  - endpoints
  verbs:
  - get
  - list
  - watch`, ns))
	return b.String()
}

func runBaseline() int {
	fmt.Printf("%s %s — %d baseline controls\n", toolName, toolVersion, len(Controls))
	fmt.Println(strings.Repeat("=", 72))
	for _, c := range Controls {
		lab := sevLabel[c.Severity]
		if lab == "" {
			lab = strings.ToUpper(c.Severity)
		}
		fmt.Printf("[%s] %s\n", lab, c.Rule)
		fmt.Printf("        %s\n", c.Title)
		fmt.Printf("        maps to: %s\n", c.Guidance)
	}
	return 0
}

func arg(args []string, name, fallback string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == name {
			return args[i+1]
		}
	}
	return fallback
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: bastionkit {baseline|generate --namespace NS|--version}")
		return 2
	}
	switch args[0] {
	case "--version":
		fmt.Printf("%s %s\n", toolName, toolVersion)
		return 0
	case "baseline":
		return runBaseline()
	case "generate":
		ns := arg(args, "--namespace", "")
		if ns == "" {
			fmt.Fprintln(os.Stderr, "error: generate requires --namespace")
			return 2
		}
		pods, err := strconv.Atoi(arg(args, "--pod-quota", "50"))
		if err != nil {
			pods = 50
		}
		fmt.Print(GenerateBundle(ns, QuotaOpts{
			CPU:    arg(args, "--cpu-quota", "4"),
			Memory: arg(args, "--memory-quota", "8Gi"),
			Pods:   pods,
		}))
		return 0
	default:
		fmt.Fprintln(os.Stderr, "usage: bastionkit {baseline|generate --namespace NS|--version}")
		return 2
	}
}

func main() { os.Exit(run(os.Args[1:])) }
