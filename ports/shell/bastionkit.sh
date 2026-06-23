#!/usr/bin/env bash
# bastionkit (POSIX shell port) — hardened security baseline for
# air-gapped/regulated Kubernetes. Mirrors the primary command surface of the
# Python reference:
#
#   bastionkit baseline                  list the baseline controls
#   bastionkit generate --namespace NS   emit a hardened baseline YAML bundle
#
# No external tools beyond a POSIX shell + coreutils. Offline; no network.
set -euo pipefail

TOOL_NAME="bastionkit"
TOOL_VERSION="0.1.1"

# rule|severity|title  (guidance omitted here for brevity; full text in core.py)
CONTROLS="\
network.default_deny_missing|high|Namespace has no default-deny NetworkPolicy.
podsec.restricted_missing|high|Namespace does not enforce the PodSecurity 'restricted' profile.
resources.quota_missing|medium|Namespace has no ResourceQuota.
resources.limitrange_missing|medium|Namespace has no LimitRange default requests/limits.
rbac.cluster_admin_binding|critical|A binding grants cluster-admin / wildcard cluster privileges.
rbac.wildcard_rule|high|A Role/ClusterRole uses wildcard verbs, resources, or apiGroups.
rbac.write_to_default_sa|medium|A binding targets the 'default' ServiceAccount.
serviceacct.automount_enabled|medium|ServiceAccount token automount is not disabled.
workload.run_as_root|high|Container may run as root (runAsNonRoot not set true).
workload.privileged|critical|Container requests privileged mode.
workload.privilege_escalation|high|Container allows privilege escalation.
workload.writable_rootfs|medium|Container root filesystem is writable.
workload.caps_not_dropped|medium|Container does not drop ALL Linux capabilities.
workload.no_resource_limits|low|Container sets no CPU/memory limits.
workload.host_namespace|high|Workload shares a host namespace (hostNetwork/hostPID/hostIPC).
workload.host_path|high|Workload mounts a hostPath volume."

sev_label() {
  case "$1" in
    critical) printf 'CRIT' ;;
    high)     printf 'HIGH' ;;
    medium)   printf 'MED ' ;;
    low)      printf 'LOW ' ;;
    info)     printf 'INFO' ;;
    *)        printf '%s' "$(printf '%s' "$1" | tr '[:lower:]' '[:upper:]')" ;;
  esac
}

cmd_baseline() {
  local count
  count=$(printf '%s\n' "$CONTROLS" | grep -c '|')
  printf '%s %s — %s baseline controls\n' "$TOOL_NAME" "$TOOL_VERSION" "$count"
  printf '%0.s=' $(seq 1 72); printf '\n'
  printf '%s\n' "$CONTROLS" | while IFS='|' read -r rule sev title; do
    printf '[%s] %s\n' "$(sev_label "$sev")" "$rule"
    printf '        %s\n' "$title"
  done
}

cmd_generate() {
  local ns="" cpu="4" mem="8Gi" pods="50"
  while [ $# -gt 0 ]; do
    case "$1" in
      --namespace) ns="$2"; shift 2 ;;
      --cpu-quota) cpu="$2"; shift 2 ;;
      --memory-quota) mem="$2"; shift 2 ;;
      --pod-quota) pods="$2"; shift 2 ;;
      *) shift ;;
    esac
  done
  if [ -z "$ns" ]; then
    echo "error: generate requires --namespace" >&2
    return 2
  fi
  cat <<YAML
---
apiVersion: v1
kind: Namespace
metadata:
  name: ${ns}
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
    app.kubernetes.io/managed-by: bastionkit
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: ${ns}
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
---
apiVersion: v1
kind: ResourceQuota
metadata:
  name: baseline-quota
  namespace: ${ns}
spec:
  hard:
    requests.cpu: "${cpu}"
    requests.memory: "${mem}"
    limits.cpu: "${cpu}"
    limits.memory: "${mem}"
    pods: ${pods}
    count/services.loadbalancers: 0
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: baseline-sa
  namespace: ${ns}
automountServiceAccountToken: false
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: baseline-readonly
  namespace: ${ns}
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
  - watch
YAML
}

main() {
  local sub="${1:-}"
  case "$sub" in
    --version) printf '%s %s\n' "$TOOL_NAME" "$TOOL_VERSION" ;;
    baseline)  cmd_baseline ;;
    generate)  shift; cmd_generate "$@" ;;
    *) echo "usage: bastionkit {baseline|generate --namespace NS|--version}" >&2; return 2 ;;
  esac
}

main "$@"
