#!/usr/bin/env bash
# Smoke test for the bastionkit shell port. No external deps beyond coreutils.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
bk="$here/bastionkit.sh"
fail=0

check() { # desc, command-output, needle
  if printf '%s' "$2" | grep -q -- "$3"; then
    echo "ok   - $1"
  else
    echo "FAIL - $1 (missing: $3)"; fail=1
  fi
}

out="$(bash "$bk" baseline)"
check "baseline lists 16 controls" "$out" "16 baseline controls"
check "baseline shows privileged control" "$out" "workload.privileged"
check "baseline shows cluster-admin control" "$out" "rbac.cluster_admin_binding"

gen="$(bash "$bk" generate --namespace prod --pod-quota 7)"
check "generate emits Namespace" "$gen" "kind: Namespace"
check "generate emits NetworkPolicy" "$gen" "kind: NetworkPolicy"
check "generate enforces restricted" "$gen" "pod-security.kubernetes.io/enforce: restricted"
check "generate default-deny selects all pods" "$gen" "podSelector: {}"
check "generate disables automount" "$gen" "automountServiceAccountToken: false"
check "generate applies custom pod quota" "$gen" "pods: 7"
check "generate propagates namespace" "$gen" "namespace: prod"

ver="$(bash "$bk" --version)"
check "version reports bastionkit" "$ver" "bastionkit"

# generate without --namespace must exit 2
if bash "$bk" generate >/dev/null 2>&1; then
  echo "FAIL - generate without namespace should exit nonzero"; fail=1
else
  echo "ok   - generate without namespace exits nonzero"
fi

if [ "$fail" -eq 0 ]; then echo "ALL SHELL PORT TESTS PASSED"; else echo "SHELL PORT TESTS FAILED"; fi
exit "$fail"
