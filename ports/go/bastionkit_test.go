package main

import (
	"strings"
	"testing"
)

func TestControlCount(t *testing.T) {
	if len(Controls) != 16 {
		t.Fatalf("want 16 controls, got %d", len(Controls))
	}
}

func TestEverySeverityValid(t *testing.T) {
	valid := map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true}
	for _, c := range Controls {
		if !valid[c.Severity] {
			t.Errorf("control %s has invalid severity %q", c.Rule, c.Severity)
		}
		if c.Title == "" || c.Guidance == "" {
			t.Errorf("control %s missing title/guidance", c.Rule)
		}
	}
}

func TestRuleIDsUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range Controls {
		if seen[c.Rule] {
			t.Errorf("duplicate rule id %s", c.Rule)
		}
		seen[c.Rule] = true
	}
}

func TestGenerateContainsBaselineKinds(t *testing.T) {
	out := GenerateBundle("prod", QuotaOpts{})
	for _, k := range []string{"kind: Namespace", "kind: NetworkPolicy",
		"kind: ResourceQuota", "kind: ServiceAccount", "kind: Role"} {
		if !strings.Contains(out, k) {
			t.Errorf("bundle missing %q", k)
		}
	}
}

func TestGenerateRestrictedLabel(t *testing.T) {
	out := GenerateBundle("prod", QuotaOpts{})
	if !strings.Contains(out, "pod-security.kubernetes.io/enforce: restricted") {
		t.Error("bundle does not enforce restricted PodSecurity")
	}
}

func TestGenerateDefaultDeny(t *testing.T) {
	out := GenerateBundle("prod", QuotaOpts{})
	if !strings.Contains(out, "name: default-deny-all") {
		t.Error("bundle missing default-deny NetworkPolicy")
	}
	if !strings.Contains(out, "podSelector: {}") {
		t.Error("default-deny must select all pods")
	}
}

func TestGenerateAutomountDisabled(t *testing.T) {
	out := GenerateBundle("prod", QuotaOpts{})
	if !strings.Contains(out, "automountServiceAccountToken: false") {
		t.Error("service account must disable token automount")
	}
}

func TestGenerateCustomPodQuota(t *testing.T) {
	out := GenerateBundle("prod", QuotaOpts{Pods: 7})
	if !strings.Contains(out, "pods: 7") {
		t.Error("custom pod quota not applied")
	}
}

func TestGenerateNamespacePropagates(t *testing.T) {
	out := GenerateBundle("payments", QuotaOpts{})
	if !strings.Contains(out, "namespace: payments") {
		t.Error("namespace not propagated into bundle")
	}
}

func TestRunBaselineExitsZero(t *testing.T) {
	if rc := run([]string{"baseline"}); rc != 0 {
		t.Errorf("baseline exit = %d, want 0", rc)
	}
}

func TestRunGenerateRequiresNamespace(t *testing.T) {
	if rc := run([]string{"generate"}); rc != 2 {
		t.Errorf("generate without --namespace exit = %d, want 2", rc)
	}
}

func TestRunVersion(t *testing.T) {
	if rc := run([]string{"--version"}); rc != 0 {
		t.Errorf("--version exit = %d, want 0", rc)
	}
}
