"""Per-control behavioral tests for the bastionkit baseline engine.

Standard library only, no network. Each baseline control is exercised both in
its violating and its satisfied state, plus scoring, serialization, and
namespace-bucketing edge cases.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bastionkit import (
    CONTROLS,
    SEVERITY_ORDER,
    Finding,
    Report,
    assess_documents,
    to_sarif,
)
from bastionkit.core import (
    _has_default_deny,
    _enforces_restricted,
    _pod_spec,
    _security_severity,
    _SARIF_LEVEL,
)


def _rules(docs):
    reports = assess_documents(docs, source="t")
    return {f.rule for r in reports for f in r.findings}


def _pod(container_sc=None, pod_extra=None, ns="n"):
    pod = {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "p", "namespace": ns},
        "spec": {"containers": [{"name": "c",
                 "securityContext": container_sc or {}}]},
    }
    if pod_extra:
        pod["spec"].update(pod_extra)
    return pod


HARDENED_SC = {
    "runAsNonRoot": True,
    "allowPrivilegeEscalation": False,
    "readOnlyRootFilesystem": True,
    "privileged": False,
    "capabilities": {"drop": ["ALL"]},
}


class TestControlCatalogue(unittest.TestCase):
    def test_catalogue_nonempty(self):
        self.assertGreaterEqual(len(CONTROLS), 16)

    def test_every_control_has_four_fields(self):
        for c in CONTROLS:
            self.assertEqual(len(c), 4, c)

    def test_every_severity_valid(self):
        for rule, sev, title, guidance in CONTROLS:
            self.assertIn(sev, SEVERITY_ORDER, rule)

    def test_every_control_has_title(self):
        for rule, sev, title, guidance in CONTROLS:
            self.assertTrue(title.strip(), rule)

    def test_every_control_maps_to_guidance(self):
        for rule, sev, title, guidance in CONTROLS:
            self.assertTrue(guidance.strip(), rule)

    def test_rule_ids_unique(self):
        ids = [c[0] for c in CONTROLS]
        self.assertEqual(len(ids), len(set(ids)))


class TestWorkloadPrivileged(unittest.TestCase):
    def test_privileged_flagged(self):
        self.assertIn("workload.privileged", _rules([_pod({"privileged": True})]))

    def test_not_privileged_clean(self):
        self.assertNotIn("workload.privileged",
                         _rules([_pod(HARDENED_SC)]))

    def test_privileged_is_critical(self):
        reports = assess_documents([_pod({"privileged": True})], source="t")
        f = [f for r in reports for f in r.findings
             if f.rule == "workload.privileged"][0]
        self.assertEqual(f.severity, "critical")


class TestWorkloadRunAsRoot(unittest.TestCase):
    def test_default_flagged(self):
        self.assertIn("workload.run_as_root", _rules([_pod({})]))

    def test_container_nonroot_clean(self):
        self.assertNotIn("workload.run_as_root",
                         _rules([_pod({"runAsNonRoot": True})]))

    def test_pod_level_nonroot_satisfies_container(self):
        pod = _pod({}, pod_extra={"securityContext": {"runAsNonRoot": True}})
        self.assertNotIn("workload.run_as_root", _rules([pod]))


class TestWorkloadEscalation(unittest.TestCase):
    def test_default_flagged(self):
        self.assertIn("workload.privilege_escalation", _rules([_pod({})]))

    def test_false_clean(self):
        self.assertNotIn("workload.privilege_escalation",
                         _rules([_pod({"allowPrivilegeEscalation": False})]))


class TestWorkloadRootfs(unittest.TestCase):
    def test_default_flagged(self):
        self.assertIn("workload.writable_rootfs", _rules([_pod({})]))

    def test_readonly_clean(self):
        self.assertNotIn("workload.writable_rootfs",
                         _rules([_pod({"readOnlyRootFilesystem": True})]))


class TestWorkloadCapabilities(unittest.TestCase):
    def test_no_drop_flagged(self):
        self.assertIn("workload.caps_not_dropped", _rules([_pod({})]))

    def test_drop_all_clean(self):
        self.assertNotIn("workload.caps_not_dropped",
                         _rules([_pod({"capabilities": {"drop": ["ALL"]}})]))

    def test_drop_all_case_insensitive(self):
        self.assertNotIn("workload.caps_not_dropped",
                         _rules([_pod({"capabilities": {"drop": ["all"]}})]))

    def test_partial_drop_flagged(self):
        self.assertIn("workload.caps_not_dropped",
                      _rules([_pod({"capabilities": {"drop": ["NET_RAW"]}})]))


class TestWorkloadResourceLimits(unittest.TestCase):
    def test_no_limits_flagged(self):
        self.assertIn("workload.no_resource_limits", _rules([_pod({})]))

    def test_both_limits_clean(self):
        pod = _pod(HARDENED_SC)
        pod["spec"]["containers"][0]["resources"] = {
            "limits": {"cpu": "500m", "memory": "256Mi"}}
        self.assertNotIn("workload.no_resource_limits", _rules([pod]))

    def test_cpu_only_still_flagged(self):
        pod = _pod({})
        pod["spec"]["containers"][0]["resources"] = {"limits": {"cpu": "1"}}
        self.assertIn("workload.no_resource_limits", _rules([pod]))


class TestWorkloadHostNamespaces(unittest.TestCase):
    def test_host_network_flagged(self):
        self.assertIn("workload.host_namespace",
                      _rules([_pod({}, {"hostNetwork": True})]))

    def test_host_pid_flagged(self):
        self.assertIn("workload.host_namespace",
                      _rules([_pod({}, {"hostPID": True})]))

    def test_host_ipc_flagged(self):
        self.assertIn("workload.host_namespace",
                      _rules([_pod({}, {"hostIPC": True})]))

    def test_no_host_namespace_clean(self):
        self.assertNotIn("workload.host_namespace", _rules([_pod(HARDENED_SC)]))


class TestWorkloadHostPath(unittest.TestCase):
    def test_hostpath_flagged(self):
        pod = _pod({}, {"volumes": [{"name": "v", "hostPath": {"path": "/"}}]})
        self.assertIn("workload.host_path", _rules([pod]))

    def test_emptydir_clean(self):
        pod = _pod(HARDENED_SC, {"volumes": [{"name": "v", "emptyDir": {}}]})
        self.assertNotIn("workload.host_path", _rules([pod]))


class TestWorkloadKinds(unittest.TestCase):
    def _wrap(self, kind):
        return {
            "apiVersion": "apps/v1", "kind": kind,
            "metadata": {"name": "w", "namespace": "n"},
            "spec": {"template": {"spec": {"containers": [
                {"name": "c", "securityContext": {"privileged": True}}]}}},
        }

    def test_deployment_scanned(self):
        self.assertIn("workload.privileged", _rules([self._wrap("Deployment")]))

    def test_statefulset_scanned(self):
        self.assertIn("workload.privileged", _rules([self._wrap("StatefulSet")]))

    def test_daemonset_scanned(self):
        self.assertIn("workload.privileged", _rules([self._wrap("DaemonSet")]))

    def test_job_scanned(self):
        self.assertIn("workload.privileged", _rules([self._wrap("Job")]))

    def test_cronjob_pod_spec_found(self):
        cj = {
            "apiVersion": "batch/v1", "kind": "CronJob",
            "metadata": {"name": "cj", "namespace": "n"},
            "spec": {"jobTemplate": {"spec": {"template": {"spec": {
                "containers": [{"name": "c",
                                "securityContext": {"privileged": True}}]}}}}},
        }
        self.assertIsNotNone(_pod_spec(cj))
        self.assertIn("workload.privileged", _rules([cj]))

    def test_init_containers_scanned(self):
        pod = _pod(HARDENED_SC)
        pod["spec"]["initContainers"] = [
            {"name": "init", "securityContext": {"privileged": True}}]
        self.assertIn("workload.privileged", _rules([pod]))


class TestRbac(unittest.TestCase):
    def test_wildcard_verbs_flagged(self):
        role = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                "metadata": {"name": "r", "namespace": "n"},
                "rules": [{"apiGroups": [""], "resources": ["pods"],
                           "verbs": ["*"]}]}
        self.assertIn("rbac.wildcard_rule", _rules([role]))

    def test_wildcard_resources_flagged(self):
        role = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                "metadata": {"name": "r", "namespace": "n"},
                "rules": [{"apiGroups": [""], "resources": ["*"],
                           "verbs": ["get"]}]}
        self.assertIn("rbac.wildcard_rule", _rules([role]))

    def test_explicit_rule_clean(self):
        role = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                "metadata": {"name": "r", "namespace": "n"},
                "rules": [{"apiGroups": [""], "resources": ["pods"],
                           "verbs": ["get", "list"]}]}
        self.assertNotIn("rbac.wildcard_rule", _rules([role]))

    def test_cluster_admin_binding_critical(self):
        b = {"apiVersion": "rbac.authorization.k8s.io/v1",
             "kind": "ClusterRoleBinding", "metadata": {"name": "b"},
             "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
             "subjects": [{"kind": "ServiceAccount", "name": "x",
                           "namespace": "n"}]}
        self.assertIn("rbac.cluster_admin_binding", _rules([b]))

    def test_admin_clusterrole_binding_flagged(self):
        b = {"apiVersion": "rbac.authorization.k8s.io/v1",
             "kind": "ClusterRoleBinding", "metadata": {"name": "b"},
             "roleRef": {"kind": "ClusterRole", "name": "admin"},
             "subjects": [{"kind": "User", "name": "x"}]}
        self.assertIn("rbac.cluster_admin_binding", _rules([b]))

    def test_namespaced_rolebinding_not_cluster_admin(self):
        b = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
             "metadata": {"name": "b", "namespace": "n"},
             "roleRef": {"kind": "Role", "name": "cluster-admin"},
             "subjects": [{"kind": "User", "name": "x"}]}
        self.assertNotIn("rbac.cluster_admin_binding", _rules([b]))

    def test_default_sa_binding_flagged(self):
        b = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
             "metadata": {"name": "b", "namespace": "n"},
             "roleRef": {"kind": "Role", "name": "r"},
             "subjects": [{"kind": "ServiceAccount", "name": "default",
                           "namespace": "n"}]}
        self.assertIn("rbac.write_to_default_sa", _rules([b]))

    def test_named_sa_binding_clean(self):
        b = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
             "metadata": {"name": "b", "namespace": "n"},
             "roleRef": {"kind": "Role", "name": "r"},
             "subjects": [{"kind": "ServiceAccount", "name": "app-sa",
                           "namespace": "n"}]}
        self.assertNotIn("rbac.write_to_default_sa", _rules([b]))


class TestServiceAccount(unittest.TestCase):
    def test_automount_default_flagged(self):
        sa = {"apiVersion": "v1", "kind": "ServiceAccount",
              "metadata": {"name": "s", "namespace": "n"}}
        self.assertIn("serviceacct.automount_enabled", _rules([sa]))

    def test_automount_true_flagged(self):
        sa = {"apiVersion": "v1", "kind": "ServiceAccount",
              "metadata": {"name": "s", "namespace": "n"},
              "automountServiceAccountToken": True}
        self.assertIn("serviceacct.automount_enabled", _rules([sa]))

    def test_automount_false_clean(self):
        sa = {"apiVersion": "v1", "kind": "ServiceAccount",
              "metadata": {"name": "s", "namespace": "n"},
              "automountServiceAccountToken": False}
        self.assertNotIn("serviceacct.automount_enabled", _rules([sa]))


class TestNamespaceControls(unittest.TestCase):
    def test_default_deny_missing_flagged(self):
        # Deployment in ns with no NetworkPolicy
        d = {"apiVersion": "apps/v1", "kind": "Deployment",
             "metadata": {"name": "d", "namespace": "n"},
             "spec": {"template": {"spec": {"containers": [
                 {"name": "c", "securityContext": HARDENED_SC}]}}}}
        self.assertIn("network.default_deny_missing", _rules([d]))

    def test_default_deny_present_clean(self):
        np = {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
              "metadata": {"name": "dd", "namespace": "n"},
              "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}}
        self.assertTrue(_has_default_deny([np["spec"] and np]))
        self.assertNotIn("network.default_deny_missing",
                         _rules([np]))

    def test_allow_rule_is_not_default_deny(self):
        np = {"spec": {"podSelector": {}, "policyTypes": ["Ingress"],
                       "ingress": [{"from": [{"podSelector": {}}]}]}}
        self.assertFalse(_has_default_deny([np]))

    def test_quota_missing_flagged(self):
        d = {"apiVersion": "apps/v1", "kind": "Deployment",
             "metadata": {"name": "d", "namespace": "qn"},
             "spec": {"template": {"spec": {"containers": [
                 {"name": "c", "securityContext": HARDENED_SC}]}}}}
        self.assertIn("resources.quota_missing", _rules([d]))

    def test_quota_present_clean(self):
        rq = {"apiVersion": "v1", "kind": "ResourceQuota",
              "metadata": {"name": "q", "namespace": "qn"},
              "spec": {"hard": {"pods": 10}}}
        # add a netpol+limitrange so only quota is under test
        self.assertNotIn("resources.quota_missing", _rules([rq]))

    def test_limitrange_present_clean(self):
        lr = {"apiVersion": "v1", "kind": "LimitRange",
              "metadata": {"name": "l", "namespace": "ln"},
              "spec": {"limits": []}}
        self.assertNotIn("resources.limitrange_missing", _rules([lr]))

    def test_restricted_label_satisfies(self):
        ns = {"apiVersion": "v1", "kind": "Namespace",
              "metadata": {"name": "n", "labels": {
                  "pod-security.kubernetes.io/enforce": "restricted"}}}
        self.assertTrue(_enforces_restricted(ns))
        self.assertNotIn("podsec.restricted_missing", _rules([ns]))

    def test_missing_label_flagged(self):
        ns = {"apiVersion": "v1", "kind": "Namespace",
              "metadata": {"name": "n"}}
        self.assertFalse(_enforces_restricted(ns))
        self.assertIn("podsec.restricted_missing", _rules([ns]))

    def test_baseline_label_not_restricted(self):
        ns = {"apiVersion": "v1", "kind": "Namespace",
              "metadata": {"name": "n", "labels": {
                  "pod-security.kubernetes.io/enforce": "baseline"}}}
        self.assertFalse(_enforces_restricted(ns))


class TestScoring(unittest.TestCase):
    def test_clean_report_scores_100(self):
        r = Report(source="t", namespace="n", findings=[])
        self.assertEqual(r.score, 100)

    def test_critical_dominates(self):
        r = Report(source="t", namespace="n", findings=[
            Finding("x", "critical", "m")])
        self.assertEqual(r.score, 60)

    def test_score_floor_zero(self):
        r = Report(source="t", namespace="n", findings=[
            Finding("a", "critical", "m"), Finding("b", "critical", "m"),
            Finding("c", "critical", "m")])
        self.assertEqual(r.score, 0)

    def test_failed_on_high(self):
        r = Report(source="t", namespace="n", findings=[
            Finding("x", "high", "m")])
        self.assertTrue(r.failed)

    def test_not_failed_on_medium(self):
        r = Report(source="t", namespace="n", findings=[
            Finding("x", "medium", "m")])
        self.assertFalse(r.failed)

    def test_counts_sum(self):
        r = Report(source="t", namespace="n", findings=[
            Finding("a", "high", "m"), Finding("b", "low", "m"),
            Finding("c", "low", "m")])
        self.assertEqual(r.counts["high"], 1)
        self.assertEqual(r.counts["low"], 2)


class TestSarif(unittest.TestCase):
    def setUp(self):
        ns = {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "n"}}
        self.sarif = to_sarif(assess_documents([ns], source="t"))

    def test_version(self):
        self.assertEqual(self.sarif["version"], "2.1.0")

    def test_driver_name(self):
        self.assertEqual(
            self.sarif["runs"][0]["tool"]["driver"]["name"], "bastionkit")

    def test_has_results(self):
        self.assertTrue(self.sarif["runs"][0]["results"])

    def test_rules_have_security_severity(self):
        for rule in self.sarif["runs"][0]["tool"]["driver"]["rules"]:
            self.assertIn("security-severity", rule["properties"])

    def test_levels_mapped(self):
        for r in self.sarif["runs"][0]["results"]:
            self.assertIn(r["level"], ("error", "warning", "note"))

    def test_severity_level_map(self):
        self.assertEqual(_SARIF_LEVEL["critical"], "error")
        self.assertEqual(_SARIF_LEVEL["high"], "error")
        self.assertEqual(_SARIF_LEVEL["medium"], "warning")
        self.assertEqual(_SARIF_LEVEL["low"], "note")

    def test_security_severity_numeric(self):
        self.assertEqual(_security_severity("critical"), "9.5")
        self.assertEqual(_security_severity("low"), "3.0")


class TestNamespaceBucketing(unittest.TestCase):
    def test_two_namespaces_two_reports(self):
        a = {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "a"}}
        b = {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "b"}}
        reports = assess_documents([a, b], source="t")
        nss = {r.namespace for r in reports}
        self.assertIn("a", nss)
        self.assertIn("b", nss)

    def test_cluster_role_in_cluster_bucket(self):
        role = {"apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "ClusterRole", "metadata": {"name": "r"},
                "rules": [{"apiGroups": ["*"], "resources": ["*"],
                           "verbs": ["*"]}]}
        reports = assess_documents([role], source="t")
        cluster = [r for r in reports if r.namespace == "(cluster)"]
        self.assertTrue(cluster)
        self.assertIn("rbac.wildcard_rule",
                      {f.rule for f in cluster[0].findings})

    def test_namespace_hint_used(self):
        d = {"apiVersion": "apps/v1", "kind": "Deployment",
             "metadata": {"name": "d"},
             "spec": {"template": {"spec": {"containers": [
                 {"name": "c", "securityContext": HARDENED_SC}]}}}}
        reports = assess_documents([d], source="t", namespace_hint="staging")
        self.assertIn("staging", {r.namespace for r in reports})

    def test_findings_sorted_by_severity(self):
        pod = _pod({"privileged": True})  # critical + several lower
        reports = assess_documents([pod], source="t")
        fnds = [f for r in reports for f in r.findings]
        sevs = [SEVERITY_ORDER[f.severity] for f in fnds]
        self.assertEqual(sevs, sorted(sevs))


if __name__ == "__main__":
    unittest.main()
