"""Deeper behavioral tests for bastionkit. Standard library only, no network."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bastionkit import SEVERITY_ORDER, assess_documents, to_sarif
from bastionkit.core import assess, assess_to_dict, parse_yaml_documents
from bastionkit.generate import baseline_documents, dump_documents


def _docs(*objs):
    return list(objs)


class TestWorkloadControls(unittest.TestCase):
    def _rules_for_pod(self, container_sc, pod_extra=None):
        pod = {
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "p", "namespace": "n"},
            "spec": {"containers": [{"name": "c", "securityContext": container_sc}]},
        }
        if pod_extra:
            pod["spec"].update(pod_extra)
        reports = assess_documents([pod], source="t")
        return {f.rule for r in reports for f in r.findings}

    def test_privileged_is_critical(self):
        rules = self._rules_for_pod({"privileged": True})
        self.assertIn("workload.privileged", rules)

    def test_run_as_root_flagged(self):
        rules = self._rules_for_pod({})
        self.assertIn("workload.run_as_root", rules)

    def test_priv_escalation_flagged(self):
        rules = self._rules_for_pod({"runAsNonRoot": True})
        self.assertIn("workload.privilege_escalation", rules)

    def test_hardened_container_is_clean(self):
        rules = self._rules_for_pod({
            "runAsNonRoot": True,
            "allowPrivilegeEscalation": False,
            "readOnlyRootFilesystem": True,
            "privileged": False,
            "capabilities": {"drop": ["ALL"]},
        })
        # Only the low-severity "no resource limits" may remain.
        self.assertNotIn("workload.run_as_root", rules)
        self.assertNotIn("workload.privilege_escalation", rules)
        self.assertNotIn("workload.writable_rootfs", rules)
        self.assertNotIn("workload.caps_not_dropped", rules)

    def test_host_namespace_flagged(self):
        rules = self._rules_for_pod({}, pod_extra={"hostPID": True})
        self.assertIn("workload.host_namespace", rules)

    def test_host_path_flagged(self):
        rules = self._rules_for_pod(
            {}, pod_extra={"volumes": [{"name": "v", "hostPath": {"path": "/"}}]})
        self.assertIn("workload.host_path", rules)


class TestRbacControls(unittest.TestCase):
    def test_wildcard_role_flagged(self):
        role = {
            "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
            "metadata": {"name": "r"},
            "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}],
        }
        rules = {f.rule for r in assess_documents([role], source="t") for f in r.findings}
        self.assertIn("rbac.wildcard_rule", rules)

    def test_explicit_role_clean(self):
        role = {
            "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
            "metadata": {"name": "r", "namespace": "n"},
            "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}],
        }
        rules = {f.rule for r in assess_documents([role], source="t") for f in r.findings}
        self.assertNotIn("rbac.wildcard_rule", rules)

    def test_cluster_admin_binding_critical(self):
        b = {
            "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
            "metadata": {"name": "b"},
            "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
            "subjects": [{"kind": "ServiceAccount", "name": "x", "namespace": "n"}],
        }
        rules = {f.rule for r in assess_documents([b], source="t") for f in r.findings}
        self.assertIn("rbac.cluster_admin_binding", rules)

    def test_default_sa_binding_flagged(self):
        b = {
            "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
            "metadata": {"name": "b", "namespace": "n"},
            "roleRef": {"kind": "Role", "name": "r"},
            "subjects": [{"kind": "ServiceAccount", "name": "default", "namespace": "n"}],
        }
        rules = {f.rule for r in assess_documents([b], source="t") for f in r.findings}
        self.assertIn("rbac.write_to_default_sa", rules)


class TestServiceAccount(unittest.TestCase):
    def test_automount_default_flagged(self):
        sa = {"apiVersion": "v1", "kind": "ServiceAccount",
              "metadata": {"name": "s", "namespace": "n"}}
        rules = {f.rule for r in assess_documents([sa], source="t") for f in r.findings}
        self.assertIn("serviceacct.automount_enabled", rules)

    def test_automount_disabled_clean(self):
        sa = {"apiVersion": "v1", "kind": "ServiceAccount",
              "metadata": {"name": "s", "namespace": "n"},
              "automountServiceAccountToken": False}
        rules = {f.rule for r in assess_documents([sa], source="t") for f in r.findings}
        self.assertNotIn("serviceacct.automount_enabled", rules)


class TestNamespaceControls(unittest.TestCase):
    def test_restricted_label_satisfies_podsec(self):
        ns = {"apiVersion": "v1", "kind": "Namespace",
              "metadata": {"name": "n", "labels": {
                  "pod-security.kubernetes.io/enforce": "restricted"}}}
        rules = {f.rule for r in assess_documents([ns], source="t") for f in r.findings}
        self.assertNotIn("podsec.restricted_missing", rules)

    def test_missing_restricted_label_flagged(self):
        ns = {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "n"}}
        rules = {f.rule for r in assess_documents([ns], source="t") for f in r.findings}
        self.assertIn("podsec.restricted_missing", rules)


class TestScoringAndSarif(unittest.TestCase):
    def test_score_monotonic(self):
        pod = {"apiVersion": "v1", "kind": "Pod",
               "metadata": {"name": "p", "namespace": "n"},
               "spec": {"containers": [{"name": "c",
                        "securityContext": {"privileged": True}}]}}
        reports = assess_documents([pod], source="t")
        worst = min(r.score for r in reports)
        self.assertLess(worst, 100)

    def test_sarif_shape(self):
        ns = {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "n"}}
        sarif = to_sarif(assess_documents([ns], source="t"))
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["name"], "bastionkit")
        self.assertTrue(sarif["runs"][0]["results"])

    def test_severity_ordering_complete(self):
        self.assertEqual(set(SEVERITY_ORDER),
                         {"critical", "high", "medium", "low", "info"})


class TestGenerateRoundTrip(unittest.TestCase):
    def test_generated_namespace_passes_assessment(self):
        docs = baseline_documents("zone-x")
        text = dump_documents(docs)
        reparsed = parse_yaml_documents(text)
        reports = assess_documents(reparsed, source="gen")
        # The scaffold itself must not produce critical/high baseline findings.
        for r in reports:
            self.assertFalse(r.failed, r.to_dict())

    def test_generate_custom_quota(self):
        docs = baseline_documents("z", cpu_quota="8", memory_quota="16Gi", pod_quota=10)
        rq = [d for d in docs if d["kind"] == "ResourceQuota"][0]
        self.assertEqual(rq["spec"]["hard"]["requests.cpu"], "8")
        self.assertEqual(rq["spec"]["hard"]["pods"], 10)


class TestAggregate(unittest.TestCase):
    def test_assess_to_dict_shape(self):
        ns = {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "n"}}
        # write to a temp file path is unnecessary; exercise via documents:
        reports = assess_documents([ns], source="t")
        d = reports[0].to_dict()
        self.assertIn("namespace", d)
        self.assertIn("findings", d)
        self.assertIn("score", d)


if __name__ == "__main__":
    unittest.main()
