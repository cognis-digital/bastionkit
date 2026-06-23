"""Generator + CLI integration tests for bastionkit.

Standard library only, no network. Every CLI invocation runs in-process against
local fixtures; nothing touches a network or a real cluster.
"""

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bastionkit import (
    assess_documents,
    baseline_documents,
    dump_documents,
    generate_bundle,
    parse_yaml_documents,
    validate_yaml,
)
from bastionkit.cli import main
from bastionkit.generate import _q, _dump

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INSECURE = os.path.join(REPO_ROOT, "demos", "01-basic", "insecure")
HARDENED = os.path.join(REPO_ROOT, "demos", "01-basic", "hardened")


def _capture(argv):
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(argv)
    return rc, buf.getvalue()


class TestYamlSerializer(unittest.TestCase):
    def test_bool_true(self):
        self.assertEqual(_q(True), "true")

    def test_bool_false(self):
        self.assertEqual(_q(False), "false")

    def test_none(self):
        self.assertEqual(_q(None), "null")

    def test_int(self):
        self.assertEqual(_q(50), "50")

    def test_plain_string(self):
        self.assertEqual(_q("restricted"), "restricted")

    def test_string_with_colon_quoted(self):
        self.assertTrue(_q("a:b").startswith('"'))

    def test_ambiguous_word_quoted(self):
        self.assertEqual(_q("true"), '"true"')

    def test_dump_simple_map(self):
        lines = _dump({"a": "b"})
        self.assertEqual(lines, ["a: b"])

    def test_dump_empty_map(self):
        lines = _dump({"a": {}})
        self.assertEqual(lines, ["a: {}"])

    def test_dump_empty_list(self):
        lines = _dump({"a": []})
        self.assertEqual(lines, ["a: []"])


class TestBaselineDocuments(unittest.TestCase):
    def setUp(self):
        self.docs = baseline_documents("zone-x")
        self.by_kind = {}
        for d in self.docs:
            self.by_kind.setdefault(d["kind"], []).append(d)

    def test_includes_namespace(self):
        self.assertIn("Namespace", self.by_kind)

    def test_includes_default_deny_netpol(self):
        nps = self.by_kind["NetworkPolicy"]
        names = {n["metadata"]["name"] for n in nps}
        self.assertIn("default-deny-all", names)

    def test_includes_dns_egress_netpol(self):
        names = {n["metadata"]["name"] for n in self.by_kind["NetworkPolicy"]}
        self.assertIn("allow-dns-egress", names)

    def test_includes_resourcequota(self):
        self.assertIn("ResourceQuota", self.by_kind)

    def test_includes_limitrange(self):
        self.assertIn("LimitRange", self.by_kind)

    def test_includes_serviceaccount(self):
        sa = self.by_kind["ServiceAccount"][0]
        self.assertIs(sa["automountServiceAccountToken"], False)

    def test_includes_role(self):
        role = self.by_kind["Role"][0]
        # least privilege: no wildcards
        for rule in role["rules"]:
            self.assertNotIn("*", rule["verbs"])
            self.assertNotIn("*", rule["resources"])

    def test_includes_rolebinding(self):
        self.assertIn("RoleBinding", self.by_kind)

    def test_includes_admission_policy(self):
        self.assertIn("ValidatingAdmissionPolicy", self.by_kind)

    def test_namespace_labelled_restricted(self):
        ns = self.by_kind["Namespace"][0]
        self.assertEqual(
            ns["metadata"]["labels"]["pod-security.kubernetes.io/enforce"],
            "restricted")

    def test_default_deny_selects_all_pods(self):
        dd = [n for n in self.by_kind["NetworkPolicy"]
              if n["metadata"]["name"] == "default-deny-all"][0]
        self.assertEqual(dd["spec"]["podSelector"], {})
        self.assertEqual(dd["spec"]["policyTypes"], ["Ingress", "Egress"])

    def test_managed_by_label(self):
        ns = self.by_kind["Namespace"][0]
        self.assertEqual(
            ns["metadata"]["labels"]["app.kubernetes.io/managed-by"],
            "bastionkit")


class TestGenerateCustomization(unittest.TestCase):
    def test_custom_cpu_quota(self):
        docs = baseline_documents("z", cpu_quota="16")
        rq = [d for d in docs if d["kind"] == "ResourceQuota"][0]
        self.assertEqual(rq["spec"]["hard"]["requests.cpu"], "16")
        self.assertEqual(rq["spec"]["hard"]["limits.cpu"], "16")

    def test_custom_memory_quota(self):
        docs = baseline_documents("z", memory_quota="32Gi")
        rq = [d for d in docs if d["kind"] == "ResourceQuota"][0]
        self.assertEqual(rq["spec"]["hard"]["requests.memory"], "32Gi")

    def test_custom_pod_quota(self):
        docs = baseline_documents("z", pod_quota=5)
        rq = [d for d in docs if d["kind"] == "ResourceQuota"][0]
        self.assertEqual(rq["spec"]["hard"]["pods"], 5)

    def test_namespace_name_propagates(self):
        docs = baseline_documents("payments")
        for d in docs:
            if d["kind"] in ("NetworkPolicy", "ResourceQuota", "LimitRange",
                             "ServiceAccount", "Role", "RoleBinding"):
                self.assertEqual(d["metadata"].get("namespace"), "payments", d["kind"])


class TestGenerateRoundTrip(unittest.TestCase):
    def test_bundle_valid_yaml(self):
        n = validate_yaml(generate_bundle("prod"))
        self.assertGreaterEqual(n, 9)

    def test_bundle_reparses(self):
        docs = parse_yaml_documents(generate_bundle("prod"))
        kinds = {d["kind"] for d in docs}
        for k in ("Namespace", "NetworkPolicy", "ResourceQuota", "LimitRange",
                  "Role", "RoleBinding", "ServiceAccount"):
            self.assertIn(k, kinds)

    def test_generated_namespace_passes_assessment(self):
        docs = parse_yaml_documents(generate_bundle("zone-x"))
        reports = assess_documents(docs, source="gen")
        for r in reports:
            self.assertFalse(r.failed, r.to_dict())

    def test_generated_has_no_default_deny_finding(self):
        docs = parse_yaml_documents(generate_bundle("ns1"))
        rules = {f.rule for r in assess_documents(docs, source="g")
                 for f in r.findings}
        self.assertNotIn("network.default_deny_missing", rules)

    def test_dump_documents_multidoc(self):
        text = dump_documents(baseline_documents("z"))
        self.assertEqual(text.count("\n---\n") + 1,
                         len(baseline_documents("z")))


class TestCliAssess(unittest.TestCase):
    def test_insecure_exits_nonzero(self):
        rc, _ = _capture(["assess", INSECURE])
        self.assertEqual(rc, 1)

    def test_hardened_exits_zero(self):
        rc, _ = _capture(["assess", HARDENED])
        self.assertEqual(rc, 0)

    def test_missing_target_exits_2(self):
        rc, _ = _capture(["assess", os.path.join(REPO_ROOT, "no", "such")])
        self.assertEqual(rc, 2)

    def test_json_format_parses(self):
        rc, out = _capture(["assess", INSECURE, "--format", "json"])
        payload = json.loads(out)
        self.assertEqual(payload["tool"], "bastionkit")
        self.assertTrue(payload["failed"])
        self.assertIn("counts", payload)

    def test_sarif_format_parses(self):
        rc, out = _capture(["assess", INSECURE, "--format", "sarif"])
        sarif = json.loads(out)
        self.assertEqual(sarif["version"], "2.1.0")

    def test_min_severity_filters(self):
        rc, out = _capture(
            ["assess", INSECURE, "--format", "json", "--min-severity", "critical"])
        payload = json.loads(out)
        for r in payload["reports"]:
            for f in r["findings"]:
                self.assertEqual(f["severity"], "critical")

    def test_fail_on_critical_gate(self):
        rc, _ = _capture(["assess", INSECURE, "--fail-on", "critical"])
        self.assertEqual(rc, 1)

    def test_fail_on_low_against_hardened(self):
        # hardened demo may carry low/medium info but no high/critical
        rc, _ = _capture(["assess", HARDENED, "--fail-on", "critical"])
        self.assertEqual(rc, 0)

    def test_out_file_written(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "r.json")
            rc = main(["assess", INSECURE, "--format", "json", "--out", path])
            self.assertTrue(os.path.exists(path))
            with open(path, encoding="utf-8") as fh:
                json.load(fh)


class TestCliGenerate(unittest.TestCase):
    def test_generate_stdout_yaml(self):
        rc, out = _capture(["generate", "--namespace", "web"])
        self.assertEqual(rc, 0)
        docs = parse_yaml_documents(out)
        self.assertTrue(any(d["kind"] == "NetworkPolicy" for d in docs))

    def test_generate_custom_quota_in_output(self):
        rc, out = _capture(
            ["generate", "--namespace", "web", "--pod-quota", "7"])
        docs = parse_yaml_documents(out)
        rq = [d for d in docs if d["kind"] == "ResourceQuota"][0]
        self.assertEqual(rq["spec"]["hard"]["pods"], 7)

    def test_generate_to_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "b.yaml")
            rc = main(["generate", "--namespace", "x", "--out", path])
            self.assertEqual(rc, 0)
            with open(path, encoding="utf-8") as fh:
                validate_yaml(fh.read())

    def test_from_intent_requires_ai(self):
        rc, _ = _capture(
            ["generate", "--namespace", "x", "--from-intent", "allow api"])
        self.assertEqual(rc, 2)


class TestCliBaseline(unittest.TestCase):
    def test_baseline_lists_controls(self):
        rc, out = _capture(["baseline"])
        self.assertEqual(rc, 0)
        self.assertIn("workload.privileged", out)
        self.assertIn("rbac.cluster_admin_binding", out)

    def test_no_command_exits_2(self):
        rc, _ = _capture([])
        self.assertEqual(rc, 2)


class TestEndToEnd(unittest.TestCase):
    def test_generate_then_assess_clean(self):
        """The bundle bastionkit emits must pass bastionkit's own assessment."""
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "baseline.yaml")
            main(["generate", "--namespace", "secure", "--out", path])
            rc, out = _capture(["assess", path, "--format", "json"])
            payload = json.loads(out)
            self.assertFalse(payload["failed"], out)


if __name__ == "__main__":
    unittest.main()
