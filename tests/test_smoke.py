"""Smoke tests for bastionkit. Standard library only, no network."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bastionkit import (
    TOOL_NAME,
    TOOL_VERSION,
    assess_documents,
    generate_bundle,
    parse_yaml_documents,
    validate_yaml,
)
from bastionkit.cli import main

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INSECURE = os.path.join(REPO_ROOT, "demos", "01-basic", "insecure")
HARDENED = os.path.join(REPO_ROOT, "demos", "01-basic", "hardened")


class TestMetadata(unittest.TestCase):
    def test_metadata(self):
        self.assertEqual(TOOL_NAME, "bastionkit")
        self.assertTrue(TOOL_VERSION)


class TestYamlReader(unittest.TestCase):
    def test_parses_block_sequence_at_parent_indent(self):
        text = "spec:\n  policyTypes:\n  - Ingress\n  - Egress\n"
        docs = parse_yaml_documents(text)
        self.assertEqual(docs[0]["spec"]["policyTypes"], ["Ingress", "Egress"])

    def test_parses_nested_list_of_maps(self):
        text = ("rules:\n  - apiGroups: [\"\"]\n    verbs:\n    - get\n"
                "    - list\n")
        docs = parse_yaml_documents(text)
        self.assertEqual(docs[0]["rules"][0]["verbs"], ["get", "list"])

    def test_multi_document_stream(self):
        text = "kind: A\n---\nkind: B\n"
        docs = parse_yaml_documents(text)
        self.assertEqual([d["kind"] for d in docs], ["A", "B"])


class TestAssess(unittest.TestCase):
    def test_insecure_demo_fails(self):
        reports = assess_documents(
            _load_dir(INSECURE), source=INSECURE)
        rules = {f.rule for r in reports for f in r.findings}
        self.assertIn("workload.privileged", rules)
        self.assertIn("rbac.cluster_admin_binding", rules)
        self.assertIn("rbac.wildcard_rule", rules)
        self.assertIn("network.default_deny_missing", rules)
        self.assertTrue(any(r.failed for r in reports))

    def test_hardened_demo_passes(self):
        reports = assess_documents(_load_dir(HARDENED), source=HARDENED)
        for r in reports:
            self.assertFalse(r.failed, r.to_dict())

    def test_default_deny_detected(self):
        text = generate_bundle("ns1")
        docs = parse_yaml_documents(text)
        reports = assess_documents(docs, source="gen")
        rules = {f.rule for r in reports for f in r.findings}
        self.assertNotIn("network.default_deny_missing", rules)


class TestGenerate(unittest.TestCase):
    def test_bundle_is_valid_yaml(self):
        text = generate_bundle("prod")
        n = validate_yaml(text)
        self.assertGreaterEqual(n, 8)

    def test_bundle_contains_baseline_kinds(self):
        docs = parse_yaml_documents(generate_bundle("prod"))
        kinds = {d["kind"] for d in docs}
        for k in ("Namespace", "NetworkPolicy", "ResourceQuota",
                  "LimitRange", "Role", "RoleBinding", "ServiceAccount"):
            self.assertIn(k, kinds)


class TestCli(unittest.TestCase):
    def test_insecure_exits_nonzero(self):
        self.assertEqual(main(["assess", INSECURE]), 1)

    def test_hardened_exits_zero(self):
        self.assertEqual(main(["assess", HARDENED]), 0)

    def test_baseline_lists_controls(self):
        self.assertEqual(main(["baseline"]), 0)

    def test_missing_target_exits_2(self):
        self.assertEqual(main(["assess", "/no/such/dir"]), 2)

    def test_no_command_exits_2(self):
        self.assertEqual(main([]), 2)

    def test_generate_via_subprocess_emits_yaml(self):
        proc = subprocess.run(
            [sys.executable, "-m", "bastionkit", "generate", "--namespace", "z"],
            cwd=REPO_ROOT, capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        docs = parse_yaml_documents(proc.stdout)
        self.assertTrue(any(d["kind"] == "NetworkPolicy" for d in docs))


def _load_dir(path):
    from bastionkit.core import load_documents
    docs = []
    for root, _dirs, files in os.walk(path):
        for fn in sorted(files):
            if fn.endswith((".yaml", ".yml", ".json")):
                docs.extend(load_documents(os.path.join(root, fn)))
    return docs


if __name__ == "__main__":
    unittest.main()
