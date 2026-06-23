"""Exhaustive tests for the dependency-free YAML reader.

Standard library only, no network. The reader handles the Kubernetes-manifest
subset of YAML; these tests pin its behaviour against the shapes Kubernetes
emits in practice.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bastionkit.core import (
    ManifestError,
    parse_yaml_documents,
    _scalar,
    _parse_flow,
    _split_top,
    _strip_comment,
    _indent,
)


class TestScalars(unittest.TestCase):
    def test_int(self):
        self.assertEqual(_scalar("42"), 42)

    def test_negative_int(self):
        self.assertEqual(_scalar("-7"), -7)

    def test_float(self):
        self.assertEqual(_scalar("3.14"), 3.14)

    def test_true_variants(self):
        for t in ("true", "True", "yes", "on"):
            self.assertIs(_scalar(t), True, t)

    def test_false_variants(self):
        for t in ("false", "False", "no", "off"):
            self.assertIs(_scalar(t), False, t)

    def test_null_variants(self):
        for t in ("", "~", "null", "NULL"):
            self.assertIsNone(_scalar(t), t)

    def test_single_quoted_string(self):
        self.assertEqual(_scalar("'hello'"), "hello")

    def test_double_quoted_string(self):
        self.assertEqual(_scalar('"world"'), "world")

    def test_quoted_true_stays_string(self):
        self.assertEqual(_scalar('"true"'), "true")

    def test_bare_word(self):
        self.assertEqual(_scalar("restricted"), "restricted")

    def test_version_like_stays_string(self):
        # not a valid float -> string
        self.assertEqual(_scalar("1.4.2"), "1.4.2")


class TestStripComment(unittest.TestCase):
    def test_trailing_comment_removed(self):
        self.assertEqual(_strip_comment("key: value  # note"), "key: value")

    def test_hash_in_quotes_kept(self):
        self.assertEqual(_strip_comment('k: "a#b"'), 'k: "a#b"')

    def test_full_line_comment(self):
        self.assertEqual(_strip_comment("# just a comment"), "")

    def test_no_comment_unchanged(self):
        self.assertEqual(_strip_comment("kind: Pod"), "kind: Pod")

    def test_hash_without_leading_space_kept(self):
        # '#' not preceded by whitespace is not a comment
        self.assertEqual(_strip_comment("color: red#orange"), "color: red#orange")


class TestIndent(unittest.TestCase):
    def test_zero(self):
        self.assertEqual(_indent("kind: Pod"), 0)

    def test_two(self):
        self.assertEqual(_indent("  name: x"), 2)

    def test_four(self):
        self.assertEqual(_indent("    - a"), 4)


class TestFlowCollections(unittest.TestCase):
    def test_flow_list(self):
        self.assertEqual(_parse_flow("[a, b, c]"), ["a", "b", "c"])

    def test_flow_empty_list(self):
        self.assertEqual(_parse_flow("[]"), [])

    def test_flow_list_of_ints(self):
        self.assertEqual(_parse_flow("[1, 2, 3]"), [1, 2, 3])

    def test_flow_map(self):
        self.assertEqual(_parse_flow("{a: 1, b: 2}"), {"a": 1, "b": 2})

    def test_flow_empty_map(self):
        self.assertEqual(_parse_flow("{}"), {})

    def test_json_passthrough(self):
        self.assertEqual(_parse_flow('["x", "y"]'), ["x", "y"])

    def test_quoted_empty_apigroup(self):
        self.assertEqual(_parse_flow('[""]'), [""])


class TestSplitTop(unittest.TestCase):
    def test_simple(self):
        self.assertEqual(_split_top("a, b, c"), ["a", "b", "c"])

    def test_nested_brackets_not_split(self):
        self.assertEqual(_split_top("a, [b, c], d"), ["a", "[b, c]", "d"])

    def test_quoted_comma_not_split(self):
        self.assertEqual(_split_top('"a,b", c'), ['"a,b"', "c"])


class TestDocumentParsing(unittest.TestCase):
    def test_simple_map(self):
        docs = parse_yaml_documents("kind: Pod\napiVersion: v1\n")
        self.assertEqual(docs[0], {"kind": "Pod", "apiVersion": "v1"})

    def test_nested_map(self):
        docs = parse_yaml_documents("metadata:\n  name: x\n  namespace: y\n")
        self.assertEqual(docs[0]["metadata"], {"name": "x", "namespace": "y"})

    def test_block_sequence_at_child_indent(self):
        text = "spec:\n  policyTypes:\n    - Ingress\n    - Egress\n"
        docs = parse_yaml_documents(text)
        self.assertEqual(docs[0]["spec"]["policyTypes"], ["Ingress", "Egress"])

    def test_block_sequence_at_parent_indent(self):
        text = "spec:\n  policyTypes:\n  - Ingress\n  - Egress\n"
        docs = parse_yaml_documents(text)
        self.assertEqual(docs[0]["spec"]["policyTypes"], ["Ingress", "Egress"])

    def test_list_of_maps(self):
        text = ("rules:\n  - apiGroups: [\"\"]\n    verbs:\n    - get\n"
                "    - list\n")
        docs = parse_yaml_documents(text)
        self.assertEqual(docs[0]["rules"][0]["apiGroups"], [""])
        self.assertEqual(docs[0]["rules"][0]["verbs"], ["get", "list"])

    def test_multi_doc(self):
        docs = parse_yaml_documents("kind: A\n---\nkind: B\n---\nkind: C\n")
        self.assertEqual([d["kind"] for d in docs], ["A", "B", "C"])

    def test_trailing_document_terminator(self):
        docs = parse_yaml_documents("kind: A\n...\n")
        self.assertEqual(docs[0]["kind"], "A")

    def test_empty_documents_dropped(self):
        docs = parse_yaml_documents("\n---\n\n---\nkind: X\n")
        self.assertEqual(len(docs), 1)

    def test_comments_ignored(self):
        text = "# header\nkind: Pod  # type\napiVersion: v1\n"
        docs = parse_yaml_documents(text)
        self.assertEqual(docs[0]["kind"], "Pod")

    def test_booleans_parsed(self):
        docs = parse_yaml_documents("spec:\n  privileged: true\n  hostPID: false\n")
        self.assertIs(docs[0]["spec"]["privileged"], True)
        self.assertIs(docs[0]["spec"]["hostPID"], False)

    def test_empty_map_value(self):
        docs = parse_yaml_documents("spec:\n  podSelector: {}\n")
        self.assertEqual(docs[0]["spec"]["podSelector"], {})

    def test_deeply_nested(self):
        text = ("spec:\n  template:\n    spec:\n      containers:\n"
                "      - name: c\n        image: nginx\n")
        docs = parse_yaml_documents(text)
        c = docs[0]["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(c["name"], "c")
        self.assertEqual(c["image"], "nginx")

    def test_quoted_keys(self):
        docs = parse_yaml_documents('metadata:\n  labels:\n    "app": web\n')
        self.assertEqual(docs[0]["metadata"]["labels"]["app"], "web")

    def test_label_with_dotted_key(self):
        text = ("labels:\n"
                "  pod-security.kubernetes.io/enforce: restricted\n")
        docs = parse_yaml_documents(text)
        self.assertEqual(
            docs[0]["labels"]["pod-security.kubernetes.io/enforce"], "restricted")

    def test_real_networkpolicy_roundtrips(self):
        text = (
            "apiVersion: networking.k8s.io/v1\n"
            "kind: NetworkPolicy\n"
            "metadata:\n"
            "  name: default-deny\n"
            "  namespace: prod\n"
            "spec:\n"
            "  podSelector: {}\n"
            "  policyTypes:\n"
            "  - Ingress\n"
            "  - Egress\n"
        )
        d = parse_yaml_documents(text)[0]
        self.assertEqual(d["kind"], "NetworkPolicy")
        self.assertEqual(d["metadata"]["namespace"], "prod")
        self.assertEqual(d["spec"]["podSelector"], {})
        self.assertEqual(d["spec"]["policyTypes"], ["Ingress", "Egress"])


class TestManifestErrorType(unittest.TestCase):
    def test_is_value_error(self):
        self.assertTrue(issubclass(ManifestError, ValueError))


if __name__ == "__main__":
    unittest.main()
