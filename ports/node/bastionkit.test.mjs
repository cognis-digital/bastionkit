// Smoke test for the bastionkit Node port. Standard library only (node:test,
// node:assert). Offline; no network. Run: node --test ports/node/
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  CONTROLS, TOOL_NAME, baselineDocuments, generateBundle, q, main,
} from "./bastionkit.mjs";

test("tool name", () => {
  assert.equal(TOOL_NAME, "bastionkit");
});

test("control catalogue has all 16 controls", () => {
  assert.equal(CONTROLS.length, 16);
});

test("every control has 4 fields and a known severity", () => {
  const sevs = new Set(["critical", "high", "medium", "low", "info"]);
  for (const c of CONTROLS) {
    assert.equal(c.length, 4);
    assert.ok(sevs.has(c[1]), c[0]);
  }
});

test("scalar quoting", () => {
  assert.equal(q(true), "true");
  assert.equal(q(false), "false");
  assert.equal(q(50), "50");
  assert.equal(q("restricted"), "restricted");
  assert.equal(q("true"), '"true"');
});

test("baseline documents include the required kinds", () => {
  const kinds = new Set(baselineDocuments("prod").map((d) => d.kind));
  for (const k of ["Namespace", "NetworkPolicy", "ResourceQuota",
                   "LimitRange", "Role", "RoleBinding", "ServiceAccount"]) {
    assert.ok(kinds.has(k), `missing ${k}`);
  }
});

test("default-deny netpol selects all pods", () => {
  const dd = baselineDocuments("prod").find(
    (d) => d.kind === "NetworkPolicy" && d.metadata.name === "default-deny-all");
  assert.deepEqual(dd.spec.podSelector, {});
  assert.deepEqual(dd.spec.policyTypes, ["Ingress", "Egress"]);
});

test("service account disables token automount", () => {
  const sa = baselineDocuments("prod").find((d) => d.kind === "ServiceAccount");
  assert.equal(sa.automountServiceAccountToken, false);
});

test("namespace labelled restricted", () => {
  const ns = baselineDocuments("prod").find((d) => d.kind === "Namespace");
  assert.equal(ns.metadata.labels["pod-security.kubernetes.io/enforce"], "restricted");
});

test("custom pod quota propagates", () => {
  const rq = baselineDocuments("p", { podQuota: 7 }).find(
    (d) => d.kind === "ResourceQuota");
  assert.equal(rq.spec.hard.pods, 7);
});

test("generated bundle is multi-document yaml", () => {
  const text = generateBundle("web");
  assert.ok(text.startsWith("---\n"));
  assert.ok(text.includes("kind: NetworkPolicy"));
  assert.ok(text.includes("pod-security.kubernetes.io/enforce: restricted"));
});

test("baseline command exits zero", () => {
  assert.equal(main(["baseline"]), 0);
});

test("generate without namespace exits 2", () => {
  assert.equal(main(["generate"]), 2);
});
