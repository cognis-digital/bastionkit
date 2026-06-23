# bastionkit — hardened security baseline for air-gapped/regulated Kubernetes

> Part of the **[Cognis Neural Suite](https://github.com/cognis-digital)** by [Cognis Digital](https://cognis.digital)
> Cognis Open Collaboration License (COCL) v1.0 · domain: `ops`

[![PyPI](https://img.shields.io/pypi/v/cognis-bastionkit.svg)](https://pypi.org/project/cognis-bastionkit/)
[![CI](https://github.com/cognis-digital/bastionkit/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/bastionkit/actions)
[![Ports](https://github.com/cognis-digital/bastionkit/actions/workflows/ports.yml/badge.svg)](https://github.com/cognis-digital/bastionkit/actions)
[![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE)
[![Suite](https://img.shields.io/badge/Cognis-Neural%20Suite-6b46c1.svg)](https://github.com/cognis-digital)

**Assess Kubernetes manifests against a hardened security baseline — then generate the controls that close the gaps.**

`bastionkit` is built for disconnected, air-gapped, and regulated clusters where
a known-good security baseline matters more than feature breadth. It is
single-purpose, **dependency-free** (Python standard library only — including
its own YAML reader and YAML emitter), scriptable, CI-friendly, and
self-hostable: point it at your manifests, get prioritized findings in the
format your workflow already speaks (table, JSON, SARIF), and scaffold a
ready-to-apply baseline bundle for any namespace.

It is **fully passive and offline** — it reads manifest files and computes
findings locally. It never connects to a cluster, an API server, or the
network. It performs **no active scanning** of any kind.

## What it really does

`bastionkit` ships two cooperating capabilities plus a couple of conveniences:

1. **`assess`** — parse a manifest file or directory, pool every document so
   namespace-scoped objects correlate across files (the NetworkPolicy in one
   file is matched to the Deployment it protects in another), evaluate the
   16-control baseline, group findings by namespace, score each namespace
   0–100, and emit table / JSON / SARIF.
2. **`generate`** — emit a deterministic, ready-to-`kubectl apply`
   multi-document baseline bundle for a namespace (Namespace + PodSecurity
   labels, default-deny + DNS-egress NetworkPolicies, ResourceQuota, LimitRange,
   least-privilege Role/RoleBinding, a no-automount ServiceAccount, and a
   ValidatingAdmissionPolicy stub denying privileged pods). The generated
   bundle is self-checking: it passes `bastionkit`'s own assessment.
3. **`baseline`** — list the controls and the public guidance each maps to.
4. **`mcp`** — expose `assess` / `generate` as an MCP stdio server.

The manifest reader, control catalogue, generator/serializer, and MCP server are
all original, clean-room work — no third-party project, source, name, or branding
is copied, forked, or vendored.

## Install

Python 3.10+ (no runtime dependencies).

```bash
# from PyPI
pip install cognis-bastionkit

# or from this repo
git clone https://github.com/cognis-digital/bastionkit
cd bastionkit
pip install .
# for development + tests:
pip install -e ".[dev]"
```

**Air-gap install:** because the package has zero runtime dependencies, you can
vendor it onto a disconnected host by copying the repo (or a built wheel) across
your transfer boundary and running `pip install ./bastionkit` — or even just
`python -m bastionkit ...` straight from the source tree. Nothing is fetched at
runtime. For hosts without Python at all, see [Language ports](#language-ports).

## Quickstart

```bash
bastionkit --version

# Assess a manifests directory or a single file
bastionkit assess demos/01-basic/insecure          # → findings, exits non-zero
bastionkit assess demos/01-basic/hardened          # → PASS, exits zero
bastionkit assess ./manifests --namespace prod

# Machine-readable output for pipelines
bastionkit assess ./manifests --format json
bastionkit assess ./manifests --format sarif --out bastion.sarif --fail-on high

# Generate a hardened baseline bundle for a namespace, then apply it
bastionkit generate --namespace payments --out baseline.yaml
kubectl apply -f baseline.yaml

# List the baseline controls + the public guidance they map to
bastionkit baseline

# Run as an MCP server (Cognis.Studio / Claude Desktop / Cursor)
bastionkit mcp
```

## Worked example

The bundled [`demos/01-basic/`](demos/01-basic/SCENARIO.md) ships a deliberately
under-hardened `payments` workload (`insecure/`) and the generated baseline plus
a compliant workload (`hardened/`).

```console
$ bastionkit assess demos/01-basic/insecure
bastionkit assessment
====================================================================

namespace: (cluster)  (source: demos/01-basic/insecure)
--------------------------------------------------------------------
[CRIT] rbac.cluster_admin_binding
        ClusterRoleBinding/payments-admin binds the 'cluster-admin' ClusterRole, granting broad cluster control.
        at:  ClusterRoleBinding/payments-admin
        fix: Bind a narrowly scoped Role instead of cluster-admin/admin.
        ref: NSA/CISA: RBAC least privilege; CIS 5.1 (RBAC and Service Accounts)
[HIGH] rbac.wildcard_rule
        ClusterRole/payments-everything grants a wildcard (verbs/resources/apiGroups), defeating least privilege.
        ...
score=32/100  critical=1 high=1 medium=1 low=0 info=0  RESULT: FAIL

namespace: payments  (source: demos/01-basic/insecure)
--------------------------------------------------------------------
[CRIT] workload.privileged
        Deployment/api:api runs privileged.
[HIGH] network.default_deny_missing
        Namespace 'payments' lacks a default-deny NetworkPolicy; all pod ingress/egress is allowed by default.
[HIGH] podsec.restricted_missing
        Namespace 'payments' does not set pod-security.kubernetes.io/enforce=restricted.
[HIGH] workload.host_namespace
        Deployment/api sets hostNetwork=true, breaking pod isolation.
        ...
====================================================================
SUMMARY: 2 namespace(s), 2 failing, 16 finding(s).
```

The same run as JSON (summary fields shown):

```console
$ bastionkit assess demos/01-basic/insecure --format json
{
  "tool": "bastionkit",
  "version": "0.1.1",
  "target": "demos/01-basic/insecure",
  "namespaces_assessed": 2,
  "namespaces_failed": 2,
  "total_findings": 16,
  "counts": { "critical": 2, "high": 7, "medium": 6, "low": 1, "info": 0 },
  "failed": true
}
```

Generate and apply a clean baseline for that namespace:

```console
$ bastionkit generate --namespace payments --cpu-quota 4 --memory-quota 8Gi --pod-quota 50 --out baseline.yaml
$ bastionkit assess baseline.yaml
SUMMARY: 1 namespace(s), 0 failing, ... → RESULT: PASS
$ kubectl apply -f baseline.yaml
```

## What it checks

`bastionkit` evaluates 16 controls drawn (by concept) from public Kubernetes
hardening guidance — the CIS Kubernetes Benchmark families and the NSA/CISA
Kubernetes Hardening Guidance:

| Domain         | Control                                                          | Severity |
|----------------|------------------------------------------------------------------|----------|
| Network        | namespace has a **default-deny** NetworkPolicy (ingress+egress)  | high     |
| Pod security   | namespace enforces the **restricted** PodSecurity profile        | high     |
| Resources      | namespace has a **ResourceQuota**                                | medium   |
| Resources      | namespace has a **LimitRange** (default requests/limits)         | medium   |
| RBAC           | no **cluster-admin / admin** ClusterRoleBindings                 | critical |
| RBAC           | **no wildcard** verbs / resources / apiGroups                    | high     |
| RBAC           | no permissions granted to the **default** ServiceAccount         | medium   |
| ServiceAccount | token **automount disabled** unless needed                       | medium   |
| Workload       | containers **non-root** (`runAsNonRoot`)                         | high     |
| Workload       | no **privileged** containers                                     | critical |
| Workload       | no **privilege escalation** (`allowPrivilegeEscalation=false`)   | high     |
| Workload       | **read-only root filesystem**                                    | medium   |
| Workload       | **drop ALL** Linux capabilities                                  | medium   |
| Workload       | set **CPU + memory limits**                                      | low      |
| Workload       | no **host namespaces** (hostNetwork / hostPID / hostIPC)         | high     |
| Workload       | no **hostPath** volumes                                          | high     |

Workload controls cover `Pod`, `Deployment`, `StatefulSet`, `DaemonSet`,
`ReplicaSet`, `Job`, and `CronJob` (including `initContainers`).

## Output formats

- **Table** (default) — human-readable terminal summary, grouped by namespace,
  with a per-namespace `score=N/100` and `PASS`/`FAIL`.
- **JSON** — machine-readable aggregate + per-namespace findings for pipelines.
- **SARIF 2.1.0** — drops directly into GitHub code-scanning and IDE problem
  panes; each rule carries a `security-severity` and a mapped level
  (`error`/`warning`/`note`).

Gate CI with `--fail-on {critical,high,medium,low,info}` (exit `1` when any
finding at or above the threshold exists) and trim noise with
`--min-severity ...`.

```yaml
# .github/workflows/k8s-baseline.yml (excerpt)
- run: bastionkit assess manifests/ --format sarif --out bastion.sarif --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: bastion.sarif }
```

## Language ports

For air-gapped jump boxes and minimal CI images that lack a Python runtime, the
**`baseline`** and **`generate`** commands are also implemented in **Node, Go,
Rust, and POSIX shell** under [`ports/`](ports/README.md). Each port is
standard-library-only, makes no network calls, and emits a baseline bundle that
is **byte-for-byte identical** to the Python generator (a `parity` CI job diffs
them on every push). All four are built and tested by
[`.github/workflows/ports.yml`](.github/workflows/ports.yml).

```bash
node  ports/node/bastionkit.mjs  generate --namespace payments
bash  ports/shell/bastionkit.sh  generate --namespace payments
( cd ports/go   && go run .          generate --namespace payments )
( cd ports/rust && cargo run --      generate --namespace payments )
```

The Python package remains the reference implementation and the only one with
the full assessor, output formats, and MCP server.

<!-- cognis:domains:start -->
## Domains

**Primary domain:** Cyber & Security  ·  **JTF MERIDIAN division:** NULLBYTE · SPECTER

**Topics:** `cognis` `security` `infosec` `cybersecurity` `blue-team` `kubernetes`

Part of the **Cognis Neural Suite** — 300+ source-available tools organized across 12 domains under the JTF MERIDIAN command structure. See the [suite on GitHub](https://github.com/cognis-digital) and [jtf-meridian](https://github.com/cognis-digital/jtf-meridian) for how the pieces fit together.
<!-- cognis:domains:end -->

## Built-in demo

[`demos/01-basic/`](demos/01-basic/SCENARIO.md) ships two namespaces:
`insecure/` (a deliberately under-hardened payments workload — fails) and
`hardened/` (the generated baseline plus a compliant workload — passes).

## Optional AI layer (off by default)

`bastionkit` is fully deterministic. An **opt-in** `--ai` flag can use a
**local** OpenAI-compatible endpoint (llama.cpp / Ollama — nothing leaves the
box) to (a) explain findings in plain language and (b) draft a NetworkPolicy
from a plain-English intent. With no `COGNIS_AI_*` environment configured, the
AI layer is disabled and the tool degrades silently to its deterministic rules.

```bash
export COGNIS_AI_BACKEND=uncensored-fleet     # or COGNIS_AI_ENDPOINT=http://127.0.0.1:11434/v1
bastionkit assess ./manifests --ai
bastionkit generate --namespace web --ai --from-intent "allow ingress from the api namespace on 8080"
```

## How it fits the Cognis Neural Suite

`bastionkit` is one tool in the [Cognis Neural Suite](https://github.com/cognis-digital).
Every tool ships an MCP server, so [Cognis.Studio](https://cognis.studio) agents
can call them as scoped capabilities. See **[INTEROP.md](INTEROP.md)** for the
suite map and composition patterns.

## Interoperability & integrations

`bastionkit` composes with the 300+ tool Cognis suite — JSON in/out and a shared
OpenAI-compatible `/v1` backbone. Forward findings to
STIX / MISP / Sigma / Splunk / Elastic / Slack / webhooks via
[`cognis-connect`](https://github.com/cognis-digital/cognis-connect)
(`pip install ".[connect]"`, then `bastionkit-emit`). See
**[INTEROP.md](INTEROP.md)** and **[INTEGRATIONS.md](INTEGRATIONS.md)**.

## Originality & scope

This is a **clean-room, original** implementation. It is inspired by the public
*concept* of a secure cluster baseline and a hardening package framework, but it
does not copy, fork, or vendor any third-party project, source, name, or
branding. The manifest reader, control catalogue, generator, language ports, and
MCP server are all original work under the COCL.

## Authorization, safety & scope

This is **defensive** security software for **authorized use only**.

- **Passive and offline.** `bastionkit` reads manifest files you provide and
  computes findings locally. It does **not** connect to a cluster, an API
  server, or the network, and performs **no active scanning, probing, or
  exploitation** of any kind. (Tests and CI run only against local fixtures.)
- Use it only against clusters, manifests, and configurations you **own or are
  explicitly authorized in writing to assess**, and in compliance with
  applicable law and policy.
- Findings are advisory. The generated baseline is a sensible starting point,
  not a substitute for review against your own threat model and compliance
  obligations. Test generated manifests with `kubectl apply --dry-run=server`
  before rolling them into production.

## Contributing

PRs, new controls, and demo scenarios are welcome. See
[CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

Source-available under the **Cognis Open Collaboration License (COCL) v1.0** —
free for personal, internal-evaluation, research, and educational use;
**commercial / production use requires a license** (licensing@cognis.digital).
See [LICENSE](LICENSE).

## About

**[Cognis Digital](https://cognis.digital)** — Wyoming, USA · *Making Tomorrow Better Today: Advanced Cybersecurity, AI Innovation, and Blockchain Expertise.*
