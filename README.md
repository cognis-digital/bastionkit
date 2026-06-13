# bastionkit — hardened security baseline for air-gapped/regulated Kubernetes

> Part of the **[Cognis Neural Suite](https://github.com/cognis-digital)** by [Cognis Digital](https://cognis.digital)
> Cognis Open Collaboration License (COCL) v1.0 · domain: `ops`

[![PyPI](https://img.shields.io/pypi/v/cognis-bastionkit.svg)](https://pypi.org/project/cognis-bastionkit/)
[![CI](https://github.com/cognis-digital/bastionkit/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/bastionkit/actions)
[![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE)
[![Suite](https://img.shields.io/badge/Cognis-Neural%20Suite-6b46c1.svg)](https://github.com/cognis-digital)

**Assess Kubernetes manifests against a hardened security baseline — then generate the controls that close the gaps.**

`bastionkit` is built for disconnected, air-gapped, and regulated clusters where
a known-good security baseline matters more than feature breadth. It is
single-purpose, dependency-free (Python standard library only), scriptable,
CI-friendly, and self-hostable: point it at your manifests, get prioritized
findings in the format your workflow already speaks (table, JSON, SARIF), and
scaffold a ready-to-apply baseline bundle for any namespace.

## Usage — step by step

1. **Install** from source (Python 3.9+):
   ```bash
   pip install .
   ```
2. **Assess** k8s manifests against the hardened baseline:
   ```bash
   bastionkit assess manifests/ --namespace prod
   ```
3. **Inspect** the baseline controls bastionkit enforces:
   ```bash
   bastionkit baseline
   ```
4. **Use the output**: emit SARIF or JSON and gate on severity in CI:
   ```bash
   bastionkit assess manifests/ --format sarif --fail-on high --out bastion.sarif
   ```
5. **Generate** a hardened baseline bundle to scaffold a namespace:
   ```bash
   bastionkit generate --namespace prod --cpu-quota 4 --memory-quota 8Gi --pod-quota 50 --out baseline.yaml
   ```
   Also: `bastionkit mcp` (MCP stdio server).

## What it checks

`bastionkit` evaluates a baseline of controls drawn (by concept) from public
Kubernetes hardening guidance — the CIS Kubernetes Benchmark families and the
NSA/CISA Kubernetes Hardening Guidance:

| Domain        | Control                                                        |
|---------------|----------------------------------------------------------------|
| Network       | namespace has a **default-deny** NetworkPolicy (ingress+egress)|
| Pod security  | namespace enforces the **restricted** PodSecurity profile      |
| Resources     | namespace has a **ResourceQuota** and **LimitRange**           |
| RBAC          | no cluster-admin bindings; **no wildcard** verbs/resources/groups|
| RBAC          | no permissions granted to the **default** ServiceAccount       |
| ServiceAccount| token **automount disabled** unless needed                     |
| Workload      | non-root, no privilege, no escalation, read-only rootfs        |
| Workload      | drop ALL capabilities; set resource limits                     |
| Workload      | no host namespaces (hostNetwork/PID/IPC); no hostPath          |

<!-- cognis:domains:start -->
## Domains

**Primary domain:** Cyber & Security  ·  **JTF MERIDIAN division:** NULLBYTE · SPECTER

**Topics:** `cognis` `security` `infosec` `cybersecurity` `blue-team` `kubernetes`

Part of the **Cognis Neural Suite** — 300+ source-available tools organized across 12 domains under the JTF MERIDIAN command structure. See the [suite on GitHub](https://github.com/cognis-digital) and [jtf-meridian](https://github.com/cognis-digital/jtf-meridian) for how the pieces fit together.
<!-- cognis:domains:end -->

## Install

```bash
pip install cognis-bastionkit
# or, from this repo:
pip install -e ".[dev]"
```

## Quick start

```bash
bastionkit --version

# Assess a manifests directory or file
bastionkit assess demos/01-basic/insecure                 # → findings, exits non-zero
bastionkit assess demos/01-basic/hardened                 # → PASS, exits zero
bastionkit assess ./manifests --format sarif --out r.sarif --fail-on high
bastionkit assess ./manifests --format json

# Generate a hardened baseline bundle for a namespace
bastionkit generate --namespace payments --out baseline.yaml
kubectl apply -f baseline.yaml

# List the baseline controls + the public guidance they map to
bastionkit baseline

# Run as an MCP server (Cognis.Studio / Claude Desktop / Cursor)
bastionkit mcp
```

## Built-in demo

[`demos/01-basic/`](demos/01-basic/SCENARIO.md) ships two namespaces:
`insecure/` (a deliberately under-hardened payments workload — fails) and
`hardened/` (the generated baseline plus a compliant workload — passes).

## Output formats

- **Table** (default) — human-readable terminal summary, grouped by namespace
- **JSON** — machine-readable findings for pipelines
- **SARIF** — drops into GitHub code-scanning / IDE problem panes

Gate CI with `--fail-on {critical,high,medium,low,info}`.

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
can call them as scoped capabilities.

## Originality & scope

This is a **clean-room, original** implementation. It is inspired by the public
*concept* of a secure cluster baseline and a hardening package framework, but it
does not copy, fork, or vendor any third-party project, source, name, or
branding. The manifest reader, control catalogue, generator, and MCP server are
all original work under the COCL.

## Contributing

PRs, new controls, and demo scenarios are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## Interoperability

`{}` composes with the 300+ tool Cognis suite — JSON in/out and a shared
OpenAI-compatible `/v1` backbone. See **[INTEROP.md](INTEROP.md)** for the
suite map, composition patterns, and reference stacks.

## License

Source-available under the **Cognis Open Collaboration License (COCL) v1.0** —
free for personal, internal-evaluation, research, and educational use;
**commercial / production use requires a license** (licensing@cognis.digital).
See [LICENSE](LICENSE).

## Responsible use

This is security software. Use it only against clusters and manifests you own or
are explicitly authorized in writing to assess, and in compliance with
applicable law.

## About

**[Cognis Digital](https://cognis.digital)** — Wyoming, USA · *Making Tomorrow Better Today: Advanced Cybersecurity, AI Innovation, and Blockchain Expertise.*
