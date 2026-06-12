# bastionkit architecture

`bastionkit` is a single Python package, standard library only.

```
bastionkit/
  core.py          # YAML reader + baseline control engine + assess() + SARIF
  generate.py      # hardened baseline bundle generator + YAML serializer
  ai.py            # opt-in AI layer (off by default; fail-open)
  cognis_ai_backend.py  # shared local OpenAI-compatible client (vendored pattern)
  cli.py           # argparse CLI: assess / generate / baseline / mcp
  mcp_server.py    # stdio JSON-RPC 2.0 MCP server (assess + generate_baseline)
  __main__.py      # python -m bastionkit
```

## Data flow

1. **Parse** — `core.load_documents` reads YAML (via an original, dependency-free
   reader supporting the Kubernetes-manifest subset) or JSON into a list of
   document dicts. Multi-document streams and pooled directories are supported so
   namespace-scoped objects in separate files correlate correctly.
2. **Assess** — `core.assess_documents` discovers namespaces, indexes
   namespace-scoped baseline objects (NetworkPolicy / ResourceQuota / LimitRange
   / Namespace labels), then applies object-scoped controls (workload
   securityContext, RBAC, ServiceAccount). Findings are bucketed per namespace
   into `Report`s with a 0-100 hardening score.
3. **Report** — table (default), JSON, or SARIF 2.1.0. `--fail-on` sets the
   exit-code gate.
4. **Generate** — `generate.baseline_documents` builds the hardened bundle in
   memory; `dump_documents` serializes deterministic YAML; `validate_yaml`
   round-trips it through the reader as a self-check.

## The YAML reader

Kubernetes emits a regular, indentation-driven YAML subset: block mappings,
block sequences (including sequences indented at the parent key's column),
multi-document streams (`---`), scalars, and inline flow collections
(`[a, b]` / `{k: v}`). The reader (`core._Reader`) implements exactly that
subset. It is an original implementation, not a vendored parser.

## Design contracts

- No network access in the assess/generate paths.
- No runtime dependencies.
- The AI layer never raises and never blocks the deterministic path.
