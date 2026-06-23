# bastionkit — language ports

The Python package in [`../bastionkit`](../bastionkit) is the reference
implementation and carries the full engine (manifest parsing, the assessor, all
output formats, and the generator). These ports mirror the **primary, offline
command surface** so the baseline can be produced and inspected on hosts that
don't have a Python runtime — a common constraint on air-gapped jump boxes and
minimal CI images.

Each port implements:

| Command                              | Behaviour                                            |
|--------------------------------------|------------------------------------------------------|
| `baseline`                           | print the 16-control catalogue (id + severity + title) |
| `generate --namespace NS [...]`      | emit the hardened baseline YAML bundle for `NS`      |
| `--version`                          | print `bastionkit <version>`                         |

`generate` accepts the same `--cpu-quota`, `--memory-quota`, and `--pod-quota`
flags as the Python CLI, and the emitted Namespace / NetworkPolicy / ResourceQuota /
ServiceAccount / Role documents are **byte-for-byte identical** to the Python
generator (the `parity` CI job diffs them on every push).

All ports are **standard-library only** (no third-party packages) and make
**no network calls**.

## Ports

| Port  | Path              | Run                                  | Test                          | Verified |
|-------|-------------------|--------------------------------------|-------------------------------|----------|
| Node  | `ports/node/`     | `node bastionkit.mjs baseline`       | `node --test`                 | local + CI |
| Go    | `ports/go/`       | `go run . baseline`                  | `go test ./...`               | CI       |
| Rust  | `ports/rust/`     | `cargo run -- baseline`              | `cargo test`                  | CI       |
| Shell | `ports/shell/`    | `bash bastionkit.sh baseline`        | `bash test.sh`                | local + CI |

Each port is built and tested on every push by
[`.github/workflows/ports.yml`](../.github/workflows/ports.yml).

## Examples

```bash
# Node
node ports/node/bastionkit.mjs generate --namespace payments --pod-quota 30

# Go
( cd ports/go && go run . baseline )

# Rust
( cd ports/rust && cargo run -- generate --namespace payments )

# Shell (nothing but bash + coreutils)
bash ports/shell/bastionkit.sh generate --namespace payments | kubectl apply --dry-run=client -f -
```

> The ports are deliberately scoped to **baseline + generate**. Full manifest
> assessment (findings, SARIF/JSON, scoring, the MCP server) lives only in the
> Python reference, which remains the source of truth.
