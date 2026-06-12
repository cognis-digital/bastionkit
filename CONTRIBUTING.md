# Contributing to bastionkit

Thanks for your interest in improving `bastionkit`, part of the
[Cognis Neural Suite](https://github.com/cognis-digital).

## Ground rules

- **Standard library only.** `bastionkit` has zero runtime dependencies. Do not
  add `pip` dependencies; the manifest reader, control engine, generator, and
  MCP server are all stdlib.
- **Clean-room / original.** Do not copy, paste, or vendor third-party source,
  manifests, names, or branding. Contributions must be your own original work,
  licensed under the COCL.
- **Deterministic core.** The assess/generate paths must stay deterministic and
  offline. Any AI assistance is opt-in via the `--ai` flag and must fail open.

## Development

```bash
pip install -e ".[dev]"
python -m unittest discover -s tests
# or
pytest -q
```

## Adding a control

1. Add the control to `CONTROLS` in `bastionkit/core.py` (id, severity, title,
   guidance tag mapping to public CIS / NSA-CISA concepts — no copied text).
2. Implement the check in the relevant `_assess_*` function.
3. Add a test in `tests/test_deep.py` covering both the failing and clean case.
4. If it is namespace-scoped and should be scaffolded, emit it in
   `bastionkit/generate.py` and confirm the generated bundle still passes
   `bastionkit assess`.

## Reporting security issues

See [SECURITY.md](SECURITY.md).
