"""Command-line interface for bastionkit."""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    CONTROLS,
    ManifestError,
    Report,
    SEVERITY_ORDER,
    assess,
    assess_to_dict,
    to_sarif,
)
from .generate import generate_bundle, validate_yaml

_SEV_LABEL = {
    "critical": "CRIT",
    "high": "HIGH",
    "medium": "MED ",
    "low": "LOW ",
    "info": "INFO",
}


def _render_report(report: Report) -> str:
    lines: List[str] = []
    lines.append(f"namespace: {report.namespace}  (source: {report.source})")
    lines.append("-" * 68)
    if not report.findings:
        lines.append("No findings. Namespace meets the bastionkit baseline.")
    else:
        for f in report.findings:
            label = _SEV_LABEL.get(f.severity, f.severity.upper())
            lines.append(f"[{label}] {f.rule}")
            lines.append(f"        {f.message}")
            if f.location:
                lines.append(f"        at:  {f.location}")
            if f.remediation:
                lines.append(f"        fix: {f.remediation}")
            if f.guidance:
                lines.append(f"        ref: {f.guidance}")
    c = report.counts
    lines.append(
        f"score={report.score}/100  "
        f"critical={c['critical']} high={c['high']} medium={c['medium']} "
        f"low={c['low']} info={c['info']}  "
        f"RESULT: {'FAIL' if report.failed else 'PASS'}"
    )
    return "\n".join(lines)


def _render_table(reports: List[Report]) -> str:
    if not reports:
        return "No manifests found to assess."
    blocks = [f"bastionkit assessment", "=" * 68]
    blocks += [_render_report(r) for r in reports]
    failing = sum(1 for r in reports if r.failed)
    blocks.append("=" * 68)
    blocks.append(
        f"SUMMARY: {len(reports)} namespace(s), {failing} failing, "
        f"{sum(len(r.findings) for r in reports)} finding(s)."
    )
    return "\n\n".join(blocks)


def _fails_gate(reports: List[Report], fail_on: Optional[str]) -> bool:
    if not fail_on:
        return any(r.failed for r in reports)
    threshold = SEVERITY_ORDER[fail_on]
    return any(
        SEVERITY_ORDER.get(f.severity, 99) <= threshold
        for r in reports for f in r.findings
    )


def _apply_min_severity(report: Report, min_sev: str) -> None:
    threshold = SEVERITY_ORDER[min_sev]
    report.findings = [
        f for f in report.findings
        if SEVERITY_ORDER.get(f.severity, 99) <= threshold
    ]


def _emit(text: str, out: Optional[str]) -> None:
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(text if text.endswith("\n") else text + "\n")
        print(f"wrote {out}", file=sys.stderr)
    else:
        print(text)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Hardened security baseline for air-gapped/regulated "
                    "Kubernetes — assess manifests and generate baseline controls.",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    a = sub.add_parser(
        "assess", help="Assess k8s manifests against the hardened baseline.")
    a.add_argument("target", help="Manifest file or directory to assess.")
    a.add_argument("--namespace", default="",
                   help="Assume this namespace for unscoped objects.")
    a.add_argument("--format", choices=("table", "json", "sarif"),
                   default="table", help="Output format (default: table).")
    a.add_argument("--min-severity", choices=tuple(SEVERITY_ORDER), default="info",
                   help="Only report findings at or above this severity.")
    a.add_argument("--out", help="Write output to this file instead of stdout.")
    a.add_argument("--fail-on", choices=tuple(SEVERITY_ORDER), default=None,
                   help="Exit non-zero if a finding at/above this severity exists.")
    a.add_argument("--ai", action="store_true",
                   help="Opt-in: use the local Cognis AI backend to explain "
                        "findings (off by default; needs COGNIS_AI_* env).")

    g = sub.add_parser(
        "generate", help="Generate a hardened baseline bundle for a namespace.")
    g.add_argument("--namespace", required=True,
                   help="Namespace to scaffold the baseline for.")
    g.add_argument("--out", help="Write the YAML bundle to this file.")
    g.add_argument("--cpu-quota", default="4", help="ResourceQuota cpu (default 4).")
    g.add_argument("--memory-quota", default="8Gi",
                   help="ResourceQuota memory (default 8Gi).")
    g.add_argument("--pod-quota", type=int, default=50,
                   help="Max pods in the namespace (default 50).")
    g.add_argument("--from-intent",
                   help="Opt-in --ai: draft a NetworkPolicy from this plain-"
                        "English intent instead of the full bundle.")
    g.add_argument("--ai", action="store_true",
                   help="Opt-in: enable AI features (off by default).")

    sub.add_parser("baseline",
                   help="List the baseline controls and their hardening guidance.")

    mcp = sub.add_parser("mcp", help="Run as an MCP server (stdio JSON-RPC).")
    mcp.add_argument("--host", default=None, help="Reserved; stdio transport only.")
    return p


def _run_assess(args: argparse.Namespace) -> int:
    try:
        reports = assess(args.target, namespace_hint=args.namespace)
    except (OSError, ManifestError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    for r in reports:
        _apply_min_severity(r, args.min_severity)

    fmt = args.format
    if fmt == "json":
        payload = assess_to_dict(args.target, namespace_hint=args.namespace)
        payload["reports"] = [r.to_dict() for r in reports]
        _emit(json.dumps(payload, indent=2), args.out)
    elif fmt == "sarif":
        _emit(json.dumps(to_sarif(reports), indent=2), args.out)
    else:
        text = _render_table(reports)
        if args.ai:
            text += "\n\n" + _ai_explanations(reports)
        _emit(text, args.out)

    return 1 if _fails_gate(reports, args.fail_on) else 0


def _ai_explanations(reports: List[Report]) -> str:
    from . import ai  # local import: AI layer is opt-in
    if not ai.is_enabled():
        return ("AI explanations requested but no backend configured "
                "(set COGNIS_AI_BACKEND / COGNIS_AI_ENDPOINT). Skipping.")
    flat = [f.to_dict() for r in reports for f in r.findings]
    explained = ai.explain_findings(flat)
    if not explained:
        return "AI backend returned no explanations."
    out = ["AI explanations", "=" * 68]
    for e in explained:
        out.append(f"[{e['rule']}] {e['explanation']}")
        if e.get("remediation"):
            out.append(f"        fix: {e['remediation']}")
    return "\n".join(out)


def _run_generate(args: argparse.Namespace) -> int:
    if args.from_intent:
        if not args.ai:
            print("error: --from-intent requires --ai", file=sys.stderr)
            return 2
        from . import ai
        if not ai.is_enabled():
            print("error: --ai needs a configured backend "
                  "(COGNIS_AI_BACKEND / COGNIS_AI_ENDPOINT).", file=sys.stderr)
            return 2
        from .generate import dump_documents
        np = ai.draft_network_policy(args.from_intent, namespace=args.namespace)
        if np is None:
            print("error: AI backend did not return a NetworkPolicy.", file=sys.stderr)
            return 1
        _emit(dump_documents([np]), args.out)
        return 0

    bundle = generate_bundle(
        args.namespace,
        cpu_quota=args.cpu_quota,
        memory_quota=args.memory_quota,
        pod_quota=args.pod_quota,
    )
    # Self-check: the emitted YAML must round-trip.
    try:
        validate_yaml(bundle)
    except ValueError as exc:  # pragma: no cover - defensive
        print(f"error: generated invalid YAML: {exc}", file=sys.stderr)
        return 2
    _emit(bundle, args.out)
    return 0


def _run_baseline() -> int:
    print(f"{TOOL_NAME} {TOOL_VERSION} — {len(CONTROLS)} baseline controls")
    print("=" * 72)
    for rule, sev, title, guidance in CONTROLS:
        print(f"[{_SEV_LABEL.get(sev, sev.upper())}] {rule}")
        print(f"        {title}")
        print(f"        maps to: {guidance}")
    return 0


def _run_mcp() -> int:
    from .mcp_server import run_mcp_server
    run_mcp_server()
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "assess":
        return _run_assess(args)
    if args.command == "generate":
        return _run_generate(args)
    if args.command == "baseline":
        return _run_baseline()
    if args.command == "mcp":
        return _run_mcp()
    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
