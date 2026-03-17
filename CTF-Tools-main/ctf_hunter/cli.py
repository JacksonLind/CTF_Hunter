"""
CTF Hunter — Command-Line Interface.

Provides headless analysis so CTF Hunter can be used without the GUI,
enabling scripted workflows, CI/CD pipelines, and integration with
other tools.

Usage examples:
    python main.py --cli file.bin
    python main.py --cli --depth deep --flag 'HTB\\{[^}]+\\}' challenge.png
    python main.py --cli --format json --output results.json *.bin
    python main.py --cli --depth auto --format markdown -o report.md folder/
    python main.py --cli --feedback <finding_id>:correct
    python main.py --cli --feedback-stats
"""
from __future__ import annotations

import argparse
import csv
import html
import io
import json
import logging
import os
import re
import sys
from pathlib import Path
from typing import List

from core.dispatcher import dispatch
from core.report import Finding, Session
from core.challenge_fingerprinter import ChallengeFingerprinter
from core.attack_chain import ChainBuilder
from core.key_registry import KeyRegistry
from core.key_extractor import KeyExtractor

logger = logging.getLogger(__name__)

# Path for persisting the most-recent CLI run's findings so --feedback can look them up.
_LAST_RUN_PATH = Path.home() / ".ctf_hunter" / "last_run.json"


# ── Formatters ────────────────────────────────────────────────────────────

def _format_text(findings: List[Finding]) -> str:
    """Human-readable plain-text output."""
    if not findings:
        return "No findings.\n"
    lines: list[str] = []
    by_file: dict[str, list[Finding]] = {}
    for f in findings:
        by_file.setdefault(f.file, []).append(f)
    for fpath, flist in by_file.items():
        lines.append(f"{'=' * 72}")
        lines.append(f"File: {fpath}")
        lines.append(f"{'=' * 72}")
        for f in flist:
            if f.duplicate_of:
                continue
            flag = " [FLAG]" if f.flag_match else ""
            lines.append(f"  [{f.severity}] {f.title}{flag}  (conf: {f.confidence:.2f})")
            lines.append(f"    Analyzer: {f.analyzer}")
            if f.offset >= 0:
                lines.append(f"    Offset:   0x{f.offset:x}")
            if f.detail:
                detail = f.detail.replace("\n", "\n              ")
                lines.append(f"    Detail:   {detail}")
            lines.append("")
    return "\n".join(lines) + "\n"


def _fingerprint_text_section(matches: list) -> str:
    """Format fingerprint matches as a plain-text section."""
    if not matches:
        return ""
    lines = [
        "",
        "=" * 72,
        "Fingerprint Matches (challenge archetype similarity)",
        "=" * 72,
    ]
    for rank, m in enumerate(matches, 1):
        arch = m["archetype"]
        pct = m["confidence_pct"]
        name = arch.get("name", "Unknown")
        source = arch.get("source", "")
        category = arch.get("category", "")
        description = arch.get("description", "")
        transforms = arch.get("typical_transforms", [])
        solve_hint = arch.get("solve_rate_hint", "")
        lines.append(
            f"  #{rank}  [{pct}%] {name}  (category: {category}"
            + (f", source: {source}" if source else "") + ")"
        )
        if description:
            lines.append(f"         {description}")
        if solve_hint:
            lines.append(f"         Typical solve rate: {solve_hint}")
        if transforms:
            lines.append("         Suggested transforms:")
            for t in transforms[:4]:
                lines.append(f"           • {t}")
        lines.append("")
    return "\n".join(lines)


def _format_json(findings: List[Finding]) -> str:
    """Machine-readable JSON output."""
    return json.dumps([f.to_dict() for f in findings if not f.duplicate_of], indent=2)


def _format_markdown(findings: List[Finding]) -> str:
    """Markdown report (mirrors GUI export)."""
    lines = ["# CTF Hunter Report\n"]
    by_file: dict[str, list[Finding]] = {}
    for f in findings:
        by_file.setdefault(f.file, []).append(f)
    for fpath, flist in by_file.items():
        lines.append(f"## {fpath}\n")
        for f in flist:
            if f.duplicate_of:
                continue
            flag_marker = " 🚩" if f.flag_match else ""
            lines.append(f"### [{f.severity}] {f.title}{flag_marker}")
            lines.append(f"- **Analyzer**: {f.analyzer}")
            lines.append(f"- **Confidence**: {f.confidence:.2f}")
            if f.offset >= 0:
                lines.append(f"- **Offset**: 0x{f.offset:x}")
            lines.append(f"- **Detail**: {f.detail}\n")
    return "\n".join(lines)


def _format_csv(findings: List[Finding]) -> str:
    """CSV output (mirrors GUI export)."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["ID", "File", "Analyzer", "Title", "Severity",
                      "Offset", "Confidence", "FlagMatch", "Detail"])
    for f in findings:
        detail = f.detail[:500] + "…" if len(f.detail) > 500 else f.detail
        writer.writerow([
            f.id, f.file, f.analyzer, f.title, f.severity,
            hex(f.offset) if f.offset >= 0 else "",
            f"{f.confidence:.2f}", str(f.flag_match), detail,
        ])
    return buf.getvalue()


def _format_html(findings: List[Finding]) -> str:
    """Self-contained HTML report (mirrors GUI export)."""
    sev_color = {"HIGH": "#cc0000", "MEDIUM": "#886600", "LOW": "#004488", "INFO": "#333"}
    by_file: dict[str, list[Finding]] = {}
    for f in findings:
        by_file.setdefault(f.file, []).append(f)

    rows: list[str] = []
    for fpath, flist in by_file.items():
        rows.append(f"<h2>{html.escape(str(fpath))}</h2>")
        for f in flist:
            if f.duplicate_of:
                continue
            color = sev_color.get(f.severity, "#333")
            flag_icon = "🚩 " if f.flag_match else ""
            detail_text = f.detail[:500] + "…" if len(f.detail) > 500 else f.detail
            rows.append(
                f'<div style="border-left:4px solid {color};padding:8px;margin:8px 0;">'
                f'<b style="color:{color}">[{f.severity}]</b> {flag_icon}'
                f'<b>{html.escape(f.title)}</b> '
                f'<span style="color:#888">(conf: {f.confidence:.2f}, analyzer: {f.analyzer})</span>'
                f'<br><code>{html.escape(detail_text)}</code>'
                f'</div>'
            )
    body = "\n".join(rows)
    return (
        "<!DOCTYPE html>\n"
        '<html><head><meta charset="utf-8"><title>CTF Hunter Report</title>\n'
        "<style>body{font-family:sans-serif;max-width:1200px;margin:auto;padding:20px}</style>\n"
        f"</head><body><h1>CTF Hunter Report</h1>{body}</body></html>"
    )


_FORMATTERS = {
    "text": _format_text,
    "json": _format_json,
    "markdown": _format_markdown,
    "csv": _format_csv,
    "html": _format_html,
}


# ── File collection ───────────────────────────────────────────────────────

def _collect_targets(paths: list[str]) -> list[str]:
    """Expand directories to their contained files (one level)."""
    targets: list[str] = []
    for p in paths:
        p = os.path.abspath(p)
        if os.path.isdir(p):
            for entry in sorted(os.listdir(p)):
                full = os.path.join(p, entry)
                if os.path.isfile(full):
                    targets.append(full)
        elif os.path.isfile(p):
            targets.append(p)
        else:
            print(f"Warning: skipping {p!r} (not a file or directory)", file=sys.stderr)
    return targets


# ── Argument parser ───────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ctf_hunter",
        description="CTF Hunter — automated CTF challenge file analyzer (CLI mode)",
    )
    parser.add_argument(
        "targets",
        nargs="*",
        help="Files or directories to analyze",
    )
    parser.add_argument(
        "--depth", "-d",
        choices=["fast", "deep", "auto"],
        default="fast",
        help="Analysis depth (default: fast)",
    )
    parser.add_argument(
        "--flag", "-f",
        default=r"CTF\{[^}]+\}",
        help=r"Flag regex pattern (default: CTF\{[^}]+\})",
    )
    parser.add_argument(
        "--format", "-F",
        choices=list(_FORMATTERS.keys()),
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Write output to file instead of stdout",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress progress messages on stderr",
    )
    parser.add_argument(
        "--flags-only",
        action="store_true",
        help="Only show findings that match the flag pattern",
    )
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=0.0,
        help="Minimum confidence threshold (0.0–1.0, default: 0.0)",
    )
    parser.add_argument(
        "--severity",
        choices=["HIGH", "MEDIUM", "LOW", "INFO"],
        default=None,
        help="Minimum severity filter",
    )
    parser.add_argument(
        "--feedback",
        metavar="FINDING_ID:correct|incorrect",
        default=None,
        help=(
            "Record feedback for a finding from the last run. "
            "Example: --feedback abc123:correct"
        ),
    )
    parser.add_argument(
        "--feedback-stats",
        action="store_true",
        help="Print a table of learned confidence weights per analyzer and finding type",
    )
    return parser


# ── Main entry point ──────────────────────────────────────────────────────

_SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


def _handle_feedback(spec: str) -> int:
    """Process --feedback FINDING_ID:correct|incorrect. Returns exit code."""
    if ":" not in spec:
        print(
            "Error: --feedback expects FINDING_ID:correct or FINDING_ID:incorrect",
            file=sys.stderr,
        )
        return 1
    finding_id, verdict = spec.rsplit(":", 1)
    finding_id = finding_id.strip()
    verdict = verdict.strip().lower()
    if verdict not in ("correct", "incorrect"):
        print(
            f"Error: verdict must be 'correct' or 'incorrect', got {verdict!r}",
            file=sys.stderr,
        )
        return 1
    was_correct = verdict == "correct"

    # Load last run
    if not _LAST_RUN_PATH.exists():
        print(
            f"Error: no last-run data found at {_LAST_RUN_PATH}. "
            "Run an analysis first.",
            file=sys.stderr,
        )
        return 1
    try:
        with open(_LAST_RUN_PATH, encoding="utf-8") as fh:
            last_findings = json.load(fh)
    except Exception as exc:
        print(f"Error reading last-run data: {exc}", file=sys.stderr)
        return 1

    # Find the matching finding (prefix match)
    matches = [f for f in last_findings if f.get("id", "").startswith(finding_id)]
    if not matches:
        print(
            f"Error: no finding with id starting with {finding_id!r} in last run.",
            file=sys.stderr,
        )
        return 1
    if len(matches) > 1:
        ids = ", ".join(m["id"][:12] for m in matches)
        print(
            f"Error: prefix {finding_id!r} is ambiguous — matches: {ids}. "
            "Provide more characters.",
            file=sys.stderr,
        )
        return 1
    match = matches[0]

    try:
        from core.feedback import FeedbackStore
        store = FeedbackStore()
        store.record(
            analyzer=match.get("analyzer", ""),
            finding_type=match.get("title", ""),
            encoding="",
            confidence_score=float(match.get("confidence", 0.5)),
            was_correct=was_correct,
            flag_format=match.get("flag_format", ""),
        )
    except Exception as exc:
        print(f"Error recording feedback: {exc}", file=sys.stderr)
        return 1

    print(
        f"Feedback recorded: finding {match['id'][:8]}… "
        f"({'correct' if was_correct else 'incorrect'})"
    )
    return 0


def _handle_feedback_stats() -> int:
    """Print a table of learned weights per analyzer/finding_type. Returns exit code."""
    try:
        from core.feedback import FeedbackStore
        store = FeedbackStore()
        stats = store.get_feedback_stats()
    except Exception as exc:
        print(f"Error reading feedback stats: {exc}", file=sys.stderr)
        return 1

    if not stats:
        print("No feedback recorded yet.")
        return 0

    # Column widths
    col_a  = max(len("Analyzer"),      max(len(s["analyzer"])     for s in stats))
    col_ft = max(len("Finding Type"),  max(len(s["finding_type"]) for s in stats))
    col_w  = 8
    col_n  = 7
    col_ok = 7
    col_no = 9

    header = (
        f"{'Analyzer':<{col_a}}  "
        f"{'Finding Type':<{col_ft}}  "
        f"{'Weight':>{col_w}}  "
        f"{'Total':>{col_n}}  "
        f"{'Correct':>{col_ok}}  "
        f"{'Incorrect':>{col_no}}"
    )
    sep = "-" * len(header)
    print(header)
    print(sep)
    for s in stats:
        print(
            f"{s['analyzer']:<{col_a}}  "
            f"{s['finding_type']:<{col_ft}}  "
            f"{s['weight']:>{col_w}.4f}  "
            f"{s['total']:>{col_n}}  "
            f"{s['correct']:>{col_ok}}  "
            f"{s['incorrect']:>{col_no}}"
        )
    return 0


def run_cli(argv: list[str] | None = None) -> int:
    """Run CTF Hunter in CLI mode.  Returns 0 on success, 1 on error."""
    parser = build_parser()
    args = parser.parse_args(argv)

    # --feedback-stats: just print table and exit
    if args.feedback_stats:
        return _handle_feedback_stats()

    # --feedback finding_id:correct|incorrect
    if args.feedback:
        return _handle_feedback(args.feedback)

    # Validate flag pattern
    try:
        flag_pattern = re.compile(args.flag, re.IGNORECASE)
    except re.error as exc:
        print(f"Error: invalid flag pattern: {exc}", file=sys.stderr)
        return 1

    # Require targets for analysis
    if not args.targets:
        print("Error: no files or directories specified.", file=sys.stderr)
        parser.print_help(sys.stderr)
        return 1

    # Collect targets
    targets = _collect_targets(args.targets)
    if not targets:
        print("Error: no files found to analyze.", file=sys.stderr)
        return 1

    # Analyze each file
    all_findings: list[Finding] = []
    for i, target in enumerate(targets, 1):
        if not args.quiet:
            print(f"[{i}/{len(targets)}] Analyzing {target} ({args.depth})...", file=sys.stderr)
        try:
            findings = dispatch(target, flag_pattern, args.depth)
            all_findings.extend(findings)
        except Exception as exc:
            print(f"Error analyzing {target}: {exc}", file=sys.stderr)

    # Persist last-run findings for --feedback look-ups
    try:
        _LAST_RUN_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(_LAST_RUN_PATH, "w", encoding="utf-8") as fh:
            json.dump([f.to_dict() for f in all_findings], fh, indent=2)
    except Exception:
        pass  # non-fatal

    # Apply filters
    if args.flags_only:
        all_findings = [f for f in all_findings if f.flag_match]

    if args.min_confidence > 0:
        all_findings = [f for f in all_findings if f.confidence >= args.min_confidence]

    if args.severity:
        min_sev = _SEVERITY_ORDER.get(args.severity, 3)
        all_findings = [f for f in all_findings
                        if _SEVERITY_ORDER.get(f.severity, 3) <= min_sev]

    # Sort: flags first, then by confidence descending
    all_findings.sort(
        key=lambda f: (not f.flag_match, -f.confidence, _SEVERITY_ORDER.get(f.severity, 3)),
    )

    # Run challenge fingerprinter on all (unfiltered-by-user) findings
    try:
        _fp = ChallengeFingerprinter()
        # Use all collected findings (before user filters) for better signal
        _fp_session_findings = [f for f in all_findings if not f.duplicate_of]
        fingerprint_matches = _fp.match(_fp_session_findings, top_n=3)
    except Exception as exc:
        logger.warning("Fingerprinting failed: %s", exc)
        fingerprint_matches = []

    # Build attack chains across files
    attack_chains = []
    try:
        if len(targets) >= 2:
            by_file: dict[str, list[Finding]] = {}
            for f in all_findings:
                by_file.setdefault(f.file, []).append(f)
            workspace = list(by_file.items())
            # Populate key registry from all findings using the KeyExtractor
            key_registry = KeyRegistry()
            _key_session = Session(findings=list(all_findings))
            _key_session.key_registry = key_registry
            for candidate in KeyExtractor().extract(_key_session):
                key_registry.register(candidate)
            builder = ChainBuilder(workspace, key_registry, flag_pattern)
            attack_chains = builder.build()
    except Exception as exc:
        logger.warning("Attack chain building failed: %s", exc)

    # Format output
    formatter = _FORMATTERS[args.format]
    if args.format == "json":
        # JSON output: dict with "findings" array and "fingerprint" array
        findings_list = [f.to_dict() for f in all_findings if not f.duplicate_of]
        fingerprint_list = [
            {
                "rank": i + 1,
                "name": m["archetype"].get("name", ""),
                "category": m["archetype"].get("category", ""),
                "source": m["archetype"].get("source", ""),
                "confidence_pct": m["confidence_pct"],
                "score": m["score"],
                "description": m["archetype"].get("description", ""),
                "typical_transforms": m["archetype"].get("typical_transforms", []),
                "solve_rate_hint": m["archetype"].get("solve_rate_hint", ""),
            }
            for i, m in enumerate(fingerprint_matches)
        ]
        output = json.dumps(
            {
                "findings": findings_list,
                "fingerprint": fingerprint_list,
                "attack_chains": [
                    ChainBuilder.chain_to_dict(chain) for chain in attack_chains
                ],
            },
            indent=2,
        )
    elif args.format == "text":
        output = (
            formatter(all_findings)
            + _fingerprint_text_section(fingerprint_matches)
            + ChainBuilder.chains_to_text(attack_chains)
        )
    else:
        output = formatter(all_findings)

    # Write output
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output)
        if not args.quiet:
            print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(output, end="")

    # Summary on stderr
    if not args.quiet:
        flag_count = sum(1 for f in all_findings if f.flag_match)
        high_count = sum(1 for f in all_findings if f.severity == "HIGH" and not f.duplicate_of)
        print(
            f"\nDone: {len(all_findings)} findings, "
            f"{flag_count} flag(s), {high_count} HIGH severity",
            file=sys.stderr,
        )
        if fingerprint_matches:
            top = fingerprint_matches[0]
            print(
                f"Top fingerprint: {top['archetype'].get('name', '?')} "
                f"({top['confidence_pct']}%)",
                file=sys.stderr,
            )

    return 0
