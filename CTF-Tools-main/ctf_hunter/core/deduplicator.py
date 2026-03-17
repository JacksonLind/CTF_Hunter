"""
Finding deduplicator: merges findings within 16 bytes of each other from
different analyzers; computes corroboration-boosted confidence scores.
"""
from __future__ import annotations

from typing import Dict, List, Optional

from .report import Finding

PROXIMITY_BYTES = 16

# Minimum confidence for a flag-match finding to trigger XOR suppression.
_FLAG_MATCH_CONFIDENCE_THRESHOLD = 0.90


def deduplicate(findings: List[Finding]) -> List[Finding]:
    """
    Group findings by file + proximity + severity.  When multiple analyzers
    flag the same region, merge them: keep the highest-confidence primary,
    mark the rest as duplicate_of, and boost confidence by corroboration.

    After proximity-based deduplication a suppression pass is applied: if any
    finding for a file has flag_match=True and confidence >= 0.90, all XOR
    recovery findings for that same file are downgraded to INFO severity and
    their duplicate_of is set to the highest-confidence flag-match finding.
    """
    if not findings:
        return findings

    # Sort for stable grouping
    sorted_findings = sorted(findings, key=lambda f: (f.file, f.offset, -f.confidence))
    groups: List[List[Finding]] = []

    for finding in sorted_findings:
        placed = False
        for group in groups:
            representative = group[0]
            if (
                finding.file == representative.file
                and finding.severity == representative.severity
                and _within_proximity(finding.offset, representative.offset)
            ):
                group.append(finding)
                placed = True
                break
        if not placed:
            groups.append([finding])

    result: List[Finding] = []
    for group in groups:
        if len(group) == 1:
            result.append(group[0])
            continue

        # Primary = highest original confidence
        primary = max(group, key=lambda f: f.confidence)
        count = len(group)
        # Confidence boost: 1 - (1 / corroboration_count), capped at 0.99
        boosted = min(0.99, 1.0 - 1.0 / count)
        primary.confidence = max(primary.confidence, boosted)
        primary.corroboration_count = count
        # Merge detail strings from all analyzers
        combined_details = [f"{f.analyzer}: {f.detail}" for f in group if f != primary]
        if combined_details:
            primary.detail = primary.detail + " | Also: " + "; ".join(combined_details)
        primary.flag_match = any(f.flag_match for f in group)
        result.append(primary)

        for other in group:
            if other is not primary:
                other.duplicate_of = primary.id
                result.append(other)

    _suppress_xor_findings(result)
    return result


def _suppress_xor_findings(findings: List[Finding]) -> None:
    """
    Suppression rule: for each file that already has a high-confidence flag
    match, downgrade all XOR recovery findings for that file to INFO severity
    and mark them as duplicates of the best flag-match finding.

    Operates in-place on *findings*.
    """
    # Collect the highest-confidence flag-match finding per file.
    best_flag_matches: Dict[str, Finding] = {}
    for f in findings:
        if f.flag_match and f.confidence >= _FLAG_MATCH_CONFIDENCE_THRESHOLD:
            current = best_flag_matches.get(f.file)
            if current is None or f.confidence > current.confidence:
                best_flag_matches[f.file] = f

    if not best_flag_matches:
        return

    for f in findings:
        anchor = best_flag_matches.get(f.file)
        if anchor is None:
            continue
        # Skip if this finding IS the anchor (don't suppress the flag match itself).
        if f is anchor:
            continue
        if "XOR" in f.title:
            f.severity = "INFO"
            if f.duplicate_of is None:
                f.duplicate_of = anchor.id


def _within_proximity(a: int, b: int) -> bool:
    """Return True if offsets are within PROXIMITY_BYTES of each other."""
    if a < 0 or b < 0:
        return False
    return abs(a - b) <= PROXIMITY_BYTES
