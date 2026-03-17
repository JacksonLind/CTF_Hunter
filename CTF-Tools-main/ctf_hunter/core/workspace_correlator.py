"""
Cross-File Workspace Correlator for CTF Hunter.

Extracts all strings, byte sequences, and key candidates from every file's
findings, then runs pairwise intersection to flag shared content across files.

Specifically checks:
  - Strings from binary/ELF findings against PCAP stream contents
  - Hash values found in one file against crackable content in another
  - Archive passwords found in one file against encrypted archives in another

Correlation findings are attributed to both source files with a combined
confidence score.
"""
from __future__ import annotations

import re
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .report import Finding, Session


# ---------------------------------------------------------------------------
# Heuristic patterns
# ---------------------------------------------------------------------------

_HASH_RE = re.compile(r"\b([0-9a-fA-F]{32,128})\b")
_PASSWORD_HINT_RE = re.compile(
    r"(?:password|passwd|pass|pwd|secret|key)\s*[:=]\s*([^\s,;\"\']{4,})",
    re.IGNORECASE,
)
_ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz"}

# Hash hex-string lengths by algorithm
_HASH_LENGTHS: dict[int, str] = {32: "MD5", 40: "SHA1", 64: "SHA256", 128: "SHA512"}


class WorkspaceCorrelator:
    """
    Correlates findings across multiple files in a session.

    Call ``correlate(session)`` to produce a list of cross-file correlation
    Findings that are appended to ``session.findings``.
    """

    def correlate(self, session: Session) -> List[Finding]:
        """
        Run pairwise correlation across all files in the session.
        Returns a list of new correlation findings (does NOT mutate session.findings
        directly — the caller is responsible for merging).
        """
        # Group existing findings by file
        by_file: Dict[str, List[Finding]] = {}
        for f in session.findings:
            by_file.setdefault(f.file, []).append(f)

        files = list(by_file.keys())
        if len(files) < 2:
            return []

        correlation_findings: List[Finding] = []

        # Build per-file feature sets
        features: Dict[str, _FileFeatures] = {
            path: _FileFeatures.from_findings(path, findings)
            for path, findings in by_file.items()
        }

        # Pairwise intersection
        for i, path_a in enumerate(files):
            for path_b in files[i + 1:]:
                fa = features[path_a]
                fb = features[path_b]
                correlation_findings.extend(
                    self._correlate_pair(path_a, fa, path_b, fb)
                )

        return correlation_findings

    # ------------------------------------------------------------------

    def _correlate_pair(
        self,
        path_a: str,
        fa: "_FileFeatures",
        path_b: str,
        fb: "_FileFeatures",
    ) -> List[Finding]:
        results: List[Finding] = []

        # 1. String verbatim intersection
        shared_strings = fa.strings & fb.strings
        for s in sorted(shared_strings):
            if len(s) < 6:
                continue
            results.append(self._correlation_finding(
                path_a,
                path_b,
                "Shared string across files",
                f"String {s!r} appears in both {Path(path_a).name} and {Path(path_b).name}",
                confidence=0.65,
            ))

        # 2. Hash values from file A appear in file B's strings
        hash_matches = fa.hashes & fb.strings | fb.hashes & fa.strings
        for h in sorted(hash_matches):
            results.append(self._correlation_finding(
                path_a,
                path_b,
                "Hash value shared across files",
                (
                    f"Hash {h[:32]}… found in both {Path(path_a).name} "
                    f"and {Path(path_b).name} — possible cracking target."
                ),
                confidence=0.72,
            ))

        # 3. Password hints from file A versus encrypted archives from file B
        for pwd in fa.password_hints:
            if fb.has_encrypted_archive:
                results.append(self._correlation_finding(
                    path_a,
                    path_b,
                    "Potential archive password found in companion file",
                    (
                        f"Password hint {pwd!r} from {Path(path_a).name} "
                        f"may unlock encrypted archive {Path(path_b).name}."
                    ),
                    confidence=0.75,
                ))
        for pwd in fb.password_hints:
            if fa.has_encrypted_archive:
                results.append(self._correlation_finding(
                    path_b,
                    path_a,
                    "Potential archive password found in companion file",
                    (
                        f"Password hint {pwd!r} from {Path(path_b).name} "
                        f"may unlock encrypted archive {Path(path_a).name}."
                    ),
                    confidence=0.75,
                ))

        return results

    # ------------------------------------------------------------------

    @staticmethod
    def _correlation_finding(
        path_a: str,
        path_b: str,
        title: str,
        detail: str,
        confidence: float = 0.6,
    ) -> Finding:
        return Finding(
            id=str(uuid.uuid4()),
            file=path_a,
            analyzer="WorkspaceCorrelator",
            title=title,
            severity="MEDIUM",
            detail=detail + f"\n[Correlation: {Path(path_a).name} ↔ {Path(path_b).name}]",
            confidence=confidence,
        )


# ---------------------------------------------------------------------------
# Feature extraction helper
# ---------------------------------------------------------------------------

class _FileFeatures:
    """Aggregated string/hash/password features for one file."""

    def __init__(self) -> None:
        self.strings: Set[str] = set()
        self.hashes: Set[str] = set()
        self.password_hints: Set[str] = set()
        self.has_encrypted_archive: bool = False

    @classmethod
    def from_findings(cls, path: str, findings: List[Finding]) -> "_FileFeatures":
        obj = cls()

        # Check if the file itself is an encrypted archive
        ext = Path(path).suffix.lower()
        if ext in _ARCHIVE_EXTENSIONS:
            obj.has_encrypted_archive = any(
                "encrypt" in f.title.lower() or "password" in f.title.lower()
                for f in findings
            )

        for finding in findings:
            text = f"{finding.title} {finding.detail}"

            # Extract printable strings (6+ chars)
            for word in re.findall(r"[A-Za-z0-9_\-\.@]{6,}", text):
                obj.strings.add(word)

            # Extract hashes
            for h in _HASH_RE.findall(text):
                if len(h) in _HASH_LENGTHS:
                    obj.hashes.add(h.lower())

            # Extract password hints
            for m in _PASSWORD_HINT_RE.finditer(text):
                obj.password_hints.add(m.group(1))

        return obj
