"""
Session diff: compare two CTF Hunter sessions and report new, removed, modified,
and unchanged findings.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Tuple

from core.report import Finding, Session


def _stable_key(f: Finding) -> Tuple[str, str, str, int]:
    """Return the stable identity key for a finding used during diff matching.

    Key: (analyzer_name, severity, title, byte_offset).

    Known limitation: if byte_offset shifts between sessions — e.g. after
    patching a binary or when two analyzers produce the same logical finding at
    slightly different offsets — the diff will report a spurious "removed" entry
    from session A and a "new" entry from session B instead of a "modified" pair.
    For most CTF workflows (re-running the same file) this is not a problem, but
    users should be aware of this when comparing sessions from patched binaries.
    Using offset=-1 for findings that are not tied to a specific byte range avoids
    this issue for those findings.
    """
    return (f.analyzer, f.severity, f.title, f.offset)


@dataclass
class DiffEntry:
    """A single entry in a session diff."""

    category: str           # "new" | "removed" | "modified" | "unchanged"
    finding: Finding        # The finding from the primary (or B) session
    old_detail: str = ""    # Only populated for "modified" entries (detail from session A)
    new_detail: str = ""    # Only populated for "modified" entries (detail from session B)


@dataclass
class SessionDiff:
    """Result of comparing two sessions."""

    new: List[DiffEntry] = field(default_factory=list)
    removed: List[DiffEntry] = field(default_factory=list)
    modified: List[DiffEntry] = field(default_factory=list)
    unchanged: List[DiffEntry] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.new) + len(self.removed) + len(self.modified) + len(self.unchanged)


def diff_sessions(session_a: Session, session_b: Session) -> SessionDiff:
    """Compare two sessions and return a SessionDiff.

    Findings are matched by the stable key (analyzer, severity, title, byte_offset).
    - Present only in A  → "removed"
    - Present only in B  → "new"
    - Present in both, detail unchanged → "unchanged"
    - Present in both, detail changed   → "modified"

    Neither session is mutated.
    """
    # Build lookup tables: key → first matching Finding (duplicates with the same
    # key are de-duplicated; in practice keys should be unique per session).
    map_a: dict[tuple, Finding] = {}
    for f in session_a.findings:
        key = _stable_key(f)
        if key not in map_a:
            map_a[key] = f

    map_b: dict[tuple, Finding] = {}
    for f in session_b.findings:
        key = _stable_key(f)
        if key not in map_b:
            map_b[key] = f

    result = SessionDiff()

    all_keys = set(map_a) | set(map_b)
    for key in sorted(all_keys):
        in_a = key in map_a
        in_b = key in map_b

        if in_a and not in_b:
            result.removed.append(DiffEntry(category="removed", finding=map_a[key]))
        elif in_b and not in_a:
            result.new.append(DiffEntry(category="new", finding=map_b[key]))
        else:
            fa = map_a[key]
            fb = map_b[key]
            if fa.detail == fb.detail:
                result.unchanged.append(DiffEntry(category="unchanged", finding=fb))
            else:
                result.modified.append(DiffEntry(
                    category="modified",
                    finding=fb,
                    old_detail=fa.detail,
                    new_detail=fb.detail,
                ))

    return result
