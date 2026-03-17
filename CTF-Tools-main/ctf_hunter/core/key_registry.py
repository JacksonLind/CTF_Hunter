"""
Key Candidate Registry for CTF Hunter.

Maintains a session-scoped collection of cryptographic key candidates
discovered by any analyzer, enabling cross-finding key correlation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class KeyCandidate:
    """A cryptographic key candidate extracted from a session finding."""

    value: str                  # the key string itself e.g. "HIDDEN"
    source_finding_id: str      # finding that produced this key
    key_type: str               # "vigenere" | "xor" | "aes" | "zip_password" | "generic"
    confidence: float           # 0.0–1.0
    context: str                # human-readable explanation of why this looks like a key


class KeyRegistry:
    """Session-scoped registry of key candidates discovered across all findings.

    Stores :class:`KeyCandidate` objects and provides filtered, confidence-ordered
    retrieval so that any part of the pipeline can query for usable keys without
    knowing which finding originally surfaced them.
    """

    def __init__(self) -> None:
        self._candidates: List[KeyCandidate] = []

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------

    def register(self, candidate: KeyCandidate) -> None:
        """Add *candidate* to the registry, skipping exact duplicates."""
        for existing in self._candidates:
            if (
                existing.value == candidate.value
                and existing.key_type == candidate.key_type
                and existing.source_finding_id == candidate.source_finding_id
            ):
                return
        self._candidates.append(candidate)

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def get_candidates(
        self, key_type: Optional[str] = None
    ) -> List[KeyCandidate]:
        """Return all candidates, optionally filtered by *key_type*.

        Results are ordered by confidence descending.

        Args:
            key_type: If provided, only candidates whose ``key_type`` matches
                this string are returned.  Pass ``None`` (the default) to get
                every registered candidate.

        Returns:
            A new list of matching :class:`KeyCandidate` objects, ordered from
            highest to lowest confidence.
        """
        if key_type is None:
            results = list(self._candidates)
        else:
            results = [c for c in self._candidates if c.key_type == key_type]
        results.sort(key=lambda c: c.confidence, reverse=True)
        return results

    def __len__(self) -> int:
        return len(self._candidates)

    def __repr__(self) -> str:
        return f"KeyRegistry({len(self._candidates)} candidates)"
