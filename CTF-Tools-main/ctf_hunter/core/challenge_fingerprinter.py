"""
Challenge Fingerprinter for CTF Hunter.

Computes cosine similarity between the current session's finding-type frequency
vector and each archetype's signal_weights vector to identify the most likely
CTF challenge type.

Usage::

    from core.challenge_fingerprinter import ChallengeFingerprinter
    fingerprinter = ChallengeFingerprinter()
    matches = fingerprinter.match(findings, top_n=3)
    # Each match: {"archetype": {...}, "score": 0.87, "confidence_pct": 87.0}
"""
from __future__ import annotations

import json
import logging
import math
from pathlib import Path
from typing import Dict, List, Optional

from .report import Finding

logger = logging.getLogger(__name__)

# Path to the bundled archetype database (relative to this file)
_DB_PATH = Path(__file__).parent.parent / "data" / "ctf_archetypes.json"


def _cosine_similarity(vec_a: Dict[str, float], vec_b: Dict[str, float]) -> float:
    """Compute cosine similarity between two sparse vectors represented as dicts.

    Returns a float in [0.0, 1.0], or 0.0 if either vector is zero.
    """
    if not vec_a or not vec_b:
        return 0.0

    # Dot product over shared keys
    dot = sum(vec_a.get(k, 0.0) * vec_b.get(k, 0.0) for k in vec_b)

    # Magnitudes
    mag_a = math.sqrt(sum(v * v for v in vec_a.values()))
    mag_b = math.sqrt(sum(v * v for v in vec_b.values()))

    if mag_a == 0.0 or mag_b == 0.0:
        return 0.0
    return dot / (mag_a * mag_b)


def _build_finding_vector(findings: List[Finding]) -> Dict[str, float]:
    """Build a normalised frequency vector from a list of findings.

    Each dimension corresponds to a lower-cased keyword extracted from:
    * The finding title (every whitespace-separated token)
    * The analyzer name (as a single token)

    Counts are *not* normalised to unit length here — cosine similarity handles
    that algebraically.
    """
    counts: Dict[str, float] = {}
    for f in findings:
        # Tokenise title
        for token in f.title.lower().split():
            counts[token] = counts.get(token, 0.0) + 1.0
        # Also add whole title as a phrase (for multi-word signal matching)
        title_phrase = f.title.lower()
        counts[title_phrase] = counts.get(title_phrase, 0.0) + 1.0
        # Add analyzer name
        if f.analyzer:
            anal = f.analyzer.lower()
            counts[anal] = counts.get(anal, 0.0) + 1.0
        # Add detail keywords (first 200 chars only, to avoid noise)
        snippet = f.detail[:200].lower() if f.detail else ""
        for token in snippet.split():
            # Only short words that look like identifiers or keywords
            if 3 <= len(token) <= 20 and token.isalpha():
                counts[token] = counts.get(token, 0.0) + 0.3
    return counts


def _expand_signal_weights(signal_weights: Dict[str, float]) -> Dict[str, float]:
    """Expand archetype signal_weights to also match individual tokens.

    Multi-word keys (e.g. "stack overflow") are kept as-is, but each individual
    word token is also added at half weight so the finding vector can partially
    match even when the exact phrase doesn't appear.
    """
    expanded: Dict[str, float] = {}
    for phrase, weight in signal_weights.items():
        expanded[phrase] = weight
        tokens = phrase.lower().split()
        if len(tokens) > 1:
            for token in tokens:
                # Don't override a more specific phrase match
                if token not in expanded:
                    expanded[token] = weight * 0.5
    return expanded


class ChallengeFingerprinter:
    """Match the current session's findings against the archetype database.

    Parameters
    ----------
    db_path:
        Path to the JSON archetype database.  Defaults to the bundled
        ``data/ctf_archetypes.json`` in the package.
    """

    def __init__(self, db_path: Optional[Path] = None) -> None:
        path = db_path or _DB_PATH
        try:
            with open(path, "r", encoding="utf-8") as fh:
                self._archetypes: List[dict] = json.load(fh)
            logger.debug("Loaded %d archetypes from %s", len(self._archetypes), path)
        except Exception as exc:
            logger.warning("Could not load archetype database from %s: %s", path, exc)
            self._archetypes = []

        # Pre-expand signal weights for each archetype
        self._expanded: List[Dict[str, float]] = [
            _expand_signal_weights(a.get("signal_weights", {}))
            for a in self._archetypes
        ]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def match(
        self,
        findings: List[Finding],
        top_n: int = 3,
    ) -> List[dict]:
        """Return the top-*n* archetype matches for the given findings list.

        Parameters
        ----------
        findings:
            Non-duplicate findings from the current session.
        top_n:
            Number of top matches to return (default 3).

        Returns
        -------
        list of dict, each containing:
            ``archetype``        — the full archetype dict from the database
            ``score``            — raw cosine similarity in [0.0, 1.0]
            ``confidence_pct``   — percentage score rounded to one decimal
        """
        if not self._archetypes or not findings:
            return []

        finding_vec = _build_finding_vector(findings)

        scored: List[tuple[float, dict]] = []
        for archetype, expanded_weights in zip(self._archetypes, self._expanded):
            score = _cosine_similarity(finding_vec, expanded_weights)
            scored.append((score, archetype))

        # Sort descending by score
        scored.sort(key=lambda x: -x[0])

        results = []
        for score, archetype in scored[:top_n]:
            results.append({
                "archetype": archetype,
                "score": round(score, 4),
                "confidence_pct": round(score * 100, 1),
            })
        return results

    def top_match(self, findings: List[Finding]) -> Optional[dict]:
        """Convenience method returning only the single best match, or None."""
        matches = self.match(findings, top_n=1)
        return matches[0] if matches else None
