"""
Confidence Scoring System for CTF Hunter.

ConfidenceScorer mutates all findings in a session in-place, applying:
  - Corroboration boosts when multiple independent analyzers flag the same byte range
  - Flag-pattern match boost when a decoded output itself contains a flag
  - Anomalous entropy boost when decoded output entropy differs significantly from input
  - Penalties for high-entropy garbage or non-printable decoded outputs
  - Learned weight multipliers from the FeedbackStore (per analyzer + finding type)
"""
from __future__ import annotations

import math
import re
import string
from typing import List, Optional

from .report import Finding, Session

# How close two offsets must be (in bytes) to be considered the same region.
_REGION_PROXIMITY = 32

# Penalty applied when decoded content is high-entropy or non-printable.
_GARBAGE_PENALTY = 0.15

# Boost applied when a decoded value itself contains a flag pattern.
_FLAG_DECODE_BOOST = 0.20

# Boost applied when a decoded value has notably lower entropy than its source
# (high-entropy source, low-entropy result is a good sign).
_LOW_ENTROPY_RESULT_BOOST = 0.10

# Maximum confidence cap
_MAX_CONFIDENCE = 0.99

# Entropy thresholds for garbage/suspicious detection
_HIGH_ENTROPY_THRESHOLD = 7.0    # > this → likely encrypted/compressed garbage
_MEDIUM_ENTROPY_THRESHOLD = 6.5  # > this → suspicious if mostly non-printable


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    total = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy


def _string_entropy(s: str) -> float:
    return _shannon_entropy(s.encode("utf-8", errors="replace"))


def _is_mostly_printable(text: str, threshold: float = 0.80) -> bool:
    if not text:
        return False
    return sum(1 for c in text if c in string.printable) / len(text) >= threshold


def _extract_decoded_result(detail: str) -> str:
    """Extract the decoded portion from a finding's detail string (after '→')."""
    if "→" in detail:
        return detail.split("→", 1)[1].strip()
    return ""


class ConfidenceScorer:
    """
    Scores (mutates) all findings in a session after analyzers complete.

    Scoring rules applied in order:
    1. Corroboration boost: findings within REGION_PROXIMITY of each other from
       different analyzers get a proportional confidence lift.
    2. Flag-in-decoded-output boost: if detail contains '→' and the result
       matches the session flag pattern, boost confidence.
    3. Low-entropy-result boost: if decoded output entropy is much lower than
       average file entropy, this suggests meaningful decoding occurred.
    4. Garbage penalty: if decoded output is mostly non-printable or has
       very high entropy, penalize confidence.
    5. Learned-weight multiplier: scale each finding's confidence by the
       per-(analyzer, finding_type) weight derived from user feedback.
    """

    def __init__(self, weight_learner: Optional["WeightLearner"] = None) -> None:
        # Import lazily to avoid circular imports and to handle missing DB gracefully.
        self._weight_learner = weight_learner

    def _get_learner(self):
        if self._weight_learner is None:
            try:
                from .feedback import WeightLearner
                self._weight_learner = WeightLearner()
            except Exception:
                self._weight_learner = None
        return self._weight_learner

    def score_session(self, session: Session) -> None:
        """Mutate all findings in *session* in-place, updating confidence scores."""
        findings = session.findings
        if not findings:
            return

        try:
            if isinstance(session.flag_pattern, re.Pattern):
                flag_re = session.flag_pattern
            else:
                flag_re = re.compile(session.flag_pattern, re.IGNORECASE)
        except re.error:
            flag_re = re.compile(r"CTF\{[^}]+\}", re.IGNORECASE)

        # Group findings by file for corroboration analysis
        by_file: dict[str, List[Finding]] = {}
        for f in findings:
            by_file.setdefault(f.file, []).append(f)

        for file_path, file_findings in by_file.items():
            self._apply_corroboration(file_findings)
            self._apply_decode_quality(file_findings, flag_re)

        # Apply learned weight multipliers from feedback history
        learner = self._get_learner()
        if learner is not None:
            for f in findings:
                weight = learner.get_weight(f.analyzer, f.title)
                if weight != 1.0:
                    f.confidence = f.confidence * weight

        # Final clamp
        for f in findings:
            f.confidence = min(_MAX_CONFIDENCE, max(0.0, f.confidence))

    # ------------------------------------------------------------------

    def _apply_corroboration(self, findings: List[Finding]) -> None:
        """
        For each finding, check how many other findings from *different* analyzers
        land within REGION_PROXIMITY bytes of it.  Boost confidence proportionally.
        """
        for i, f in enumerate(findings):
            if f.offset < 0:
                continue
            neighbors = [
                other for j, other in enumerate(findings)
                if i != j
                and other.offset >= 0
                and other.analyzer != f.analyzer
                and abs(other.offset - f.offset) <= _REGION_PROXIMITY
                and other.id not in f.corroboration
            ]
            if not neighbors:
                continue
            # Corroboration boost: diminishing returns beyond 3 corroborators
            n = min(len(neighbors), 3)
            boost = n * 0.05
            f.confidence = min(_MAX_CONFIDENCE, f.confidence + boost)
            # Record supporting finding IDs
            for nb in neighbors:
                if nb.id not in f.corroboration:
                    f.corroboration.append(nb.id)

    def _apply_decode_quality(
        self,
        findings: List[Finding],
        flag_re: re.Pattern,
    ) -> None:
        """
        For findings that produced a decoded output (detail contains '→'):
        - Boost if decoded result matches flag pattern.
        - Boost if decoded result has much lower entropy than its encoded input.
        - Penalize if decoded result is mostly non-printable or very high entropy.
        """
        for f in findings:
            decoded = _extract_decoded_result(f.detail)
            if not decoded:
                continue

            # Flag-in-decoded-output boost
            if flag_re.search(decoded) and not f.flag_match:
                f.confidence = min(_MAX_CONFIDENCE, f.confidence + _FLAG_DECODE_BOOST)
                f.flag_match = True

            decoded_ent = _string_entropy(decoded)

            # Extract the input (before '→') to compare entropy
            if "→" in f.detail:
                encoded_part = f.detail.split("→", 1)[0].strip()
                # Strip common prefixes like "Input: "
                for pfx in ("Input: ", "Key=0x", "Key="):
                    if encoded_part.startswith(pfx):
                        encoded_part = encoded_part[len(pfx):]
                encoded_ent = _string_entropy(encoded_part)
            else:
                encoded_ent = decoded_ent

            # Garbage penalty: high entropy decoded result that isn't printable
            if decoded_ent > _HIGH_ENTROPY_THRESHOLD and not _is_mostly_printable(decoded):
                f.confidence = max(0.0, f.confidence - _GARBAGE_PENALTY)
            elif decoded_ent > _MEDIUM_ENTROPY_THRESHOLD and not _is_mostly_printable(decoded, 0.70):
                f.confidence = max(0.0, f.confidence - _GARBAGE_PENALTY * 0.5)
            # Low-entropy result boost: entropy dropped significantly (good decoding)
            elif encoded_ent > 5.0 and decoded_ent < 4.0 and _is_mostly_printable(decoded):
                f.confidence = min(_MAX_CONFIDENCE, f.confidence + _LOW_ENTROPY_RESULT_BOOST)
