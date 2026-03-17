"""
Solver Feedback Loop for CTF Hunter.

FeedbackStore: SQLite-backed storage of per-finding correctness feedback.
WeightLearner: Computes per-(analyzer, finding_type) weight multipliers using
               a simple Bayesian update (Beta(1,1) prior → weight = 1.0 when
               no data, shifts toward 2.0 for all-correct or 0.0 for all-incorrect).
"""
from __future__ import annotations

import datetime
import sqlite3
from pathlib import Path
from typing import Optional

_DB_PATH = Path.home() / ".ctf_hunter" / "feedback.db"

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS feedback (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    analyzer         TEXT    NOT NULL,
    finding_type     TEXT    NOT NULL,
    encoding         TEXT    NOT NULL DEFAULT '',
    confidence_score REAL    NOT NULL,
    was_correct      INTEGER NOT NULL,
    flag_format      TEXT    NOT NULL DEFAULT '',
    timestamp        TEXT    NOT NULL
)
"""


def _extract_encoding(finding) -> str:
    """Try to extract encoding name from a Finding's title or first 100 chars of detail."""
    haystack = (finding.title + " " + finding.detail[:100]).lower()
    for enc in (
        "base64", "base32", "base58", "base85",
        "hex", "xor", "rot13", "caesar",
        "url", "morse", "binary", "utf-8", "ascii",
    ):
        if enc in haystack:
            return enc
    return ""


def _compute_weight(correct: int, total: int) -> float:
    """
    Bayesian weight with a symmetric Beta(1,1) prior.

    At zero feedback the weight is exactly 1.0 (neutral multiplier).
    As correct findings accumulate the weight rises toward 2.0.
    As incorrect findings accumulate the weight falls toward 0.0.

        weight = 2 * (1 + correct) / (2 + total)
    """
    return 2.0 * (1 + correct) / (2 + total)


class FeedbackStore:
    """Persist per-finding correctness feedback in a local SQLite database."""

    DB_PATH: Path = _DB_PATH

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self.db_path = Path(db_path) if db_path else self.DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # ------------------------------------------------------------------
    # Internal helpers

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self.db_path))

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(_CREATE_TABLE)
            conn.commit()

    # ------------------------------------------------------------------
    # Public API

    def record(
        self,
        analyzer: str,
        finding_type: str,
        encoding: str,
        confidence_score: float,
        was_correct: bool,
        flag_format: str = "",
    ) -> None:
        """Insert one feedback row into the database."""
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO feedback "
                "(analyzer, finding_type, encoding, confidence_score, "
                " was_correct, flag_format, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    analyzer, finding_type, encoding,
                    float(confidence_score), int(was_correct),
                    flag_format, ts,
                ),
            )
            conn.commit()

    def record_finding(
        self,
        finding,
        was_correct: bool,
        flag_format: str = "",
    ) -> None:
        """Convenience wrapper that accepts a Finding object."""
        self.record(
            analyzer=finding.analyzer,
            finding_type=finding.title,
            encoding=_extract_encoding(finding),
            confidence_score=finding.confidence,
            was_correct=was_correct,
            flag_format=flag_format,
        )

    def get_feedback_stats(self) -> list[dict]:
        """
        Return per-(analyzer, finding_type) statistics and computed weights.

        Each dict contains: analyzer, finding_type, total, correct, incorrect,
        weight, avg_confidence.
        """
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT analyzer, finding_type,
                       COUNT(*)          AS total,
                       SUM(was_correct)  AS correct,
                       AVG(confidence_score) AS avg_conf
                FROM   feedback
                GROUP  BY analyzer, finding_type
                ORDER  BY analyzer, finding_type
                """
            ).fetchall()
        return [
            {
                "analyzer":       row[0],
                "finding_type":   row[1],
                "total":          row[2],
                "correct":        int(row[3] or 0),
                "incorrect":      row[2] - int(row[3] or 0),
                "weight":         _compute_weight(int(row[3] or 0), row[2]),
                "avg_confidence": row[4],
            }
            for row in rows
        ]


class WeightLearner:
    """
    Queries a FeedbackStore and exposes per-(analyzer, finding_type) weight
    multipliers for use by the confidence scorer.
    """

    def __init__(self, store: Optional[FeedbackStore] = None) -> None:
        self._store = store or FeedbackStore()
        self._cache: Optional[dict[tuple[str, str], float]] = None

    def _ensure_cache(self) -> None:
        if self._cache is None:
            self._cache = {}
            for stat in self._store.get_feedback_stats():
                key = (stat["analyzer"], stat["finding_type"])
                self._cache[key] = stat["weight"]

    def get_weight(self, analyzer: str, finding_type: str) -> float:
        """Return the learned weight for this pair (1.0 if no feedback yet)."""
        self._ensure_cache()
        return self._cache.get((analyzer, finding_type), 1.0)

    def get_all_weights(self) -> dict[tuple[str, str], float]:
        """Return a copy of the full (analyzer, finding_type) → weight map."""
        self._ensure_cache()
        return dict(self._cache)

    def invalidate_cache(self) -> None:
        """Force a re-query on the next call to get_weight / get_all_weights."""
        self._cache = None
