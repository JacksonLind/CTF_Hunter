"""
Database analyzer: SQLite table dump, flag pattern search across all fields.
"""
from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from typing import List, Optional

from core.report import Finding
from core.ai_client import AIClient
from .base import Analyzer

_SQLITE_MAGIC = b"SQLite format 3\x00"


class DatabaseAnalyzer(Analyzer):
    def analyze(
        self,
        path: str,
        flag_pattern: re.Pattern,
        depth: str,
        ai_client: Optional[AIClient],
        session=None,
        dispatcher_module=None,
    ) -> List[Finding]:
        findings: List[Finding] = []
        try:
            header = Path(path).read_bytes()[:16]
        except Exception:
            return []
        if not header.startswith(_SQLITE_MAGIC[:15]):
            return []

        try:
            conn = sqlite3.connect(path)
            cursor = conn.cursor()
        except Exception as exc:
            return [self._finding(path, f"SQLite open error: {exc}", "", confidence=0.2)]

        try:
            # Get table names
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [row[0] for row in cursor.fetchall()]

            findings.append(self._finding(
                path,
                f"SQLite database: {len(tables)} table(s)",
                "Tables: " + ", ".join(tables[:20]),
                severity="INFO",
                confidence=0.6,
            ))

            for table in tables:
                # Get schema
                cursor.execute(f"PRAGMA table_info([{table}]);")
                cols = cursor.fetchall()
                col_names = [c[1] for c in cols]
                col_types = [c[2] for c in cols]
                schema = ", ".join(f"{n} {t}" for n, t in zip(col_names, col_types))
                findings.append(self._finding(
                    path,
                    f"Table '{table}' schema",
                    schema,
                    severity="INFO",
                    confidence=0.5,
                ))

                # Dump rows and search for flag
                try:
                    cursor.execute(f"SELECT * FROM [{table}] LIMIT 10000;")
                    rows = cursor.fetchall()
                    for row_idx, row in enumerate(rows):
                        for col_idx, value in enumerate(row):
                            cell = str(value) if value is not None else ""
                            if self._check_flag(cell, flag_pattern):
                                col_name = col_names[col_idx] if col_idx < len(col_names) else str(col_idx)
                                findings.append(self._finding(
                                    path,
                                    f"Flag pattern in table '{table}', column '{col_name}', row {row_idx}",
                                    cell[:300],
                                    severity="HIGH",
                                    flag_match=True,
                                    confidence=0.95,
                                ))
                except Exception as exc:
                    findings.append(self._finding(
                        path, f"Error reading table '{table}': {exc}",
                        "", confidence=0.2,
                    ))

        except Exception as exc:
            findings.append(self._finding(path, f"SQLite analysis error: {exc}", "", confidence=0.2))
        finally:
            conn.close()

        self._run_redispatch_hook(findings, session, dispatcher_module)
        return findings
