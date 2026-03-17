"""
Timeline tab: displays the chronological timestamp timeline reconstructed by
ForensicsTimelineAnalyzer for the selected file.
"""
from __future__ import annotations

import os
from typing import List

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget,
    QTableWidgetItem, QHeaderView, QPushButton, QComboBox,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont

from core.report import Finding


class TimelineTab(QWidget):
    """Shows timestamp timeline data from ForensicsTimelineAnalyzer findings."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._all_findings: List[Finding] = []

        layout = QVBoxLayout(self)

        # Header row
        hdr = QHBoxLayout()
        self._title_label = QLabel("No timeline data available.")
        self._title_label.setStyleSheet("font-weight: bold; font-size: 13px;")
        hdr.addWidget(self._title_label)
        hdr.addStretch()

        hdr.addWidget(QLabel("File:"))
        self._file_combo = QComboBox()
        self._file_combo.setMinimumWidth(220)
        self._file_combo.currentTextChanged.connect(self._refresh_for_file)
        hdr.addWidget(self._file_combo)

        self._clear_btn = QPushButton("Clear")
        self._clear_btn.clicked.connect(self._clear)
        hdr.addWidget(self._clear_btn)
        layout.addLayout(hdr)

        # Timeline table
        self._table = QTableWidget()
        self._table.setColumnCount(5)
        self._table.setHorizontalHeaderLabels([
            "Source", "Field Name", "Raw Value", "Formatted DateTime", "Anomaly Flag"
        ])
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.setColumnWidth(0, 100)
        self._table.setColumnWidth(1, 200)
        self._table.setColumnWidth(2, 140)
        self._table.setColumnWidth(3, 180)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setAlternatingRowColors(True)
        layout.addWidget(self._table)

    # ------------------------------------------------------------------

    def refresh(self, findings: List[Finding]) -> None:
        """Update with all findings; extract timeline data."""
        self._all_findings = findings

        # Collect files that have timeline findings
        files_with_timeline: list[str] = []
        for f in findings:
            if (f.analyzer == "ForensicsTimelineAnalyzer"
                    and "Timeline:" in f.title
                    and f.file not in files_with_timeline):
                files_with_timeline.append(f.file)

        current = self._file_combo.currentText()
        self._file_combo.blockSignals(True)
        self._file_combo.clear()
        for fp in files_with_timeline:
            self._file_combo.addItem(os.path.basename(fp), fp)
        self._file_combo.blockSignals(False)

        if files_with_timeline:
            # Re-select the previously selected file if still present
            idx = self._file_combo.findText(
                current, Qt.MatchFlag.MatchContains
            )
            self._file_combo.setCurrentIndex(max(idx, 0))
            self._refresh_for_file(self._file_combo.currentText())
        else:
            self._table.setRowCount(0)
            self._title_label.setText("No timeline data available.")

    def _refresh_for_file(self, _: str) -> None:
        file_path = self._file_combo.currentData()
        if not file_path:
            self._table.setRowCount(0)
            return

        # Find the timeline finding for this file
        timeline_finding = None
        for f in self._all_findings:
            if (f.analyzer == "ForensicsTimelineAnalyzer"
                    and "Timeline:" in f.title
                    and f.file == file_path):
                timeline_finding = f
                break

        if not timeline_finding:
            self._table.setRowCount(0)
            self._title_label.setText("No timeline data for selected file.")
            return

        # Collect anomaly findings for this file
        anomaly_fields: dict[str, str] = {}
        for f in self._all_findings:
            if f.analyzer == "ForensicsTimelineAnalyzer" and f.file == file_path:
                # Extract field name from detail if present
                for part in f.detail.split("|"):
                    part = part.strip()
                    if part.startswith("Field:"):
                        field = part[6:].strip()
                        anomaly_fields[field] = f.title

        # Parse the table from the finding's detail
        rows = self._parse_timeline_table(timeline_finding.detail)
        self._table.setRowCount(len(rows))

        for row_idx, row_data in enumerate(rows):
            source, field, raw_val, dt_str, anomaly = row_data
            items = [source, field, raw_val, dt_str, anomaly]
            for col_idx, text in enumerate(items):
                item = QTableWidgetItem(text)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                if anomaly or field in anomaly_fields:
                    item.setBackground(QColor("#fff3cd"))
                if "FUTURE" in anomaly.upper():
                    item.setBackground(QColor("#f8d7da"))
                self._table.setItem(row_idx, col_idx, item)

        self._title_label.setText(
            f"Timeline: {len(rows)} entries for {os.path.basename(file_path)}"
        )

    def _parse_timeline_table(self, detail: str) -> list[tuple[str, str, str, str, str]]:
        """Parse the pipe-delimited table from the timeline finding detail."""
        rows: list[tuple[str, str, str, str, str]] = []
        lines = detail.splitlines()
        for line in lines:
            if "|" not in line or line.startswith("-"):
                continue
            parts = [p.strip() for p in line.split("|")]
            if len(parts) < 4:
                continue
            # Skip header line
            if parts[0].lower() == "source":
                continue
            source = parts[0] if len(parts) > 0 else ""
            field = parts[1] if len(parts) > 1 else ""
            raw_val = parts[2] if len(parts) > 2 else ""
            dt_str = parts[3] if len(parts) > 3 else ""
            anomaly = parts[4] if len(parts) > 4 else ""
            rows.append((source, field, raw_val, dt_str, anomaly))
        return rows

    def _clear(self) -> None:
        self._table.setRowCount(0)
        self._file_combo.clear()
        self._title_label.setText("No timeline data available.")
