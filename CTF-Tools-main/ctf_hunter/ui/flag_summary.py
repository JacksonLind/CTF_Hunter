"""
Flag Summary tab: aggregates all flag_match=True findings across all files.
"""
from __future__ import annotations

from typing import List

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTreeWidget, QTreeWidgetItem,
    QPushButton, QLabel, QTextEdit, QTabWidget,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QColor

from core.report import Finding


class FlagSummaryTab(QWidget):
    def __init__(self, ai_client=None, parent=None):
        super().__init__(parent)
        self._ai_client = ai_client
        self._findings: List[Finding] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        header_row = QHBoxLayout()
        self._count_label = QLabel("No flag matches found.")
        self._count_label.setStyleSheet("font-weight: bold; font-size: 13px;")
        header_row.addWidget(self._count_label)
        header_row.addStretch()
        self._ask_ai_btn = QPushButton("🤖 Ask AI: Best Lead?")
        self._ask_ai_btn.setEnabled(False)
        self._ask_ai_btn.setToolTip("Set API key in Settings to enable AI analysis")
        self._ask_ai_btn.clicked.connect(self._ask_ai)
        header_row.addWidget(self._ask_ai_btn)
        layout.addLayout(header_row)

        self._tree = QTreeWidget()
        self._tree.setHeaderLabels(["File", "Analyzer", "Title", "Detail", "Confidence"])
        self._tree.setColumnWidth(0, 160)
        self._tree.setColumnWidth(1, 100)
        self._tree.setColumnWidth(2, 220)
        self._tree.setColumnWidth(3, 300)
        self._tree.setColumnWidth(4, 80)
        self._tree.setAlternatingRowColors(True)
        self._tree.itemSelectionChanged.connect(self._on_selection)
        layout.addWidget(self._tree, 1)

        # Detail / AI output in a tabbed widget
        self._detail_tabs = QTabWidget()
        self._detail_tabs.setMaximumHeight(200)

        self._detail_box = QTextEdit()
        self._detail_box.setReadOnly(True)
        self._detail_box.setPlaceholderText("Select a finding to see full detail...")
        self._detail_tabs.addTab(self._detail_box, "Details")

        self._ai_output = QTextEdit()
        self._ai_output.setReadOnly(True)
        self._ai_output.setPlaceholderText("AI holistic analysis output will appear here...")
        self._detail_tabs.addTab(self._ai_output, "🤖 AI Analysis")

        layout.addWidget(self._detail_tabs)

    def set_ai_client(self, ai_client) -> None:
        self._ai_client = ai_client
        self._ask_ai_btn.setEnabled(
            ai_client is not None and ai_client.available
        )
        if ai_client and ai_client.available:
            self._ask_ai_btn.setToolTip("Query Claude AI for the best lead across all findings")

    def refresh(self, all_findings: List[Finding]) -> None:
        self._findings = [f for f in all_findings if f.flag_match and not f.duplicate_of]
        self._tree.clear()
        for f in self._findings:
            item = QTreeWidgetItem([
                str(f.file)[-40:],
                f.analyzer,
                f.title,
                f.detail[:80],
                f"{f.confidence:.2f}",
            ])
            item.setForeground(0, QColor("darkred"))
            item.setFont(2, QFont("", -1, QFont.Weight.Bold))
            item.setData(0, Qt.ItemDataRole.UserRole, f)
            self._tree.addTopLevelItem(item)

        count = len(self._findings)
        self._count_label.setText(
            f"🚩 {count} flag match(es) found across all files"
            if count > 0 else "No flag matches found."
        )
        self._count_label.setStyleSheet(
            "font-weight: bold; font-size: 13px; color: darkred;"
            if count > 0 else "font-weight: bold; font-size: 13px;"
        )

    def _on_selection(self) -> None:
        items = self._tree.selectedItems()
        if not items:
            return
        f: Finding = items[0].data(0, Qt.ItemDataRole.UserRole)
        if f:
            self._detail_box.setPlainText(f.detail)

    def _ask_ai(self) -> None:
        if not self._ai_client or not self._ai_client.available:
            return
        summary_lines = []
        for f in self._findings:
            summary_lines.append(
                f"[{f.severity}] {f.file}: {f.title} — {f.detail[:200]}"
            )
        summary = "\n".join(summary_lines[:100])
        self._ai_output.setPlainText("Querying AI… please wait.")
        self._detail_tabs.setCurrentWidget(self._ai_output)
        response = self._ai_client.holistic_analysis(summary)
        self._ai_output.setPlainText(response or "No response from AI.")
