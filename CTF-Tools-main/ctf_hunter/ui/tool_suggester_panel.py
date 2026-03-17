"""
Suggested Tools panel: lists external CTF tools recommended based on current
findings, with install commands and pre-filled usage examples.

Tools already detected as installed are shown with a green checkmark (✔).
"""
from __future__ import annotations

from typing import List

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QTreeWidget, QTreeWidgetItem,
    QAbstractItemView,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont

from core.report import Finding
from core.tool_suggester import suggest_tools


class SuggestedToolsPanel(QWidget):
    """Displays tool suggestions derived from the current file's findings."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)

        hdr = QLabel("🛠 Suggested Tools")
        hdr.setStyleSheet("font-weight: bold; padding: 2px 4px;")
        layout.addWidget(hdr)

        self._tree = QTreeWidget()
        self._tree.setHeaderLabels(["Tool", "Why Suggested", "Install / Get", "Usage Example"])
        self._tree.setColumnWidth(0, 160)
        self._tree.setColumnWidth(1, 220)
        self._tree.setColumnWidth(2, 200)
        self._tree.setColumnWidth(3, 340)
        self._tree.setAlternatingRowColors(True)
        self._tree.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._tree.setToolTip(
            "Tools recommended based on findings.  "
            "✔ = already installed on this system."
        )
        layout.addWidget(self._tree)

        self._placeholder = QLabel(
            "No tool suggestions yet — run an analysis to populate this panel."
        )
        self._placeholder.setStyleSheet("color: #888; padding: 4px;")
        self._placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._placeholder)
        self._placeholder.setVisible(True)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def refresh(self, findings: List[Finding]) -> None:
        """Recompute and display tool suggestions for *findings*."""
        self._tree.clear()
        suggestions = suggest_tools(findings)

        if not suggestions:
            self._tree.setVisible(False)
            self._placeholder.setVisible(True)
            return

        self._tree.setVisible(True)
        self._placeholder.setVisible(False)

        for s in suggestions:
            installed = s["installed"]
            check = "✔ " if installed else ""
            tool_label = f"{check}{s['tool_name']}"

            item = QTreeWidgetItem([
                tool_label,
                s["reason"],
                s["install_cmd"],
                s["usage_example"],
            ])

            # Color the tool-name cell: green if installed, blue otherwise
            if installed:
                item.setForeground(0, QColor("#007700"))
                bold = QFont()
                bold.setBold(True)
                item.setFont(0, bold)
            else:
                item.setForeground(0, QColor("#004488"))

            # Store metadata for tooltip
            tooltip = (
                f"Tool: {s['tool_name']}\n"
                f"URL: {s['url']}\n"
                f"Triggered by finding: {s['finding_title']}"
            )
            for col in range(4):
                item.setToolTip(col, tooltip)

            # Store the full suggestion dict so callers can inspect it
            item.setData(0, Qt.ItemDataRole.UserRole, s)
            self._tree.addTopLevelItem(item)
