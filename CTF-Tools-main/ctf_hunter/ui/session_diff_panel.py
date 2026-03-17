"""
Session diff panel: dockable widget that shows the result of comparing two
CTF Hunter sessions side-by-side.

New findings are highlighted green, removed findings in red with strikethrough,
modified findings in yellow with an expandable before/after detail view.
Unchanged findings are hidden by default with a toggle to show them.
"""
from __future__ import annotations

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTreeWidget, QTreeWidgetItem,
    QPushButton, QLabel, QCheckBox, QTextEdit, QSplitter,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont

from core.session_diff import SessionDiff, DiffEntry


# Colours used for diff rows
_GREEN  = QColor("#ccffcc")
_RED    = QColor("#ffcccc")
_YELLOW = QColor("#fffacc")
_GREY   = QColor("#f0f0f0")

_STRIKE_FG = QColor("#888888")


class SessionDiffPanel(QWidget):
    """Shows a SessionDiff in a dockable panel."""

    def __init__(self, diff: SessionDiff, label_a: str = "Session A",
                 label_b: str = "Session B", parent=None):
        super().__init__(parent)
        self._diff = diff
        self._show_unchanged = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)

        # Summary header
        summary = (
            f"🆕 {len(diff.new)} new  |  "
            f"🗑 {len(diff.removed)} removed  |  "
            f"✏️ {len(diff.modified)} modified  |  "
            f"✅ {len(diff.unchanged)} unchanged"
        )
        hdr = QLabel(summary)
        hdr.setStyleSheet("font-weight: bold; padding: 4px;")
        layout.addWidget(hdr)

        sub_hdr = QLabel(f"Comparing  A: {label_a}  →  B: {label_b}")
        sub_hdr.setStyleSheet("color: #555; font-size: 11px; padding: 2px 4px;")
        layout.addWidget(sub_hdr)

        # Toolbar
        toolbar = QHBoxLayout()
        self._unchanged_chk = QCheckBox("Show unchanged")
        self._unchanged_chk.setChecked(False)
        self._unchanged_chk.toggled.connect(self._toggle_unchanged)
        toolbar.addWidget(self._unchanged_chk)
        toolbar.addStretch()
        layout.addLayout(toolbar)

        # Splitter: tree on top, detail on bottom
        splitter = QSplitter(Qt.Orientation.Vertical)

        self._tree = QTreeWidget()
        self._tree.setHeaderLabels(["Status", "Severity", "Analyzer", "Title", "Offset"])
        self._tree.setColumnWidth(0, 90)
        self._tree.setColumnWidth(1, 70)
        self._tree.setColumnWidth(2, 110)
        self._tree.setColumnWidth(3, 240)
        self._tree.setColumnWidth(4, 70)
        self._tree.itemSelectionChanged.connect(self._on_selection)
        splitter.addWidget(self._tree)

        # Detail / diff area
        detail_widget = QWidget()
        detail_layout = QVBoxLayout(detail_widget)
        detail_layout.setContentsMargins(0, 0, 0, 0)
        self._detail_label = QLabel("Select a finding to see details")
        self._detail_label.setStyleSheet("font-weight: bold; padding: 2px 4px;")
        detail_layout.addWidget(self._detail_label)

        diff_split = QSplitter(Qt.Orientation.Horizontal)
        self._before_edit = QTextEdit()
        self._before_edit.setReadOnly(True)
        self._before_edit.setPlaceholderText("Before (Session A)…")
        self._after_edit = QTextEdit()
        self._after_edit.setReadOnly(True)
        self._after_edit.setPlaceholderText("After (Session B)…")
        diff_split.addWidget(self._before_edit)
        diff_split.addWidget(self._after_edit)
        detail_layout.addWidget(diff_split)
        splitter.addWidget(detail_widget)

        splitter.setSizes([400, 200])
        layout.addWidget(splitter)

        self._populate()

    # ------------------------------------------------------------------

    def _populate(self) -> None:
        self._tree.clear()
        for entry in self._diff.new:
            self._add_row(entry)
        for entry in self._diff.removed:
            self._add_row(entry)
        for entry in self._diff.modified:
            self._add_row(entry)
        if self._show_unchanged:
            for entry in self._diff.unchanged:
                self._add_row(entry)

    def _add_row(self, entry: DiffEntry) -> None:
        f = entry.finding
        status_map = {
            "new":       "🆕 New",
            "removed":   "🗑 Removed",
            "modified":  "✏️ Modified",
            "unchanged": "✅ Unchanged",
        }
        status = status_map.get(entry.category, entry.category)
        offset_str = f"0x{f.offset:x}" if f.offset >= 0 else "-"

        item = QTreeWidgetItem([status, f.severity, f.analyzer, f.title, offset_str])

        if entry.category == "new":
            for col in range(5):
                item.setBackground(col, _GREEN)
        elif entry.category == "removed":
            for col in range(5):
                item.setBackground(col, _RED)
            strike_font = QFont()
            strike_font.setStrikeOut(True)
            item.setFont(3, strike_font)
            item.setForeground(3, _STRIKE_FG)
        elif entry.category == "modified":
            for col in range(5):
                item.setBackground(col, _YELLOW)
        elif entry.category == "unchanged":
            for col in range(5):
                item.setBackground(col, _GREY)

        item.setData(0, Qt.ItemDataRole.UserRole, entry)
        self._tree.addTopLevelItem(item)

    def _toggle_unchanged(self, checked: bool) -> None:
        self._show_unchanged = checked
        self._populate()

    def _on_selection(self) -> None:
        items = self._tree.selectedItems()
        if not items:
            return
        entry: DiffEntry = items[0].data(0, Qt.ItemDataRole.UserRole)
        if entry is None:
            return

        f = entry.finding
        self._detail_label.setText(f"[{entry.category.upper()}] {f.title}")

        if entry.category == "modified":
            self._before_edit.setPlainText(entry.old_detail)
            self._after_edit.setPlainText(entry.new_detail)
        elif entry.category == "removed":
            self._before_edit.setPlainText(f.detail)
            self._after_edit.clear()
        elif entry.category == "new":
            self._before_edit.clear()
            self._after_edit.setPlainText(f.detail)
        else:
            self._before_edit.setPlainText(f.detail)
            self._after_edit.setPlainText(f.detail)
