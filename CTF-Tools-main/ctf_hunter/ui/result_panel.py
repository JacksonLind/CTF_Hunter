"""
Result panel: findings tree (top-right) with severity badges, confidence scores,
flag-match highlighting, triage state filter/coloring, and per-file "Analyze with AI" button.
"""
from __future__ import annotations

from typing import List, Callable, Optional

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTreeWidget, QTreeWidgetItem,
    QPushButton, QLabel, QTextEdit, QMenu, QApplication, QInputDialog,
    QToolBar, QTabWidget,
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QColor, QAction

from core.report import Finding, TRIAGE_STATES
from ui.tool_suggester_panel import SuggestedToolsPanel

_SEVERITY_COLORS = {
    "HIGH":   ("#cc0000", "#ffeeee"),
    "MEDIUM": ("#886600", "#fffaee"),
    "LOW":    ("#004488", "#eeeeff"),
    "INFO":   ("#333333", "#f8f8f8"),
}

# Row background/foreground overrides by triage state
# (fg, bg, bold, strikethrough)
_TRIAGE_STYLE: dict[str, tuple[str, str, bool, bool]] = {
    "untriaged":      ("",        "",        False, False),
    "promising":      ("",        "#ddeeff", False, False),
    "investigating":  ("",        "#fffacc", False, False),
    "dead_end":       ("#888888", "#eeeeee", False, True),
    "confirmed_flag": ("#006600", "#ddffdd", True,  False),
}

_TRIAGE_LABELS: dict[str, str] = {
    "untriaged":      "❔ Untriaged",
    "promising":      "🔵 Promising",
    "investigating":  "🟡 Investigating",
    "dead_end":       "⬜ Dead End",
    "confirmed_flag": "🚩 Confirmed Flag",
}


class ResultPanel(QWidget):
    """Shows the findings tree and triggers hex viewer jumps."""

    finding_selected = pyqtSignal(object)   # emits Finding
    pin_finding_requested = pyqtSignal(object)  # emits Finding for Transform Pipeline
    triage_changed = pyqtSignal(object)     # emits Finding after triage update

    def __init__(self, ai_client=None, parent=None):
        super().__init__(parent)
        self._ai_client = ai_client
        self._current_file: str = ""
        self._findings: List[Finding] = []
        self._selected_finding: Optional[Finding] = None
        # Which triage states are currently visible (all by default)
        self._visible_states: set[str] = set(TRIAGE_STATES)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        # Header row
        hdr = QHBoxLayout()
        self._file_label = QLabel("No file selected")
        self._file_label.setStyleSheet("font-weight: bold;")
        hdr.addWidget(self._file_label)
        hdr.addStretch()

        self._ai_btn = QPushButton("🤖 Analyze with AI")
        self._ai_btn.setEnabled(False)
        self._ai_btn.setToolTip("Set API key in Settings to enable AI analysis")
        self._ai_btn.clicked.connect(self._analyze_with_ai)
        hdr.addWidget(self._ai_btn)
        layout.addLayout(hdr)

        # Triage filter toolbar — compact single-row toggle buttons
        filter_bar = QHBoxLayout()
        filter_bar.setSpacing(2)
        self._triage_btns: dict[str, QPushButton] = {}
        for state in TRIAGE_STATES:
            btn = QPushButton(_TRIAGE_LABELS[state])
            btn.setCheckable(True)
            btn.setChecked(True)
            btn.setFixedHeight(22)
            btn.setStyleSheet("font-size: 11px; padding: 1px 4px;")
            btn.clicked.connect(lambda checked, s=state: self._on_triage_filter(s, checked))
            self._triage_btns[state] = btn
            filter_bar.addWidget(btn)
        filter_bar.addStretch()
        # Triage summary label (inline with filter)
        self._triage_summary = QLabel("")
        self._triage_summary.setStyleSheet("font-size: 11px; color: #555;")
        filter_bar.addWidget(self._triage_summary)
        layout.addLayout(filter_bar)

        # Findings tree with context menu
        self._tree = QTreeWidget()
        self._tree.setHeaderLabels(["Severity", "Analyzer", "Title", "Confidence", "Offset", "Triage"])
        self._tree.setColumnWidth(0, 80)
        self._tree.setColumnWidth(1, 110)
        self._tree.setColumnWidth(2, 220)
        self._tree.setColumnWidth(3, 70)
        self._tree.setColumnWidth(4, 70)
        self._tree.setColumnWidth(5, 110)
        self._tree.setAlternatingRowColors(True)
        self._tree.itemSelectionChanged.connect(self._on_selection)
        self._tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._tree.customContextMenuRequested.connect(self._finding_context_menu)
        layout.addWidget(self._tree, 1)

        # Detail area: tabbed widget for Detail / AI Output / Suggested Tools
        self._detail_tabs = QTabWidget()
        self._detail_tabs.setMaximumHeight(200)

        # Detail tab
        detail_widget = QWidget()
        detail_layout = QVBoxLayout(detail_widget)
        detail_layout.setContentsMargins(0, 0, 0, 0)
        detail_layout.setSpacing(2)

        self._detail = QTextEdit()
        self._detail.setReadOnly(True)
        self._detail.setPlaceholderText("Select a finding to see details…")
        detail_layout.addWidget(self._detail)

        # Feedback buttons row
        feedback_bar = QHBoxLayout()
        feedback_bar.setSpacing(4)
        self._feedback_label = QLabel("Feedback:")
        self._feedback_label.setStyleSheet("font-size: 11px; color: #aaa;")
        feedback_bar.addWidget(self._feedback_label)

        self._thumbs_up_btn = QPushButton("👍 Correct")
        self._thumbs_up_btn.setFixedHeight(22)
        self._thumbs_up_btn.setStyleSheet("font-size: 11px; padding: 1px 6px;")
        self._thumbs_up_btn.setToolTip("Mark this finding as correct")
        self._thumbs_up_btn.setEnabled(False)
        self._thumbs_up_btn.clicked.connect(self._on_thumbs_up)
        feedback_bar.addWidget(self._thumbs_up_btn)

        self._thumbs_down_btn = QPushButton("👎 Incorrect")
        self._thumbs_down_btn.setFixedHeight(22)
        self._thumbs_down_btn.setStyleSheet("font-size: 11px; padding: 1px 6px;")
        self._thumbs_down_btn.setToolTip("Mark this finding as incorrect")
        self._thumbs_down_btn.setEnabled(False)
        self._thumbs_down_btn.clicked.connect(self._on_thumbs_down)
        feedback_bar.addWidget(self._thumbs_down_btn)

        self._feedback_status = QLabel("")
        self._feedback_status.setStyleSheet("font-size: 11px; color: #aaa;")
        feedback_bar.addWidget(self._feedback_status)
        feedback_bar.addStretch()
        detail_layout.addLayout(feedback_bar)

        self._detail_tabs.addTab(detail_widget, "Details")

        # AI output tab
        self._ai_output = QTextEdit()
        self._ai_output.setReadOnly(True)
        self._ai_output.setPlaceholderText("AI analysis output will appear here…")
        self._detail_tabs.addTab(self._ai_output, "🤖 AI")

        # Suggested Tools tab
        self._tool_suggester = SuggestedToolsPanel()
        self._detail_tabs.addTab(self._tool_suggester, "🛠 Tools")

        layout.addWidget(self._detail_tabs)

    def set_ai_client(self, ai_client) -> None:
        self._ai_client = ai_client
        enabled = ai_client is not None and ai_client.available
        self._ai_btn.setEnabled(enabled)
        if enabled:
            self._ai_btn.setToolTip("Query Claude AI for analysis of this file's findings")

    def show_findings(self, file_path: str, findings: List[Finding]) -> None:
        self._current_file = file_path
        self._findings = findings
        self._file_label.setText(f"Findings for: {file_path}")
        self._rebuild_tree()
        self._detail.clear()
        self._ai_output.clear()
        self._tool_suggester.refresh(findings)

    def _rebuild_tree(self) -> None:
        """Re-populate the tree respecting the current triage filter."""
        self._tree.clear()
        for f in sorted(self._findings, key=lambda x: (-x.confidence, x.severity)):
            if f.duplicate_of:
                continue  # skip duplicates
            if f.triage not in self._visible_states:
                continue
            self._add_tree_item(f)
        self._update_triage_summary()

    def _add_tree_item(self, f: Finding) -> QTreeWidgetItem:
        sev_fg, sev_bg = _SEVERITY_COLORS.get(f.severity, ("#000", "#fff"))
        badge = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "🟢"}.get(f.severity, "")
        triage_label = _TRIAGE_LABELS.get(f.triage, f.triage)

        item = QTreeWidgetItem([
            f"{badge} {f.severity}",
            f.analyzer,
            f.title,
            f"{f.confidence:.2f}",
            f"0x{f.offset:x}" if f.offset >= 0 else "-",
            triage_label,
        ])
        item.setForeground(0, QColor(sev_fg))
        item.setBackground(0, QColor(sev_bg))

        # Triage coloring
        tri_fg, tri_bg, tri_bold, tri_strike = _TRIAGE_STYLE.get(
            f.triage, ("", "", False, False)
        )
        for col in range(6):
            if tri_bg:
                item.setBackground(col, QColor(tri_bg))
            if tri_fg:
                item.setForeground(col, QColor(tri_fg))

        # Combine triage + flag_match font styling
        title_font = QFont()
        if tri_bold or f.flag_match:
            title_font.setBold(True)
        if tri_strike:
            title_font.setStrikeOut(True)
        if tri_bold or tri_strike or f.flag_match:
            item.setFont(2, title_font)

        if f.flag_match:
            item.setForeground(2, QColor("darkred"))

        item.setData(0, Qt.ItemDataRole.UserRole, f)
        self._tree.addTopLevelItem(item)
        return item

    def _update_triage_summary(self) -> None:
        counts: dict[str, int] = {s: 0 for s in TRIAGE_STATES}
        for f in self._findings:
            if not f.duplicate_of:
                counts[f.triage] = counts.get(f.triage, 0) + 1
        parts = []
        if counts["confirmed_flag"]:
            parts.append(f"{counts['confirmed_flag']} confirmed")
        if counts["promising"]:
            parts.append(f"{counts['promising']} promising")
        if counts["investigating"]:
            parts.append(f"{counts['investigating']} investigating")
        if counts["dead_end"]:
            parts.append(f"{counts['dead_end']} dead ends")
        if counts["untriaged"]:
            parts.append(f"{counts['untriaged']} untriaged")
        self._triage_summary.setText(" | ".join(parts))

    def _on_triage_filter(self, state: str, checked: bool) -> None:
        if checked:
            self._visible_states.add(state)
        else:
            self._visible_states.discard(state)
        self._rebuild_tree()

    def _on_selection(self) -> None:
        items = self._tree.selectedItems()
        if not items:
            return
        f: Finding = items[0].data(0, Qt.ItemDataRole.UserRole)
        if f:
            detail = f.detail
            if f.triage_note:
                detail = f"[Triage note: {f.triage_note}]\n\n{detail}"
            self._detail.setPlainText(detail)
            self._selected_finding = f
            self._thumbs_up_btn.setEnabled(True)
            self._thumbs_down_btn.setEnabled(True)
            self._feedback_status.setText("")
            self.finding_selected.emit(f)

    def _finding_context_menu(self, pos) -> None:
        item = self._tree.itemAt(pos)
        if not item:
            return
        f: Optional[Finding] = item.data(0, Qt.ItemDataRole.UserRole)
        if not f:
            return
        menu = QMenu(self)
        copy_act = menu.addAction("📋 Copy detail")
        pin_act = menu.addAction("📌 Pin to Transform Pipeline")
        menu.addSeparator()

        # Triage sub-menu
        triage_menu = menu.addMenu("🏷 Set Triage")
        triage_actions: dict[QAction, str] = {}
        for state in TRIAGE_STATES:
            act = triage_menu.addAction(_TRIAGE_LABELS[state])
            if f.triage == state:
                act.setEnabled(False)  # already set
            triage_actions[act] = state

        note_act = menu.addAction("✏️ Edit Triage Note…")

        action = menu.exec(self._tree.mapToGlobal(pos))
        if action == copy_act:
            QApplication.clipboard().setText(f.detail)
        elif action == pin_act:
            self.pin_finding_requested.emit(f)
        elif action == note_act:
            self._edit_triage_note(f, item)
        elif action in triage_actions:
            self._set_triage(f, triage_actions[action], item)

    def _set_triage(self, f: Finding, state: str, item: QTreeWidgetItem) -> None:
        f.triage = state
        # Rebuild or hide the item if the new state is filtered out
        if state not in self._visible_states:
            idx = self._tree.indexOfTopLevelItem(item)
            if idx >= 0:
                self._tree.takeTopLevelItem(idx)
        else:
            # Refresh the row label and styling
            triage_label = _TRIAGE_LABELS.get(state, state)
            item.setText(5, triage_label)
            tri_fg, tri_bg, tri_bold, tri_strike = _TRIAGE_STYLE.get(state, ("", "", False, False))
            for col in range(6):
                if tri_bg:
                    item.setBackground(col, QColor(tri_bg))
                else:
                    item.setBackground(col, QColor())
                if tri_fg:
                    item.setForeground(col, QColor(tri_fg))
            title_font = QFont()
            # Preserve flag_match bold when re-styling after a triage change
            finding = item.data(0, Qt.ItemDataRole.UserRole)
            if tri_bold or (finding and finding.flag_match):
                title_font.setBold(True)
            if tri_strike:
                title_font.setStrikeOut(True)
            item.setFont(2, title_font)
        self._update_triage_summary()
        self.triage_changed.emit(f)

    def _edit_triage_note(self, f: Finding, item: QTreeWidgetItem) -> None:
        text, ok = QInputDialog.getText(
            self, "Triage Note",
            f"Annotation for: {f.title}",
            text=f.triage_note,
        )
        if ok:
            f.triage_note = text
            self.triage_changed.emit(f)

    def _on_thumbs_up(self) -> None:
        self._record_feedback(was_correct=True)

    def _on_thumbs_down(self) -> None:
        self._record_feedback(was_correct=False)

    def _record_feedback(self, was_correct: bool) -> None:
        f = self._selected_finding
        if f is None:
            return
        try:
            from core.feedback import FeedbackStore
            store = FeedbackStore()
            store.record_finding(f, was_correct=was_correct)
            label = "✅ Marked correct" if was_correct else "❌ Marked incorrect"
            self._feedback_status.setText(label)
        except Exception as exc:
            self._feedback_status.setText(f"Error: {exc}")

    def _analyze_with_ai(self) -> None:
        if not self._ai_client or not self._ai_client.available:
            return
        visible = [f for f in self._findings if not f.duplicate_of]
        summary = "\n".join(
            f"[{f.severity}] {f.analyzer}: {f.title} — {f.detail[:150]}"
            for f in visible[:30]
        )
        # Build hex context around highest-confidence finding
        best = max(visible, key=lambda f: f.confidence, default=None)
        hex_ctx = ""
        if best and best.offset >= 0:
            try:
                with open(self._current_file, "rb") as fh:
                    fh.seek(max(0, best.offset))
                    raw = fh.read(256)
                hex_ctx = " ".join(f"{b:02x}" for b in raw)
            except Exception:
                pass

        self._ai_output.setPlainText("Querying AI… please wait.")
        self._detail_tabs.setCurrentWidget(self._ai_output)
        response = self._ai_client.analyze_findings(self._current_file, summary, hex_ctx)
        self._ai_output.setPlainText(response or "No response from AI.")

