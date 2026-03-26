"""
Main application window for CTF Hunter.
3-panel layout: file list (left), findings tree (top-right), hex viewer (bottom-right).
Toolbar: Analyze All, Fast/Deep toggle, flag format selector, tool status dots,
         Save/Load Session, Watchfolder toggle, Export button.
Tabs: Main view | Flag Summary | Steg Viewer.
"""
from __future__ import annotations

import csv
import os
import re
import sys
import html
from pathlib import Path
from typing import List, Dict, Optional

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QListWidget, QListWidgetItem, QLabel, QProgressBar, QToolBar,
    QComboBox, QPushButton, QCheckBox, QMenu, QTabWidget,
    QFileDialog, QMessageBox, QTextEdit, QApplication, QLineEdit,
    QDialog, QInputDialog, QDockWidget,
)
from PyQt6.QtCore import (
    Qt, QThreadPool, QRunnable, QObject, pyqtSignal, pyqtSlot, QTimer,
)
from PyQt6.QtGui import QAction, QColor, QFont, QDragEnterEvent, QDropEvent

from core.report import Finding, Session
from core.dispatcher import dispatch
from core.ai_client import AIClient
from core.external import probe_tools, is_available
from core.watchfolder import WatchfolderManager
from ui.result_panel import ResultPanel
from ui.hex_viewer import HexViewer
from ui.diff_view import DiffViewWindow
from ui.flag_summary import FlagSummaryTab
from ui.steg_viewer import StegViewerTab
from ui.file_intel import FileIntelTab
from ui.challenge_panel import ChallengePanelTab
from ui.settings_dialog import SettingsDialog, load_config
from ui.session import save_session_dialog, load_session_dialog
from ui.network_console import NetworkConsoleTab
from ui.timeline_tab import TimelineTab
from ui.transform_pipeline import make_transform_pipeline_dock, TransformPipelinePanel
from ui.attack_plan_tab import AttackPlanTab
from ui.attack_chains_tab import AttackChainsTab
from ui.help_tab import HelpTab
from ui.investigate_tab import InvestigateTab

# ---------------------------------------------------------------------------
# Worker signals / runnable
# ---------------------------------------------------------------------------

class _WorkerSignals(QObject):
    finished = pyqtSignal(str, list)   # (path, findings)
    error = pyqtSignal(str, str)       # (path, error_msg)
    progress = pyqtSignal(str, int)    # (path, percent)


class _AnalyzeWorker(QRunnable):
    def __init__(
        self,
        path: str,
        flag_pattern: re.Pattern,
        depth: str,
        ai_client: Optional[AIClient],
    ):
        super().__init__()
        self.path = path
        self.flag_pattern = flag_pattern
        self.depth = depth
        self.ai_client = ai_client
        self.signals = _WorkerSignals()

    @pyqtSlot()
    def run(self):
        try:
            self.signals.progress.emit(self.path, 10)
            findings = dispatch(self.path, self.flag_pattern, self.depth, self.ai_client)
            self.signals.progress.emit(self.path, 100)
            self.signals.finished.emit(self.path, findings)
        except Exception as exc:
            self.signals.error.emit(self.path, str(exc))

# ---------------------------------------------------------------------------
# Flag format presets
# ---------------------------------------------------------------------------

_FLAG_PRESETS: dict[str, str] = {
    "CTF{...}":       r"CTF\{[^}]+\}",
    "flag{...}":      r"flag\{[^}]+\}",
    "HTB{...}":       r"HTB\{[^}]+\}",
    "picoCTF{...}":   r"picoCTF\{[^}]+\}",
    "DUCTF{...}":     r"DUCTF\{[^}]+\}",
    "Custom…":        r"",
}

# ---------------------------------------------------------------------------
# Main Window
# ---------------------------------------------------------------------------

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CTF Hunter — Anomaly Detector")
        self.resize(1400, 900)
        self.setAcceptDrops(True)

        # State
        self._session = Session()
        self._findings_by_file: Dict[str, List[Finding]] = {}
        self._notes_by_file: Dict[str, str] = {}
        self._progress_by_file: Dict[str, QProgressBar] = {}
        self._thread_pool = QThreadPool()
        self._thread_pool.setMaxThreadCount(4)
        self._watchfolder = WatchfolderManager(self)
        self._watchfolder.file_detected.connect(self._on_watchfolder_file)
        self._watchfolder.file_skipped.connect(self._on_watchfolder_skip)
        self._watchfolder_active = False
        self._diff_first_file: Optional[str] = None
        self._frida_timeout_seconds: int = 10

        # AI / config
        cfg = load_config()
        self._ai_client = AIClient(api_key=cfg.get("api_key", ""))

        # Probe external tools
        probe_tools()

        # Build UI
        self._build_toolbar()
        self._build_central()
        self._build_transform_pipeline_dock()
        self._build_session_diff_dock()
        self._build_frida_results_dock()
        self._build_menu_bar()

        # Update tool dots
        self._update_tool_status()

    # ------------------------------------------------------------------
    # Toolbar
    # ------------------------------------------------------------------

    def _build_toolbar(self) -> None:
        tb = QToolBar("Main Toolbar")
        tb.setMovable(False)
        self.addToolBar(tb)

        # Analyze All
        act_analyze = QAction("▶ Analyze All", self)
        act_analyze.setToolTip("Analyze all loaded files")
        act_analyze.triggered.connect(self._analyze_all)
        tb.addAction(act_analyze)

        tb.addSeparator()

        # Fast / Deep / Auto toggle
        tb.addWidget(QLabel(" Mode:"))
        self._depth_combo = QComboBox()
        self._depth_combo.addItems(["Fast", "Deep", "Auto"])
        self._depth_combo.setToolTip(
            "Fast: quick analysis\n"
            "Deep: full LSB, disasm, XOR, PCAP streams\n"
            "Auto: fast first, then deep for high-confidence regions"
        )
        tb.addWidget(self._depth_combo)

        # Flag format selector
        tb.addWidget(QLabel(" Flag:"))
        self._flag_combo = QComboBox()
        self._flag_combo.addItems(list(_FLAG_PRESETS.keys()))
        self._flag_combo.currentTextChanged.connect(self._on_flag_preset_changed)
        tb.addWidget(self._flag_combo)

        tb.addSeparator()

        # Session actions grouped into a single dropdown menu button
        session_btn = QPushButton("💾 Session")
        session_menu = QMenu(session_btn)
        session_menu.addAction("💾 Save Session", self._save_session)
        session_menu.addAction("📂 Load Session", self._load_session)
        session_menu.addAction("🔀 Compare Session…", self._compare_session)
        session_btn.setMenu(session_menu)
        tb.addWidget(session_btn)

        # Export
        export_btn = QPushButton("📤 Export")
        export_menu = QMenu(export_btn)
        export_menu.addAction("Markdown", lambda: self._export("markdown"))
        export_menu.addAction("CSV", lambda: self._export("csv"))
        export_menu.addAction("HTML", lambda: self._export("html"))
        export_btn.setMenu(export_menu)
        tb.addWidget(export_btn)

        tb.addSeparator()

        # Watchfolder toggle
        self._watchfolder_btn = QPushButton("📁 Watch")
        self._watchfolder_btn.setCheckable(True)
        self._watchfolder_btn.setToolTip("Monitor a folder for new files")
        self._watchfolder_btn.toggled.connect(self._toggle_watchfolder)
        tb.addWidget(self._watchfolder_btn)

        # Dynamic Analysis (Frida) — moved from main tab body to toolbar
        self._frida_btn = QPushButton("🔬 Dynamic")
        self._frida_btn.setToolTip(
            "Run Frida-based runtime instrumentation on the selected binary.\n"
            "Requires frida (pip install frida frida-tools)."
        )
        self._frida_btn.clicked.connect(self._run_dynamic_analysis)
        tb.addWidget(self._frida_btn)

        tb.addSeparator()

        # Settings
        act_settings = QAction("⚙ Settings", self)
        act_settings.triggered.connect(self._open_settings)
        tb.addAction(act_settings)

        # Transform Pipeline toggle — kept as a toolbar action for quick access
        self._pipeline_toggle_action = QAction("🔧 Pipeline", self)
        self._pipeline_toggle_action.setCheckable(True)
        self._pipeline_toggle_action.setChecked(True)
        self._pipeline_toggle_action.setToolTip("Toggle Transform Pipeline panel")
        self._pipeline_toggle_action.triggered.connect(self._toggle_transform_pipeline)
        tb.addAction(self._pipeline_toggle_action)

        # Tool status dots — shown in status bar instead of toolbar
        self._tool_dots: dict[str, QLabel] = {}
        status_bar = self.statusBar()
        for tool in ("exiftool", "binwalk", "strings", "file", "tshark"):
            dot = QLabel(f"● {tool}")
            dot.setFont(QFont("", 9))
            self._tool_dots[tool] = dot
            status_bar.addPermanentWidget(dot)

    # ------------------------------------------------------------------
    # Central widget
    # ------------------------------------------------------------------

    def _build_central(self) -> None:
        tabs = QTabWidget()

        # --- Tab 1: Main ---
        main_tab = QWidget()
        main_layout = QVBoxLayout(main_tab)
        main_layout.setContentsMargins(4, 4, 4, 4)
        main_layout.setSpacing(0)

        splitter_h = QSplitter(Qt.Orientation.Horizontal)

        # Left panel: file list
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(4, 4, 4, 4)
        left_layout.setSpacing(4)

        left_hdr = QHBoxLayout()
        left_hdr.addWidget(QLabel("<b>Files</b>"))
        left_hdr.addStretch()
        add_btn = QPushButton("+")
        add_btn.setFixedWidth(28)
        add_btn.setToolTip("Add files")
        add_btn.clicked.connect(self._add_files)
        left_hdr.addWidget(add_btn)
        add_folder_btn = QPushButton("📂")
        add_folder_btn.setFixedWidth(32)
        add_folder_btn.setToolTip("Add folder (recursively)")
        add_folder_btn.clicked.connect(self._add_folder)
        left_hdr.addWidget(add_folder_btn)
        clear_btn = QPushButton("✕")
        clear_btn.setFixedWidth(28)
        clear_btn.setToolTip("Clear all files")
        clear_btn.clicked.connect(self._clear_files)
        left_hdr.addWidget(clear_btn)
        left_layout.addLayout(left_hdr)

        self._file_list = QListWidget()
        self._file_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._file_list.customContextMenuRequested.connect(self._file_context_menu)
        self._file_list.currentItemChanged.connect(self._on_file_selected)
        left_layout.addWidget(self._file_list, 1)

        # Correlate All button
        correlate_btn = QPushButton("🔗 Correlate All")
        correlate_btn.setToolTip("Cross-correlate findings across all loaded files")
        correlate_btn.clicked.connect(self._correlate_all_files)
        left_layout.addWidget(correlate_btn)

        # Notes field — collapsible
        self._notes_toggle = QPushButton("▶ Notes")
        self._notes_toggle.setFlat(True)
        self._notes_toggle.setStyleSheet("text-align: left; font-weight: bold; padding: 2px;")
        self._notes_toggle.clicked.connect(self._toggle_notes)
        left_layout.addWidget(self._notes_toggle)
        self._notes_edit = QTextEdit()
        self._notes_edit.setMaximumHeight(90)
        self._notes_edit.setPlaceholderText("Per-file notes…")
        self._notes_edit.textChanged.connect(self._on_notes_changed)
        self._notes_edit.hide()
        left_layout.addWidget(self._notes_edit)

        left.setMinimumWidth(200)
        splitter_h.addWidget(left)

        # Right panels
        splitter_v = QSplitter(Qt.Orientation.Vertical)

        self._result_panel = ResultPanel(ai_client=self._ai_client)
        self._result_panel.set_ai_client(self._ai_client)
        self._result_panel.finding_selected.connect(self._on_finding_selected)
        self._result_panel.pin_finding_requested.connect(self._on_pin_finding)
        splitter_v.addWidget(self._result_panel)

        self._hex_viewer = HexViewer()
        splitter_v.addWidget(self._hex_viewer)

        splitter_v.setSizes([500, 300])
        splitter_h.addWidget(splitter_v)
        splitter_h.setSizes([220, 980])

        main_layout.addWidget(splitter_h)

        tabs.addTab(main_tab, "📋 Analysis")

        # --- Tab 2: Flag Summary ---
        self._flag_summary = FlagSummaryTab(ai_client=self._ai_client)
        tabs.addTab(self._flag_summary, "🚩 Flags")

        # --- Tab 3: Steg Viewer ---
        self._steg_viewer = StegViewerTab()
        tabs.addTab(self._steg_viewer, "🔬 Steg")

        # --- Tab 4: File Intel ---
        self._file_intel = FileIntelTab()
        tabs.addTab(self._file_intel, "🔑 Intel")

        # --- Tab 5: Challenge ---
        self._challenge_panel = ChallengePanelTab(ai_client=self._ai_client)
        tabs.addTab(self._challenge_panel, "🎯 Challenge")

        # --- Tab 6: Network ---
        self._network_console = NetworkConsoleTab(session=self._session)
        self._network_console.flag_detected.connect(self._on_network_flag_detected)
        tabs.addTab(self._network_console, "🌐 Network")

        # --- Tab 7: Attack Plan ---
        self._attack_plan = AttackPlanTab(ai_client=self._ai_client)
        tabs.addTab(self._attack_plan, "⚔️ Attack")

        # --- Tab 8: Attack Chains ---
        self._attack_chains = AttackChainsTab()
        self._attack_chains.run_chain_requested.connect(self._on_run_chain)
        tabs.addTab(self._attack_chains, "⛓️ Chains")

        # --- Tab 9: Timeline ---
        self._timeline_tab = TimelineTab()
        tabs.addTab(self._timeline_tab, "🕒 Timeline")

        # --- Tab 10: Investigate ---
        self._investigate_tab = InvestigateTab()
        self._investigate_tab.pin_finding_requested.connect(self._on_pin_finding)
        tabs.addTab(self._investigate_tab, "🧭 Investigate")

        # --- Tab 11: Help ---
        self._help_tab = HelpTab()
        tabs.addTab(self._help_tab, "❓ Help")

        self.setCentralWidget(tabs)
        self._tabs = tabs

    # ------------------------------------------------------------------
    # File management
    # ------------------------------------------------------------------

    def _add_files(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(
            self, "Add Files", "", "All Files (*)"
        )
        for p in paths:
            self._add_file(p)

    def _add_folder(self) -> None:
        directory = QFileDialog.getExistingDirectory(self, "Add Folder")
        if not directory:
            return
        self._add_directory_files(directory)

    def _add_directory_files(self, directory: str) -> None:
        """Recursively add all files found under *directory*."""
        for file_path in Path(directory).rglob("*"):
            if file_path.is_file():
                self._add_file(str(file_path))

    def _add_file(self, path: str) -> None:
        if path in self._session.files:
            return
        self._session.files.append(path)

        # Badge
        badge = self._severity_badge_for_file(path)
        item = QListWidgetItem(f"{badge} {Path(path).name}")
        item.setData(Qt.ItemDataRole.UserRole, path)
        item.setToolTip(path)

        # Progress bar widget
        container = QWidget()
        row = QHBoxLayout(container)
        row.setContentsMargins(2, 0, 2, 0)
        lbl = QLabel(f"{badge} {Path(path).name}")
        lbl.setToolTip(path)
        row.addWidget(lbl)
        pb = QProgressBar()
        pb.setRange(0, 100)
        pb.setValue(0)
        pb.setFixedWidth(80)
        pb.setFixedHeight(14)
        pb.setTextVisible(False)
        row.addWidget(pb)
        self._progress_by_file[path] = pb

        self._file_list.addItem(item)
        self._file_list.setItemWidget(item, container)

    def _clear_files(self) -> None:
        self._session.files.clear()
        self._findings_by_file.clear()
        self._progress_by_file.clear()
        self._file_list.clear()
        self._diff_first_file = None  # reset pending diff selection
        self._result_panel.show_findings("", [])
        self._hex_viewer.load_bytes(b"", "")
        self._flag_summary.refresh([])
        self._challenge_panel.update_findings([])
        self._timeline_tab.refresh([])

    def _severity_badge_for_file(self, path: str) -> str:
        findings = self._findings_by_file.get(path, [])
        if any(f.severity == "HIGH" for f in findings):
            return "🔴"
        if any(f.severity == "MEDIUM" for f in findings):
            return "🟡"
        return "🟢"

    def _file_context_menu(self, pos) -> None:
        item = self._file_list.itemAt(pos)
        if not item:
            return
        path = item.data(Qt.ItemDataRole.UserRole)
        menu = QMenu(self)
        analyze_act = menu.addAction("Analyze This File")
        if self._diff_first_file is None:
            diff_act = menu.addAction("Diff with…  (set as File A)")
            cancel_diff_act = None
        else:
            diff_act = menu.addAction(f"Diff with '{Path(self._diff_first_file).name}'")
            cancel_diff_act = menu.addAction("Cancel Diff")
        steg_act = menu.addAction("Open in Steg Viewer")
        remove_act = menu.addAction("Remove")

        action = menu.exec(self._file_list.mapToGlobal(pos))
        if action == analyze_act:
            self._analyze_file(path)
        elif action == diff_act:
            if self._diff_first_file is None:
                self._diff_first_file = path
                QMessageBox.information(
                    self, "Diff",
                    f"File A set: {path}\nRight-click another file and choose 'Diff with…' to compare."
                )
            else:
                dlg = DiffViewWindow(self._diff_first_file, path, self)
                dlg.exec()
                self._diff_first_file = None
        elif cancel_diff_act and action == cancel_diff_act:
            self._diff_first_file = None
        elif action == steg_act:
            self._steg_viewer.load_image(path)
            self._tabs.setCurrentIndex(2)
        elif action == remove_act:
            row = self._file_list.row(item)
            self._file_list.takeItem(row)
            if path in self._session.files:
                self._session.files.remove(path)
            self._findings_by_file.pop(path, None)
            self._progress_by_file.pop(path, None)
            # Clear diff state if the removed file was the diff selection
            if self._diff_first_file == path:
                self._diff_first_file = None

    def _on_file_selected(self, current, previous) -> None:
        if previous and previous.data(Qt.ItemDataRole.UserRole):
            old_path = previous.data(Qt.ItemDataRole.UserRole)
            self._notes_by_file[old_path] = self._notes_edit.toPlainText()
            self._session.notes[old_path] = self._notes_by_file[old_path]

        if not current:
            return
        path = current.data(Qt.ItemDataRole.UserRole)
        findings = self._findings_by_file.get(path, [])
        self._result_panel.show_findings(path, findings)
        self._hex_viewer.load_file(path)
        self._notes_edit.setPlainText(self._notes_by_file.get(path, ""))
        self._file_intel.load_file(path)
        self._investigate_tab.load_file(path)

    def _on_notes_changed(self) -> None:
        item = self._file_list.currentItem()
        if item:
            path = item.data(Qt.ItemDataRole.UserRole)
            self._notes_by_file[path] = self._notes_edit.toPlainText()

    def _toggle_notes(self) -> None:
        visible = not self._notes_edit.isVisible()
        self._notes_edit.setVisible(visible)
        self._notes_toggle.setText("▼ Notes" if visible else "▶ Notes")

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------

    def _analyze_all(self) -> None:
        for path in self._session.files:
            self._analyze_file(path)

    def _analyze_file(self, path: str) -> None:
        if pb := self._progress_by_file.get(path):
            pb.setValue(0)

        pattern_text = _FLAG_PRESETS.get(self._flag_combo.currentText(), r"CTF\{[^}]+\}")
        if not pattern_text:
            pattern_text = r"CTF\{[^}]+\}"
        self._session.flag_pattern = pattern_text

        try:
            flag_pattern = re.compile(pattern_text, re.IGNORECASE)
        except re.error:
            flag_pattern = re.compile(r"CTF\{[^}]+\}", re.IGNORECASE)

        depth = self._depth_combo.currentText().lower()
        self._session.depth = depth
        self._investigate_tab.set_flag_pattern(flag_pattern)
        self._investigate_tab.set_depth(depth)

        worker = _AnalyzeWorker(path, flag_pattern, depth, self._ai_client)
        worker.signals.finished.connect(self._on_analysis_done)
        worker.signals.error.connect(self._on_analysis_error)
        worker.signals.progress.connect(self._on_analysis_progress)
        self._thread_pool.start(worker)

    def _on_analysis_done(self, path: str, findings: List[Finding]) -> None:
        self._findings_by_file[path] = findings
        self._session.findings = [
            f for path_f, flist in self._findings_by_file.items() for f in flist
        ]

        if pb := self._progress_by_file.get(path):
            pb.setValue(100)

        # Update badge
        for i in range(self._file_list.count()):
            item = self._file_list.item(i)
            if item and item.data(Qt.ItemDataRole.UserRole) == path:
                badge = self._severity_badge_for_file(path)
                # Update the label in the container widget
                widget = self._file_list.itemWidget(item)
                if widget:
                    lbl = widget.findChild(QLabel)
                    if lbl:
                        lbl.setText(f"{badge} {Path(path).name}")
                break

        # Refresh results if this file is currently selected
        current = self._file_list.currentItem()
        if current and current.data(Qt.ItemDataRole.UserRole) == path:
            self._result_panel.show_findings(path, findings)

        # Refresh flag summary
        all_findings = [f for flist in self._findings_by_file.values() for f in flist]
        self._flag_summary.refresh(all_findings)
        self._challenge_panel.update_findings(all_findings)
        self._timeline_tab.refresh(all_findings)
        self._attack_plan.update_session(self._session)
        self._attack_chains.update_session(self._session)

    def _on_analysis_error(self, path: str, msg: str) -> None:
        if pb := self._progress_by_file.get(path):
            pb.setValue(0)
        QMessageBox.warning(self, "Analysis Error", f"Error analyzing {path}:\n{msg}")

    def _on_analysis_progress(self, path: str, pct: int) -> None:
        if pb := self._progress_by_file.get(path):
            pb.setValue(pct)

    # ------------------------------------------------------------------
    # Hex viewer jump
    # ------------------------------------------------------------------

    def _on_finding_selected(self, finding: Finding) -> None:
        if finding.offset >= 0:
            self._hex_viewer.highlight_offset(finding.offset, 16)
            self._hex_viewer.jump_to_offset(finding.offset)

    def _on_pin_finding(self, finding: Finding) -> None:
        """Load a finding's detail into the Transform Pipeline's first node."""
        panel: TransformPipelinePanel = self._pipeline_dock.widget()
        panel.load_finding(finding.detail)
        self._pipeline_dock.setVisible(True)

    def _on_run_chain(self, initial_data: str, pipeline_configs: list) -> None:
        """Load an attack chain into the Transform Pipeline and show it."""
        panel: TransformPipelinePanel = self._pipeline_dock.widget()
        panel.load_finding(initial_data)
        if pipeline_configs:
            panel.set_pipeline_config(pipeline_configs)
        self._pipeline_dock.setVisible(True)

    # ------------------------------------------------------------------
    # Flag preset
    # ------------------------------------------------------------------

    def _on_flag_preset_changed(self, text: str) -> None:
        if text == "Custom…":
            regex, ok = QInputDialog.getText(
                self, "Custom Flag Regex", "Enter flag regex pattern:"
            )
            if ok and regex:
                _FLAG_PRESETS["Custom…"] = regex

    # ------------------------------------------------------------------
    # Tool status
    # ------------------------------------------------------------------

    def _update_tool_status(self) -> None:
        for tool, label in self._tool_dots.items():
            if is_available(tool):
                label.setStyleSheet("color: #00aa00;")
                label.setToolTip(f"{tool}: found")
            else:
                label.setStyleSheet("color: #999999;")
                label.setToolTip(f"{tool}: not found (using Python fallback)")

    # ------------------------------------------------------------------
    # Session
    # ------------------------------------------------------------------

    def _save_session(self) -> None:
        # Sync notes
        for path, note in self._notes_by_file.items():
            self._session.notes[path] = note
        save_session_dialog(self, self._session)

    def _load_session(self) -> None:
        session = load_session_dialog(self)
        if not session:
            return
        self._clear_files()
        self._session = session
        self._findings_by_file = {}

        # Rebuild findings by file
        for f in session.findings:
            self._findings_by_file.setdefault(f.file, []).append(f)

        for path in session.files:
            self._add_file(path)

        self._notes_by_file = dict(session.notes)
        self._flag_summary.refresh(session.findings)
        self._challenge_panel.update_findings(session.findings)
        self._timeline_tab.refresh(session.findings)
        self._network_console.set_session(session)
        self._attack_plan.update_session(session)
        self._attack_chains.update_session(session)

    def _compare_session(self) -> None:
        """Open a second .ctfs file and show a session diff panel."""
        from core.session_diff import diff_sessions
        from ui.session_diff_panel import SessionDiffPanel

        path, _ = QFileDialog.getOpenFileName(
            self, "Select Session to Compare", "", "CTF Hunter Session (*.ctfs);;All Files (*)"
        )
        if not path:
            return
        try:
            session_b = Session.load(path)
        except Exception as exc:
            QMessageBox.critical(self, "Load Error", f"Failed to load session:\n{exc}")
            return

        diff = diff_sessions(self._session, session_b)

        panel = SessionDiffPanel(
            diff,
            label_a="Current session",
            label_b=Path(path).name,
            parent=self,
        )
        # Reuse the persistent diff dock so its View-menu toggle remains valid
        # across multiple comparisons.
        self._diff_dock.setWidget(panel)
        self._diff_dock.show()
        self._diff_dock.raise_()

    # ------------------------------------------------------------------
    # Dynamic Frida analysis
    # ------------------------------------------------------------------

    def _run_dynamic_analysis(self) -> None:
        """Run Frida instrumentation on the currently selected binary — explicit opt-in."""
        item = self._file_list.currentItem()
        if not item:
            QMessageBox.information(self, "Dynamic Analysis", "Select a file in the list first.")
            return
        path = item.data(Qt.ItemDataRole.UserRole)
        if not path:
            return

        # Optional frida args
        args_str, ok = QInputDialog.getText(
            self, "Frida Arguments",
            "Optional arguments for the target binary (space-separated):",
            text="",
        )
        if not ok:
            return
        frida_args: List[str] = args_str.strip().split() if args_str.strip() else []
        self._run_frida_worker(path, frida_args)

    def _run_frida_worker(self, path: str, frida_args: List[str]) -> None:
        """Spawn the Frida analyzer in a thread pool worker."""
        class _FridaSignals(QObject):
            finished = pyqtSignal(str, list)
            error = pyqtSignal(str, str)

        class _FridaWorker(QRunnable):
            def __init__(self, _path, _flag_re, _ai_client, _args, _timeout):
                super().__init__()
                self.signals = _FridaSignals()
                self._path = _path
                self._flag_re = _flag_re
                self._ai_client = _ai_client
                self._frida_args = _args
                self._timeout = _timeout

            @pyqtSlot()
            def run(self):
                try:
                    from analyzers.dynamic_frida import FridaAnalyzer
                    findings = FridaAnalyzer().analyze(
                        self._path,
                        self._flag_re,
                        "deep",
                        self._ai_client,
                        frida_args=self._frida_args,
                        timeout_seconds=self._timeout,
                    )
                    self.signals.finished.emit(self._path, findings)
                except Exception as exc:
                    self.signals.error.emit(self._path, str(exc))

        try:
            flag_re = re.compile(self._session.flag_pattern, re.IGNORECASE)
        except re.error:
            flag_re = re.compile(r"CTF\{[^}]+\}", re.IGNORECASE)

        worker = _FridaWorker(path, flag_re, self._ai_client, frida_args,
                              self._frida_timeout_seconds)
        worker.signals.finished.connect(self._on_frida_analysis_done)
        worker.signals.error.connect(self._on_analysis_error)
        self._thread_pool.start(worker)

    def _on_frida_analysis_done(self, path: str, findings: List[Finding]) -> None:
        """Handle Frida analysis completion: update main result panel and show Frida dock."""
        self._on_analysis_done(path, findings)
        # Populate the dedicated Frida results dock with a human-readable summary
        frida_findings = [f for f in findings if f.analyzer == "FridaAnalyzer"]
        lines: List[str] = [f"Dynamic analysis results for:\n{path}\n"]
        if frida_findings:
            for f in frida_findings:
                flag_icon = "🚩 " if f.flag_match else ""
                lines.append(f"[{f.severity}] {flag_icon}{f.title}")
                if f.detail:
                    detail = f.detail[:300] + ("…" if len(f.detail) > 300 else "")
                    lines.append(f"  {detail}")
                lines.append("")
        else:
            lines.append("No findings from dynamic analysis.")
        self._frida_results_text.setPlainText("\n".join(lines))
        self._frida_dock.show()
        self._frida_dock.raise_()

    # ------------------------------------------------------------------
    # Network tab
    # ------------------------------------------------------------------

    def _on_network_flag_detected(self, context: str, flag_text: str) -> None:
        """Called when the network console auto-detects a flag pattern."""
        from core.report import Finding
        f = Finding(
            file=f"network://{context}",
            analyzer="NetworkConsoleTab",
            title="Flag pattern detected in network data",
            severity="HIGH",
            detail=flag_text[:500],
            flag_match=True,
            confidence=0.90,
        )
        # Add to the flag summary
        self._session.findings.append(f)
        all_findings = list(self._session.findings)
        self._flag_summary.refresh(all_findings)
        # Switch to flag summary tab
        self._tabs.setCurrentIndex(1)  # Flag Summary is tab index 1

    def _toggle_watchfolder(self, checked: bool) -> None:
        if checked:
            directory = QFileDialog.getExistingDirectory(self, "Select Watch Folder")
            if not directory:
                self._watchfolder_btn.setChecked(False)
                return
            self._session.watchfolder_path = directory
            # Apply current max_file_mb from config
            cfg = load_config()
            self._watchfolder.max_file_mb = float(cfg.get("max_file_mb", 50))
            self._watchfolder.start(directory)
            self._watchfolder_btn.setText("📁 Watch ●")
            self._watchfolder_btn.setStyleSheet("color: green;")
            self._watchfolder_active = True
        else:
            self._watchfolder.stop()
            self._watchfolder_btn.setText("📁 Watch")
            self._watchfolder_btn.setStyleSheet("")
            self._watchfolder_active = False

    def _on_watchfolder_file(self, path: str) -> None:
        """Called (via Qt signal) when a new file passes debounce + size gate."""
        self._add_file(path)
        self._analyze_file(path)

    def _on_watchfolder_skip(self, path: str, reason: str) -> None:
        """Called (via Qt signal) when a file is skipped by the size gate."""
        msg = f"Watchfolder skipped: {Path(path).name} — {reason}"
        self.statusBar().showMessage(msg, 8000)

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def _export(self, fmt: str) -> None:
        all_findings = [f for flist in self._findings_by_file.values() for f in flist]
        if not all_findings:
            QMessageBox.information(self, "Export", "No findings to export.")
            return

        ext_map = {"markdown": "*.md", "csv": "*.csv", "html": "*.html"}
        ext = ext_map.get(fmt, "*.*")
        path, _ = QFileDialog.getSaveFileName(self, "Export Report", "", f"{ext.upper()[1:]} ({ext})")
        if not path:
            return

        try:
            if fmt == "markdown":
                self._export_markdown(path, all_findings)
            elif fmt == "csv":
                self._export_csv(path, all_findings)
            elif fmt == "html":
                self._export_html(path, all_findings)
            QMessageBox.information(self, "Export", f"Exported to {path}")
        except Exception as exc:
            QMessageBox.critical(self, "Export Error", str(exc))

    def _export_markdown(self, path: str, findings: List[Finding]) -> None:
        lines = ["# CTF Hunter Report\n"]
        by_file: dict[str, list[Finding]] = {}
        for f in findings:
            by_file.setdefault(f.file, []).append(f)
        for fpath, flist in by_file.items():
            lines.append(f"## {fpath}\n")
            for f in flist:
                if f.duplicate_of:
                    continue
                flag_marker = " 🚩" if f.flag_match else ""
                lines.append(f"### [{f.severity}] {f.title}{flag_marker}")
                lines.append(f"- **Analyzer**: {f.analyzer}")
                lines.append(f"- **Confidence**: {f.confidence:.2f}")
                if f.offset >= 0:
                    lines.append(f"- **Offset**: 0x{f.offset:x}")
                lines.append(f"- **Detail**: {f.detail}\n")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))

    def _export_csv(self, path: str, findings: List[Finding]) -> None:
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["ID", "File", "Analyzer", "Title", "Severity",
                              "Offset", "Confidence", "FlagMatch", "Detail"])
            for f in findings:
                writer.writerow([
                    f.id, f.file, f.analyzer, f.title, f.severity,
                    hex(f.offset) if f.offset >= 0 else "",
                    f"{f.confidence:.2f}", str(f.flag_match), f.detail[:500],
                ])

    def _export_html(self, path: str, findings: List[Finding]) -> None:
        sev_color = {"HIGH": "#cc0000", "MEDIUM": "#886600", "LOW": "#004488", "INFO": "#333"}
        by_file: dict[str, list[Finding]] = {}
        for f in findings:
            by_file.setdefault(f.file, []).append(f)

        rows = []
        for fpath, flist in by_file.items():
            rows.append(f"<h2>{html.escape(str(fpath))}</h2>")
            for f in flist:
                if f.duplicate_of:
                    continue
                color = sev_color.get(f.severity, "#333")
                flag_icon = "🚩 " if f.flag_match else ""
                rows.append(
                    f'<div style="border-left:4px solid {color};padding:8px;margin:8px 0;">'
                    f'<b style="color:{color}">[{f.severity}]</b> {flag_icon}'
                    f'<b>{html.escape(f.title)}</b> '
                    f'<span style="color:#888">(conf: {f.confidence:.2f}, analyzer: {f.analyzer})</span>'
                    f'<br><code>{html.escape(f.detail[:500])}</code>'
                    f'</div>'
                )
        body = "\n".join(rows)
        html_content = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>CTF Hunter Report</title>
<style>body{{font-family:sans-serif;max-width:1200px;margin:auto;padding:20px}}</style>
</head><body><h1>CTF Hunter Report</h1>{body}</body></html>"""
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html_content)

    # ------------------------------------------------------------------
    # Settings
    # ------------------------------------------------------------------

    def _open_settings(self) -> None:
        dlg = SettingsDialog(self)
        if dlg.exec():
            api_key = dlg.get_api_key()
            self._ai_client.set_api_key(api_key)
            self._result_panel.set_ai_client(self._ai_client)
            self._flag_summary.set_ai_client(self._ai_client)
            self._challenge_panel.set_ai_client(self._ai_client)
            self._attack_plan.set_ai_client(self._ai_client)
            # Propagate watchfolder size limit
            self._watchfolder.max_file_mb = dlg.get_max_file_mb()
            # Store frida timeout
            self._frida_timeout_seconds = dlg.get_frida_timeout_seconds()

    # ------------------------------------------------------------------
    # Transform Pipeline dock
    # ------------------------------------------------------------------

    def _build_transform_pipeline_dock(self) -> None:
        from PyQt6.QtCore import Qt as _Qt
        self._pipeline_dock = make_transform_pipeline_dock(self, ai_client=self._ai_client)
        self._pipeline_dock.visibilityChanged.connect(self._on_pipeline_visibility_changed)
        panel: TransformPipelinePanel = self._pipeline_dock.widget()
        panel.hypothesis_requested.connect(self._on_pipeline_hypothesis_requested)
        self.addDockWidget(_Qt.DockWidgetArea.RightDockWidgetArea, self._pipeline_dock)

    def _toggle_transform_pipeline(self, checked: bool) -> None:
        self._pipeline_dock.setVisible(checked)

    def _on_pipeline_visibility_changed(self, visible: bool) -> None:
        self._pipeline_toggle_action.setChecked(visible)

    def _on_pipeline_hypothesis_requested(self, final_output: str, transforms: str) -> None:
        """Forward pipeline output to AI client (if configured) via challenge panel."""
        context = f"Transform chain applied: {transforms}\n\nFinal output:\n{final_output[:2000]}"
        self._challenge_panel.set_additional_context(context)
        self._tabs.setCurrentWidget(self._challenge_panel)

    # ------------------------------------------------------------------
    # Session Diff dock
    # ------------------------------------------------------------------

    def _build_session_diff_dock(self) -> None:
        """Create the persistent Session Diff dock (initially hidden).

        The dock is shown and its content replaced each time _compare_session()
        runs.  Its toggleViewAction() is registered in the View menu so users
        can re-show a diff that was accidentally closed without re-running the
        comparison.
        """
        placeholder = QLabel("Use '🔀 Compare Session' to load a session diff.")
        placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        placeholder.setStyleSheet("color: #888; padding: 20px;")

        self._diff_dock = QDockWidget("🔀 Session Diff", self)
        self._diff_dock.setAllowedAreas(
            Qt.DockWidgetArea.BottomDockWidgetArea | Qt.DockWidgetArea.TopDockWidgetArea
        )
        self._diff_dock.setWidget(placeholder)
        self._diff_dock.setMinimumHeight(300)
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, self._diff_dock)
        self._diff_dock.hide()

    # ------------------------------------------------------------------
    # Frida results dock
    # ------------------------------------------------------------------

    def _build_frida_results_dock(self) -> None:
        """Create the persistent Dynamic Analysis (Frida) results dock (initially hidden).

        The dock is shown and populated each time a Frida analysis completes.
        Its toggleViewAction() is registered in the View menu so users can
        re-open the panel after closing it.
        """
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(4, 4, 4, 4)

        hdr = QLabel("🔬 Dynamic Analysis (Frida) Results")
        hdr.setStyleSheet("font-weight: bold; padding: 4px;")
        layout.addWidget(hdr)

        self._frida_results_text = QTextEdit()
        self._frida_results_text.setReadOnly(True)
        self._frida_results_text.setPlaceholderText(
            "Run '🔬 Run Dynamic Analysis (Frida)' on a binary to see results here."
        )
        layout.addWidget(self._frida_results_text)

        self._frida_dock = QDockWidget("🔬 Dynamic Analysis Results", self)
        self._frida_dock.setAllowedAreas(
            Qt.DockWidgetArea.BottomDockWidgetArea | Qt.DockWidgetArea.RightDockWidgetArea
        )
        self._frida_dock.setWidget(container)
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, self._frida_dock)
        self._frida_dock.hide()

    # ------------------------------------------------------------------
    # View menu (menu bar)
    # ------------------------------------------------------------------

    def _build_menu_bar(self) -> None:
        """Build the application menu bar with a View menu for dock panel toggles.

        All three dockable panels are registered here so users can toggle them
        from a single, discoverable location even if they have been closed.
        """
        mb = self.menuBar()
        view_menu = mb.addMenu("View")

        # Session Diff panel — uses the dock's own toggleViewAction() so Qt
        # keeps the checked state in sync with actual dock visibility automatically.
        diff_action = self._diff_dock.toggleViewAction()
        diff_action.setText("Session Diff Panel")
        view_menu.addAction(diff_action)

        # Dynamic Analysis (Frida) results panel
        frida_action = self._frida_dock.toggleViewAction()
        frida_action.setText("Dynamic Analysis Results")
        view_menu.addAction(frida_action)

        view_menu.addSeparator()

        # Transform Pipeline — the same QAction already present in the toolbar,
        # mirrored here so the View menu is the single place to find all panels.
        view_menu.addAction(self._pipeline_toggle_action)

    # ------------------------------------------------------------------
    # Workspace correlator
    # ------------------------------------------------------------------

    def _correlate_all_files(self) -> None:
        from core.workspace_correlator import WorkspaceCorrelator
        correlator = WorkspaceCorrelator()
        new_findings = correlator.correlate(self._session)
        if not new_findings:
            QMessageBox.information(
                self, "Correlate All", "No cross-file correlations found."
            )
            return
        # Add correlation findings to the session
        self._session.findings.extend(new_findings)
        for f in new_findings:
            self._findings_by_file.setdefault(f.file, []).append(f)

        # Refresh the currently selected file's results
        current = self._file_list.currentItem()
        if current:
            path = current.data(Qt.ItemDataRole.UserRole)
            self._result_panel.show_findings(
                path, self._findings_by_file.get(path, [])
            )
        all_findings = [f for flist in self._findings_by_file.values() for f in flist]
        self._flag_summary.refresh(all_findings)
        self._attack_plan.update_session(self._session)
        self._attack_chains.update_session(self._session)
        QMessageBox.information(
            self, "Correlate All",
            f"Found {len(new_findings)} cross-file correlation(s)."
        )

    # ------------------------------------------------------------------
    # Drag and drop
    # ------------------------------------------------------------------

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent) -> None:
        for url in event.mimeData().urls():
            path = url.toLocalFile()
            if not path:
                continue
            p = Path(path)
            if p.is_file():
                self._add_file(str(p))
            elif p.is_dir():
                self._add_directory_files(str(p))

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def closeEvent(self, event) -> None:
        self._watchfolder.stop()
        self._thread_pool.waitForDone(3000)
        super().closeEvent(event)
