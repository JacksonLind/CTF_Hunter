"""
Manual Investigation tab for CTF Hunter.

Lets the analyst click on a loaded file and choose — step by step — which
analysis path to run next.  Results accumulate as a vertical investigation log.
Each step can be pinned to the Transform Pipeline, copied to clipboard, or
annotated with a note before moving on.

Layout
──────
┌──────────────────────────────────────────────────────────────────────┐
│ File: challenge.png   [PNG Image · 42 KB]               [🗑 Clear]  │
├──────────────────────┬───────────────────────────────────────────────┤
│  ACTION PALETTE      │  INVESTIGATION LOG                            │
│  ─ Forensics         │  ┌──────────────────────────────────────────┐ │
│    [🔍 Strings]      │  │ Step 1 · LSB Extract                     │ │
│    [📊 Entropy]      │  │ ▸ 3 findings …                           │ │
│    [🕵 EXIF]         │  │   [MEDIUM] LSB plane 0 …                 │ │
│  ─ Crypto            │  │ [📌 Pin] [📋 Copy] [✏ Note]             │ │
│    [🔑 Hash ID]      │  └──────────────────────────────────────────┘ │
│    [🔐 RSA/ECC]      │  ┌──────────────────────────────────────────┐ │
│  ─ Encoding          │  │ Step 2 · Encoding Chain …                │ │
│    [🔗 Chain BFS]    │  └──────────────────────────────────────────┘ │
│  ─ Archive           │                                               │
│    [🗜 List/Crack]   │                                               │
│  ─ Custom            │                                               │
│    [⚙ Transform…]   │                                               │
└──────────────────────┴───────────────────────────────────────────────┘
"""
from __future__ import annotations

import re
import time
from pathlib import Path
from typing import List, Optional

from PyQt6.QtCore import (
    Qt, QObject, QRunnable, QThreadPool, pyqtSignal, pyqtSlot,
)
from PyQt6.QtGui import QFont, QColor
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QScrollArea, QFrame, QTextEdit, QSizePolicy, QApplication,
    QSplitter, QGroupBox, QSpacerItem,
)

from core.report import Finding

# ---------------------------------------------------------------------------
# Step worker — runs one analyzer key in isolation
# ---------------------------------------------------------------------------

class _StepSignals(QObject):
    finished = pyqtSignal(str, list, float)   # (label, findings, elapsed_s)
    error    = pyqtSignal(str, str)            # (label, message)


class _StepWorker(QRunnable):
    """Run a single analyzer (or small set) on *path* without full dispatch."""

    def __init__(
        self,
        label: str,
        path: str,
        analyzer_keys: list[str],
        flag_pattern: re.Pattern,
        depth: str,
    ):
        super().__init__()
        self.label         = label
        self.path          = path
        self.analyzer_keys = analyzer_keys
        self.flag_pattern  = flag_pattern
        self.depth         = depth
        self.signals       = _StepSignals()

    @pyqtSlot()
    def run(self) -> None:
        try:
            from core.dispatcher import analyze_file
            from core.report import Session
            from core.deduplicator import deduplicate

            s = Session()
            s.flag_pattern = self.flag_pattern.pattern
            s.depth = self.depth

            t0 = time.perf_counter()
            findings: list = []

            # GenericAnalyzer is not in _ANALYZER_REGISTRY (it is always-run in
            # full dispatch), so we call it directly when requested.
            if "generic" in self.analyzer_keys:
                from analyzers.generic import GenericAnalyzer
                findings.extend(
                    GenericAnalyzer().analyze(self.path, self.flag_pattern, self.depth, None)
                )
            remaining = [k for k in self.analyzer_keys if k != "generic"]
            if remaining:
                findings.extend(analyze_file(self.path, s, analyzers=remaining))

            elapsed = time.perf_counter() - t0
            self.signals.finished.emit(self.label, deduplicate(findings), elapsed)
        except Exception as exc:
            self.signals.error.emit(self.label, str(exc))


# ---------------------------------------------------------------------------
# Step card widget — one entry in the investigation log
# ---------------------------------------------------------------------------

_SEV_COLOUR = {
    "HIGH":   "#cc2222",
    "MEDIUM": "#cc8800",
    "LOW":    "#226622",
    "INFO":   "#555555",
}


class _StepCard(QFrame):
    pin_requested  = pyqtSignal(object)   # Finding
    note_saved     = pyqtSignal(str, str) # (step_label, note_text)

    def __init__(self, step_num: int, label: str, parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setStyleSheet("QFrame { background: #1e1e2e; border-radius: 6px; }")
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self._step_num = step_num
        self._label    = label
        self._findings: List[Finding] = []

        vbox = QVBoxLayout(self)
        vbox.setContentsMargins(10, 8, 10, 8)
        vbox.setSpacing(4)

        # Header row
        hdr = QHBoxLayout()
        num_lbl = QLabel(f"<b style='color:#7799ff'>Step {step_num}</b>")
        lbl_lbl = QLabel(f"<span style='color:#cccccc'>{label}</span>")
        self._spinner = QLabel("⏳")
        hdr.addWidget(num_lbl)
        hdr.addWidget(lbl_lbl)
        hdr.addStretch()
        hdr.addWidget(self._spinner)
        vbox.addLayout(hdr)

        # Findings area (filled when worker completes)
        self._findings_widget = QWidget()
        self._findings_layout = QVBoxLayout(self._findings_widget)
        self._findings_layout.setContentsMargins(0, 0, 0, 0)
        self._findings_layout.setSpacing(2)
        vbox.addWidget(self._findings_widget)

        # Note field (hidden by default)
        self._note_edit = QTextEdit()
        self._note_edit.setPlaceholderText("Add a note for this step…")
        self._note_edit.setMaximumHeight(60)
        self._note_edit.setStyleSheet("background:#2a2a3e; color:#cccccc;")
        self._note_edit.hide()
        vbox.addWidget(self._note_edit)

        # Action row (hidden until results arrive)
        self._action_row = QWidget()
        action_hbox = QHBoxLayout(self._action_row)
        action_hbox.setContentsMargins(0, 4, 0, 0)
        action_hbox.setSpacing(6)

        self._note_btn = QPushButton("✏ Note")
        self._note_btn.setFixedWidth(72)
        self._note_btn.setStyleSheet("QPushButton{background:#2a3a4a;color:#aaaacc;}")
        self._note_btn.clicked.connect(self._toggle_note)
        action_hbox.addWidget(self._note_btn)

        action_hbox.addStretch()
        self._action_row.hide()
        vbox.addWidget(self._action_row)

    # ------------------------------------------------------------------

    def populate(self, findings: List[Finding], elapsed: float) -> None:
        self._findings = findings
        self._spinner.setText(f"✓  {elapsed:.2f}s")

        if not findings:
            lbl = QLabel("<span style='color:#888888;font-style:italic'>No findings.</span>")
            self._findings_layout.addWidget(lbl)
        else:
            for f in findings:
                self._add_finding_row(f)

        self._action_row.show()

    def set_error(self, msg: str) -> None:
        self._spinner.setText("✗")
        lbl = QLabel(f"<span style='color:#cc4444'><b>Error:</b> {msg}</span>")
        lbl.setWordWrap(True)
        self._findings_layout.addWidget(lbl)
        self._action_row.show()

    def _add_finding_row(self, finding: Finding) -> None:
        row = QWidget()
        hbox = QHBoxLayout(row)
        hbox.setContentsMargins(4, 1, 4, 1)
        hbox.setSpacing(6)

        sev = finding.severity
        colour = _SEV_COLOUR.get(sev, "#888888")
        sev_lbl = QLabel(f"<b style='color:{colour}'>[{sev}]</b>")
        sev_lbl.setFixedWidth(72)

        title = finding.title[:80] + ("…" if len(finding.title) > 80 else "")
        title_lbl = QLabel(f"<span style='color:#dddddd'>{title}</span>")
        title_lbl.setWordWrap(False)

        pin_btn = QPushButton("📌")
        pin_btn.setFixedWidth(32)
        pin_btn.setToolTip("Pin to Transform Pipeline")
        pin_btn.setStyleSheet("QPushButton{background:#2a3a2a;}")
        pin_btn.clicked.connect(lambda _, f=finding: self.pin_requested.emit(f))

        copy_btn = QPushButton("📋")
        copy_btn.setFixedWidth(32)
        copy_btn.setToolTip("Copy finding detail")
        copy_btn.setStyleSheet("QPushButton{background:#2a2a3a;}")
        copy_btn.clicked.connect(lambda _, f=finding: QApplication.clipboard().setText(
            f"{f.title}\n{f.detail}"
        ))

        if finding.flag_match:
            flag_lbl = QLabel("🚩")
            flag_lbl.setToolTip("Flag match!")
            hbox.addWidget(flag_lbl)

        hbox.addWidget(sev_lbl)
        hbox.addWidget(title_lbl, 1)
        hbox.addWidget(pin_btn)
        hbox.addWidget(copy_btn)
        self._findings_layout.addWidget(row)

    def _toggle_note(self) -> None:
        visible = not self._note_edit.isVisible()
        self._note_edit.setVisible(visible)
        self._note_btn.setText("💾 Save" if visible else "✏ Note")
        if not visible:
            self.note_saved.emit(self._label, self._note_edit.toPlainText())


# ---------------------------------------------------------------------------
# Action palette — groups of buttons for each investigation path
# ---------------------------------------------------------------------------

# (display_name, analyzer_keys, depth_override, tooltip)
# depth_override None = inherit current session depth
_PATHS: list[tuple[str, list[str], str | None, str, str]] = [
    # (category, label, analyzer_keys, depth_override, tooltip)
    ("Forensics",  "🔍 Strings & Entropy",  ["generic"],              None,    "Generic checks: entropy, strings, STFT"),
    ("Forensics",  "🕵 EXIF & File Intel",  ["image_format"],         None,    "EXIF metadata, hidden color channels"),
    ("Forensics",  "⏱ Timeline",            ["forensics_timeline"],  None,    "Forensics timeline analysis"),
    ("Forensics",  "💾 Disk Image",          ["filesystem"],          None,    "Disk image / inode forensics"),
    ("Steg",       "🎨 LSB Image",           ["image"],               "deep",  "LSB steganography, chi-square, QR repair"),
    ("Steg",       "🎵 LSB Audio",           ["audio"],               "deep",  "LSB audio steganography, phase analysis"),
    ("Steg",       "🔬 Steganalysis",        ["steganalysis"],        "deep",  "Chi-square, RS analysis, histogram"),
    ("Crypto",     "🔑 RSA / ECC",           ["crypto_rsa"],          None,    "RSA modulus factoring, ECC Smart attack"),
    ("Crypto",     "🔐 Classical Cipher",    ["classical_cipher"],    None,    "ROT/affine/Vigenere/Grey rotation"),
    ("Crypto",     "🎲 PRNG Recovery",       ["crypto_prng"],         None,    "MT19937 state recovery"),
    ("Crypto",     "🌊 Side-Channel",        ["side_channel"],        None,    "DPA trace averaging"),
    ("Encoding",   "🔗 Encoding Chain",      ["encoding"],            "deep",  "BFS over base64/hex/rot13/xor/…"),
    ("Encoding",   "🔑 JWT",                 ["jwt"],                 None,    "JWT decode, alg:none, HMAC brute"),
    ("Archive",    "🗜 Archive / Password",  ["archive"],             "deep",  "ZIP/7z/RAR list + password spray"),
    ("Binary",     "🔩 Binary / PE",         ["binary"],              None,    "ELF/PE strings, PE .rsrc extraction"),
    ("Binary",     "🔭 Disassembly",         ["disassembly"],         None,    "Capstone disassembly (ELF/PE/Mach-O)"),
    ("Network",    "📡 PCAP / Timing",       ["pcap"],                "deep",  "DNS exfil, HTTP creds, timing channel"),
    ("Network",    "🔌 SAL Logic",           ["sal"],                 None,    "Saleae UART / logic analyzer decode"),
    ("Forensics",  "🗂 Git Forensics",       ["git_forensics"],       None,    "Git bundle / deleted branches"),
    ("Database",   "🗄 SQLite",              ["database"],            None,    "SQLite schema and content scan"),
    ("Document",   "📄 PDF / Office",        ["document"],            None,    "PDF/Office content extraction"),
]

_CATEGORY_ORDER = [
    "Forensics", "Steg", "Crypto", "Encoding",
    "Archive", "Binary", "Network", "Database", "Document",
]


# ---------------------------------------------------------------------------
# Main tab widget
# ---------------------------------------------------------------------------

class InvestigateTab(QWidget):
    """Step-by-step manual investigation panel."""

    # Emitted when analyst pins a finding — MainWindow connects to load pipeline
    pin_finding_requested = pyqtSignal(object)   # Finding

    def __init__(self, parent=None):
        super().__init__(parent)

        self._path: Optional[str] = None
        self._flag_pattern: re.Pattern = re.compile(r"CTF\{[^}]+\}", re.IGNORECASE)
        self._depth: str = "deep"
        self._step_counter: int = 0
        self._pool = QThreadPool()
        self._pool.setMaxThreadCount(2)

        self._build_ui()

    # ------------------------------------------------------------------
    # Public API (called by MainWindow)
    # ------------------------------------------------------------------

    def load_file(self, path: str) -> None:
        """Switch investigation target to *path*."""
        self._path = path
        p = Path(path)
        try:
            size_kb = p.stat().st_size // 1024
            size_str = f"{size_kb} KB" if size_kb < 1024 else f"{size_kb // 1024} MB"
        except Exception:
            size_str = "?"
        self._file_label.setText(
            f"<b style='color:#7799ff'>{p.name}</b>"
            f"  <span style='color:#888888'>{size_str}</span>"
        )

    def set_flag_pattern(self, pattern: re.Pattern) -> None:
        self._flag_pattern = pattern

    def set_depth(self, depth: str) -> None:
        self._depth = depth

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        main_vbox = QVBoxLayout(self)
        main_vbox.setContentsMargins(6, 6, 6, 6)
        main_vbox.setSpacing(6)

        # ── Header bar ──────────────────────────────────────────────
        hdr = QHBoxLayout()
        self._file_label = QLabel(
            "<span style='color:#888888;font-style:italic'>No file selected.</span>"
        )
        self._file_label.setFont(QFont("Monospace", 10))

        clear_btn = QPushButton("🗑 Clear log")
        clear_btn.setFixedWidth(100)
        clear_btn.setToolTip("Clear the investigation log")
        clear_btn.clicked.connect(self._clear_log)

        hdr.addWidget(self._file_label, 1)
        hdr.addWidget(clear_btn)
        main_vbox.addLayout(hdr)

        # ── Splitter: palette left / log right ───────────────────────
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left: action palette
        palette_scroll = QScrollArea()
        palette_scroll.setWidgetResizable(True)
        palette_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        palette_scroll.setMinimumWidth(180)
        palette_scroll.setMaximumWidth(220)
        palette_scroll.setStyleSheet("QScrollArea{border:none;background:#12121e;}")

        palette_inner = QWidget()
        palette_inner.setStyleSheet("background:#12121e;")
        self._palette_layout = QVBoxLayout(palette_inner)
        self._palette_layout.setContentsMargins(6, 6, 6, 6)
        self._palette_layout.setSpacing(2)
        self._build_palette()
        self._palette_layout.addStretch()
        palette_scroll.setWidget(palette_inner)
        splitter.addWidget(palette_scroll)

        # Right: investigation log
        log_outer = QWidget()
        log_vbox = QVBoxLayout(log_outer)
        log_vbox.setContentsMargins(0, 0, 0, 0)

        log_hdr = QLabel("<b style='color:#aaaaaa'>  Investigation Log</b>")
        log_vbox.addWidget(log_hdr)

        self._log_scroll = QScrollArea()
        self._log_scroll.setWidgetResizable(True)
        self._log_scroll.setStyleSheet("QScrollArea{border:none;background:#0e0e1e;}")

        self._log_inner = QWidget()
        self._log_inner.setStyleSheet("background:#0e0e1e;")
        self._log_layout = QVBoxLayout(self._log_inner)
        self._log_layout.setContentsMargins(8, 8, 8, 8)
        self._log_layout.setSpacing(8)
        self._log_layout.addStretch()

        self._log_scroll.setWidget(self._log_inner)
        log_vbox.addWidget(self._log_scroll)

        splitter.addWidget(log_outer)
        splitter.setSizes([200, 800])

        main_vbox.addWidget(splitter, 1)

    def _build_palette(self) -> None:
        # Group buttons by category
        by_cat: dict[str, list] = {c: [] for c in _CATEGORY_ORDER}
        for entry in _PATHS:
            cat, lbl, keys, depth_ov, tip = entry
            if cat in by_cat:
                by_cat[cat].append((lbl, keys, depth_ov, tip))

        for cat in _CATEGORY_ORDER:
            entries = by_cat.get(cat, [])
            if not entries:
                continue
            # Category header
            cat_lbl = QLabel(f"<span style='color:#6688aa;font-size:9pt'>{cat}</span>")
            cat_lbl.setContentsMargins(0, 6, 0, 0)
            self._palette_layout.addWidget(cat_lbl)

            for lbl, keys, depth_ov, tip in entries:
                btn = QPushButton(lbl)
                btn.setToolTip(tip)
                btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
                btn.setStyleSheet(
                    "QPushButton{"
                    "  background:#1a1a2e; color:#ccccdd; border:1px solid #333355;"
                    "  border-radius:4px; padding:4px 6px; text-align:left;"
                    "}"
                    "QPushButton:hover{background:#252540;}"
                    "QPushButton:pressed{background:#1a1a40;}"
                )
                btn.clicked.connect(
                    lambda checked, l=lbl, k=keys, d=depth_ov: self._run_step(l, k, d)
                )
                self._palette_layout.addWidget(btn)

    # ------------------------------------------------------------------
    # Step execution
    # ------------------------------------------------------------------

    def _run_step(self, label: str, analyzer_keys: list[str], depth_override: Optional[str]) -> None:
        if not self._path:
            return

        self._step_counter += 1
        depth = depth_override if depth_override is not None else self._depth

        card = _StepCard(self._step_counter, label)
        card.pin_requested.connect(self.pin_finding_requested)
        card.note_saved.connect(lambda lbl, note: None)  # future: persist to session

        # Insert before the trailing stretch
        count = self._log_layout.count()
        self._log_layout.insertWidget(count - 1, card)

        # Scroll to bottom
        QApplication.processEvents()
        self._log_scroll.verticalScrollBar().setValue(
            self._log_scroll.verticalScrollBar().maximum()
        )

        worker = _StepWorker(label, self._path, analyzer_keys, self._flag_pattern, depth)
        worker.signals.finished.connect(
            lambda lbl, findings, elapsed, c=card: c.populate(findings, elapsed)
        )
        worker.signals.error.connect(
            lambda lbl, msg, c=card: c.set_error(msg)
        )
        self._pool.start(worker)

    # ------------------------------------------------------------------
    # Log management
    # ------------------------------------------------------------------

    def _clear_log(self) -> None:
        while self._log_layout.count() > 1:   # keep the trailing stretch
            item = self._log_layout.takeAt(0)
            if item and item.widget():
                item.widget().deleteLater()
        self._step_counter = 0
