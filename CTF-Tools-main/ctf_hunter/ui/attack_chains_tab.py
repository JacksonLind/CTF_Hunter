"""
Attack Chains tab for CTF Hunter.

Displays multi-stage cross-file attack chains discovered by ChainBuilder as a
vertical step-by-step card flow.  Each chain card shows:

  - Chain score badge and step count
  - Per-step panels with file badge, finding summary (severity / title /
    confidence) and the transform/rationale connecting steps
  - A "Run Chain" button that loads the chain into the Transform Pipeline
"""
from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Tuple

from PyQt6.QtCore import Qt, QSize, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from core.attack_chain import Chain, ChainBuilder, ChainStep
from core.key_registry import KeyRegistry
from core.report import Finding, Session


# ---------------------------------------------------------------------------
# Severity badge colours
# ---------------------------------------------------------------------------

_SEV_COLOURS: dict[str, tuple[str, str]] = {
    "HIGH":   ("#cc0000", "#fff0f0"),
    "MEDIUM": ("#886600", "#fffbf0"),
    "LOW":    ("#004488", "#f0f5ff"),
    "INFO":   ("#333333", "#f8f8f8"),
}
_DEFAULT_SEV = ("#333333", "#f8f8f8")

# Transforms that are descriptive labels rather than executable pipeline operations
_NON_EXECUTABLE_TRANSFORMS: frozenset[str] = frozenset([
    "Initial finding",
    "Data flow",
    "Data Overlap",
    "value_match",
])


def _sev_colours(sev: str) -> tuple[str, str]:
    return _SEV_COLOURS.get(sev.upper(), _DEFAULT_SEV)


# ---------------------------------------------------------------------------
# Step panel (one row in the chain card)
# ---------------------------------------------------------------------------

class _StepPanel(QFrame):
    """Visual representation of a single ChainStep."""

    def __init__(self, step: ChainStep, step_index: int, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        fg, bg = _sev_colours(step.finding.severity)
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setStyleSheet(
            f"QFrame {{ background:{bg}; border:1px solid #d0d0d0; border-radius:4px; }}"
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 6, 8, 6)
        layout.setSpacing(3)

        # ── Header row: step number + file badge + severity + title ──────
        header = QHBoxLayout()
        header.setSpacing(6)

        # Step number badge
        num_lbl = QLabel(f"Step {step_index + 1}")
        num_lbl.setStyleSheet(
            "background:#555555; color:white; padding:2px 6px; border-radius:3px; font-size:10px;"
        )
        num_lbl.setFixedHeight(18)
        header.addWidget(num_lbl)

        # File badge
        fname = Path(step.file).name if step.file else "?"
        file_lbl = QLabel(f"📄 {fname}")
        file_lbl.setFont(QFont("monospace", 9))
        file_lbl.setStyleSheet(
            "background:#1a1a3a; color:#aad4ff; padding:2px 6px; "
            "border-radius:3px; font-size:9px;"
        )
        file_lbl.setMaximumWidth(220)
        file_lbl.setToolTip(step.file)
        header.addWidget(file_lbl)

        # Severity badge
        sev_lbl = QLabel(step.finding.severity)
        sev_lbl.setStyleSheet(
            f"background:{fg}; color:white; padding:2px 5px; "
            f"border-radius:3px; font-weight:bold; font-size:9px;"
        )
        sev_lbl.setFixedHeight(18)
        header.addWidget(sev_lbl)

        # Title
        title_lbl = QLabel(step.finding.title)
        title_lbl.setFont(QFont("sans-serif", 9))
        title_lbl.setStyleSheet(f"color:{fg}; font-weight:bold;")
        title_lbl.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        title_lbl.setWordWrap(True)
        header.addWidget(title_lbl, 1)

        # Confidence
        conf_lbl = QLabel(f"{step.finding.confidence:.0%}")
        conf_lbl.setStyleSheet("color:#666666; font-size:9px;")
        conf_lbl.setToolTip(f"Confidence: {step.finding.confidence:.4f}")
        header.addWidget(conf_lbl)

        layout.addLayout(header)

        # ── Transform + rationale (shown for step_index > 0) ────────────
        if step_index > 0 and (step.transform or step.rationale):
            detail_row = QHBoxLayout()
            detail_row.setContentsMargins(24, 0, 0, 0)
            detail_row.setSpacing(4)

            if step.transform and step.transform != "Initial finding":
                tr_lbl = QLabel(f"↳ {step.transform}")
                tr_lbl.setFont(QFont("Courier", 8))
                tr_lbl.setStyleSheet(
                    "background:#e8e8e8; color:#333333; padding:2px 6px; border-radius:3px;"
                )
                tr_lbl.setToolTip(f"Transform: {step.transform}")
                detail_row.addWidget(tr_lbl)

            if step.rationale:
                rat_lbl = QLabel(step.rationale)
                rat_lbl.setFont(QFont("sans-serif", 8))
                rat_lbl.setStyleSheet("color:#555555;")
                rat_lbl.setWordWrap(True)
                rat_lbl.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
                detail_row.addWidget(rat_lbl, 1)

            layout.addLayout(detail_row)


# ---------------------------------------------------------------------------
# Chain card
# ---------------------------------------------------------------------------

class _ChainCard(QFrame):
    """Expandable card rendering one complete attack chain."""

    #: Emitted when the user clicks "Run Chain".
    #: Payload: (initial_detail, pipeline_configs list[dict])
    run_chain_requested = pyqtSignal(str, list)

    def __init__(self, chain: Chain, chain_index: int, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._chain = chain
        self._expanded = False

        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setStyleSheet(
            "QFrame { background:#f0f4ff; border:1px solid #b0b8d0; border-radius:5px; }"
        )

        self._outer = QVBoxLayout(self)
        self._outer.setContentsMargins(8, 6, 8, 6)
        self._outer.setSpacing(4)

        score = sum(s.finding.confidence for s in chain)

        # ── Header row ───────────────────────────────────────────────────
        header = QHBoxLayout()
        header.setSpacing(6)

        self._toggle_btn = QPushButton("▶")
        self._toggle_btn.setFixedSize(QSize(20, 20))
        self._toggle_btn.setFlat(True)
        self._toggle_btn.clicked.connect(self._toggle)
        header.addWidget(self._toggle_btn)

        # Chain index badge
        chain_badge = QLabel(f"Chain #{chain_index + 1}")
        chain_badge.setStyleSheet(
            "background:#3355aa; color:white; padding:3px 8px; "
            "border-radius:4px; font-weight:bold; font-size:11px;"
        )
        header.addWidget(chain_badge)

        # Score badge
        score_badge = QLabel(f"Score {score:.2f}")
        score_badge.setStyleSheet(
            "background:#226633; color:white; padding:3px 8px; border-radius:4px; font-size:10px;"
        )
        header.addWidget(score_badge)

        # Steps badge
        steps_badge = QLabel(f"{len(chain)} step(s)")
        steps_badge.setStyleSheet(
            "background:#666666; color:white; padding:3px 6px; border-radius:4px; font-size:10px;"
        )
        header.addWidget(steps_badge)

        # Summary: first and last file names
        if chain:
            src_name = Path(chain[0].file).name if chain[0].file else "?"
            dst_name = Path(chain[-1].file).name if chain[-1].file else "?"
            route_lbl = QLabel(f"{src_name} → … → {dst_name}" if len(chain) > 2 else f"{src_name} → {dst_name}")
            route_lbl.setStyleSheet("color:#333366; font-style:italic; font-size:10px;")
            route_lbl.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
            header.addWidget(route_lbl, 1)

        self._outer.addLayout(header)

        # ── Collapsible body ─────────────────────────────────────────────
        self._body = QWidget()
        body_layout = QVBoxLayout(self._body)
        body_layout.setContentsMargins(0, 4, 0, 4)
        body_layout.setSpacing(4)

        for idx, step in enumerate(chain):
            if idx > 0:
                # Arrow separator
                arrow_lbl = QLabel("▼")
                arrow_lbl.setAlignment(Qt.AlignmentFlag.AlignHCenter)
                arrow_lbl.setStyleSheet("color:#666666; font-size:14px;")
                body_layout.addWidget(arrow_lbl)

            step_panel = _StepPanel(step, idx)
            body_layout.addWidget(step_panel)

        # "Run Chain" button row
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        run_btn = QPushButton("▶  Run Chain")
        run_btn.setToolTip(
            "Execute this chain's transforms sequentially in the Transform Pipeline"
        )
        run_btn.setStyleSheet(
            "QPushButton { background:#225588; color:white; padding:5px 14px; "
            "border-radius:4px; font-weight:bold; }"
            "QPushButton:hover { background:#3366aa; }"
        )
        run_btn.clicked.connect(self._emit_run)
        btn_row.addWidget(run_btn)
        body_layout.addLayout(btn_row)

        self._body.setVisible(False)
        self._outer.addWidget(self._body)

    # ------------------------------------------------------------------

    def _toggle(self) -> None:
        self._expanded = not self._expanded
        self._toggle_btn.setText("▼" if self._expanded else "▶")
        self._body.setVisible(self._expanded)

    def _emit_run(self) -> None:
        """Emit run_chain_requested with initial data and pipeline config."""
        if not self._chain:
            return

        initial_data = self._chain[0].finding.detail or ""

        # Build pipeline node configs for steps 1..N (skip the starting finding)
        configs: list[dict] = []
        for step in self._chain[1:]:
            tr_name = step.transform
            # Skip descriptive-only transforms that don't map to pipeline operations
            if tr_name in _NON_EXECUTABLE_TRANSFORMS:
                continue
            configs.append({"transform": tr_name, "param": step.transform_param})

        self.run_chain_requested.emit(initial_data, configs)


# ---------------------------------------------------------------------------
# Main tab widget
# ---------------------------------------------------------------------------

class AttackChainsTab(QWidget):
    """Tab showing multi-stage cross-file attack chains as step-by-step card flows."""

    #: Re-emitted from child cards; connected in MainWindow to the pipeline.
    run_chain_requested = pyqtSignal(str, list)

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._chains: List[Chain] = []
        self._workspace: List[Tuple[str, List[Finding]]] = []
        self._key_registry: KeyRegistry = KeyRegistry()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        # ── Toolbar ──────────────────────────────────────────────────────
        toolbar = QHBoxLayout()
        toolbar.addWidget(QLabel("<b>⛓️ Attack Chains</b> — multi-stage cross-file attack paths"))
        toolbar.addStretch()

        self._refresh_btn = QPushButton("🔄 Refresh Chains")
        self._refresh_btn.setToolTip("Re-compute attack chains from the current workspace")
        self._refresh_btn.clicked.connect(self._refresh)
        toolbar.addWidget(self._refresh_btn)

        layout.addLayout(toolbar)

        # ── Scroll area for chain cards ───────────────────────────────────
        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        self._cards_container = QWidget()
        self._cards_layout = QVBoxLayout(self._cards_container)
        self._cards_layout.setContentsMargins(4, 4, 4, 4)
        self._cards_layout.setSpacing(10)
        self._cards_layout.addStretch()

        self._scroll.setWidget(self._cards_container)
        layout.addWidget(self._scroll, 1)

        # ── Status label ─────────────────────────────────────────────────
        self._status_lbl = QLabel(
            "No chains yet — analyse multiple files and click Refresh Chains."
        )
        self._status_lbl.setStyleSheet("color:#666666; font-style:italic;")
        layout.addWidget(self._status_lbl)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def update_session(self, session: Session) -> None:
        """Recompute chains whenever the session is updated."""
        # Build workspace from session findings grouped by file
        by_file: dict[str, list[Finding]] = {}
        for f in session.findings:
            by_file.setdefault(f.file, []).append(f)
        self._workspace = list(by_file.items())
        self._key_registry = session.key_registry
        self._refresh()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _refresh(self) -> None:
        if len(self._workspace) < 2:
            self._set_status("Need findings from at least 2 files to build attack chains.")
            self._clear_cards()
            return

        try:
            builder = ChainBuilder(self._workspace, self._key_registry)
            self._chains = builder.build()
        except Exception as exc:  # pragma: no cover
            self._set_status(
                f"Chain building failed with {len(self._workspace)} file(s): {exc}"
            )
            return

        self._rebuild_cards()

    def _clear_cards(self) -> None:
        """Remove all chain cards from the layout (keep trailing stretch)."""
        while self._cards_layout.count() > 1:
            item = self._cards_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def _rebuild_cards(self) -> None:
        self._clear_cards()

        if not self._chains:
            self._set_status(
                "No attack chains found — findings don't share correlated values across files."
            )
            return

        self._set_status(
            f"{len(self._chains)} chain(s) discovered — click ▶ on any card to expand."
        )

        for idx, chain in enumerate(self._chains):
            card = _ChainCard(chain, idx)
            card.run_chain_requested.connect(self.run_chain_requested)
            # Insert before the trailing stretch
            self._cards_layout.insertWidget(self._cards_layout.count() - 1, card)

    def _set_status(self, text: str) -> None:
        self._status_lbl.setText(text)
