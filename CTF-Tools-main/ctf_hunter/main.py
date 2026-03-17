#!/usr/bin/env python3
"""
CTF Hunter — entry point.

GUI mode (default):
    python main.py

CLI mode (headless):
    python main.py --cli file.bin
    python main.py --cli --depth deep --format json challenge.png
    python main.py --cli --help
"""
from __future__ import annotations

import sys
import os

# Ensure ctf_hunter package root is on the path when running from the project directory
_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


_STYLESHEET = """
/* ── Global clean-up ──────────────────────────────────────────── */
QMainWindow, QWidget {
    font-size: 13px;
    background-color: #2b2b2b;
    color: #ffffff;
}

QToolBar {
    spacing: 4px;
    padding: 2px 4px;
    background-color: #2b2b2b;
    border: none;
}
QToolBar QLabel {
    padding: 0 2px;
    color: #ffffff;
}

QTabWidget::pane {
    border: 1px solid #555555;
    border-radius: 3px;
}
QTabBar::tab {
    padding: 5px 12px;
    margin-right: 2px;
    background-color: #3a3a3a;
    color: #ffffff;
    border: 1px solid #555555;
    border-bottom: none;
    border-radius: 3px 3px 0 0;
}
QTabBar::tab:selected {
    font-weight: bold;
    background-color: #2b2b2b;
}
QTabBar::tab:hover:!selected {
    background-color: #444444;
}

QTreeWidget {
    background-color: #2b2b2b;
    alternate-background-color: #323232;
    color: #ffffff;
}
QTreeWidget::item {
    padding: 2px 0;
}
QTreeWidget::item:selected {
    background-color: #1e4a7a;
}

QGroupBox {
    font-weight: bold;
    border: 1px solid #555555;
    border-radius: 4px;
    margin-top: 8px;
    padding-top: 14px;
    color: #ffffff;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 4px;
}

QTextEdit {
    background-color: #353535;
    color: #ffffff;
    border: 1px solid #555555;
    border-radius: 3px;
}
QTextEdit[readOnly="true"] {
    background-color: #323232;
    border: 1px solid #555555;
    border-radius: 3px;
}

QLineEdit {
    background-color: #353535;
    color: #ffffff;
    border: 1px solid #555555;
    border-radius: 3px;
    padding: 2px 4px;
}

QPushButton {
    padding: 4px 10px;
    border: 1px solid #555555;
    border-radius: 3px;
    background: #3d3d3d;
    color: #ffffff;
}
QPushButton:hover {
    background: #4a4a4a;
}
QPushButton:pressed {
    background: #252525;
}
QPushButton:checked {
    background: #1e4a7a;
    border-color: #5588bb;
}

QComboBox {
    padding: 3px 6px;
    border: 1px solid #555555;
    border-radius: 3px;
    background-color: #3d3d3d;
    color: #ffffff;
}
QComboBox QAbstractItemView {
    background-color: #3d3d3d;
    color: #ffffff;
    selection-background-color: #1e4a7a;
}

QScrollBar:vertical {
    background: #2b2b2b;
    width: 12px;
}
QScrollBar::handle:vertical {
    background: #555555;
    border-radius: 4px;
    min-height: 20px;
}
QScrollBar:horizontal {
    background: #2b2b2b;
    height: 12px;
}
QScrollBar::handle:horizontal {
    background: #555555;
    border-radius: 4px;
    min-width: 20px;
}

QSplitter::handle {
    background: #555555;
}
QSplitter::handle:horizontal {
    width: 3px;
}
QSplitter::handle:vertical {
    height: 3px;
}

QStatusBar {
    font-size: 11px;
    color: #cccccc;
    background-color: #222222;
}

QDockWidget {
    font-weight: bold;
    color: #ffffff;
}
QDockWidget::title {
    padding: 4px;
    background: #3a3a3a;
    color: #ffffff;
}

QMenuBar {
    background-color: #2b2b2b;
    color: #ffffff;
}
QMenuBar::item:selected {
    background-color: #3a3a3a;
}
QMenu {
    background-color: #2b2b2b;
    color: #ffffff;
    border: 1px solid #555555;
}
QMenu::item:selected {
    background-color: #1e4a7a;
}

QHeaderView::section {
    background-color: #3a3a3a;
    color: #ffffff;
    border: 1px solid #555555;
    padding: 4px;
}

QLabel {
    color: #ffffff;
}

QCheckBox {
    color: #ffffff;
}

QRadioButton {
    color: #ffffff;
}

QSpinBox, QDoubleSpinBox {
    background-color: #353535;
    color: #ffffff;
    border: 1px solid #555555;
    border-radius: 3px;
}
"""


def _run_gui() -> None:
    """Launch the full PyQt6 GUI."""
    from PyQt6.QtWidgets import QApplication
    from ui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("CTF Hunter")
    app.setOrganizationName("CTFTools")
    app.setStyle("Fusion")
    app.setStyleSheet(_STYLESHEET)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


def main() -> None:
    # Detect CLI mode: either explicit --cli flag or piped/redirected output
    if "--cli" in sys.argv:
        from cli import run_cli
        # Strip the --cli flag before passing to argparse
        argv = [a for a in sys.argv[1:] if a != "--cli"]
        sys.exit(run_cli(argv))
    else:
        _run_gui()


if __name__ == "__main__":
    main()
