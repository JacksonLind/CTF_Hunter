"""
Diff view window: side-by-side hex/text/metadata comparison of two files.
"""
from __future__ import annotations

import difflib
from pathlib import Path

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTextEdit, QLabel,
    QPushButton, QTabWidget, QWidget, QSplitter,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QColor, QTextCharFormat, QTextCursor

from core.external import run_exiftool


class DiffViewWindow(QDialog):
    def __init__(self, path_a: str, path_b: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Diff: {Path(path_a).name}  ←→  {Path(path_b).name}")
        self.resize(1100, 700)

        layout = QVBoxLayout(self)
        header = QHBoxLayout()
        header.addWidget(QLabel(f"A: {path_a}"))
        header.addStretch()
        header.addWidget(QLabel(f"B: {path_b}"))
        layout.addLayout(header)

        tabs = QTabWidget()

        # --- Hex diff ---
        tabs.addTab(self._make_hex_diff(path_a, path_b), "Hex Diff")

        # --- Text diff ---
        tabs.addTab(self._make_text_diff(path_a, path_b), "Text Diff")

        # --- Metadata diff ---
        tabs.addTab(self._make_meta_diff(path_a, path_b), "Metadata Diff")

        layout.addWidget(tabs)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.close)
        layout.addWidget(close_btn, alignment=Qt.AlignmentFlag.AlignRight)

    # ------------------------------------------------------------------

    def _make_hex_diff(self, path_a: str, path_b: str) -> QWidget:
        widget = QWidget()
        layout = QHBoxLayout(widget)
        split = QSplitter()

        left = QTextEdit()
        right = QTextEdit()
        left.setReadOnly(True)
        right.setReadOnly(True)
        left.setFont(QFont("Courier New", 9))
        right.setFont(QFont("Courier New", 9))
        left.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        right.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)

        try:
            data_a = Path(path_a).read_bytes()[:65536]
            data_b = Path(path_b).read_bytes()[:65536]
            hex_a = self._bytes_to_hex_lines(data_a)
            hex_b = self._bytes_to_hex_lines(data_b)

            diff = list(difflib.ndiff(hex_a, hex_b))
            lines_a: list[str] = []
            lines_b: list[str] = []
            colors_a: list[str] = []
            colors_b: list[str] = []
            for line in diff:
                if line.startswith("  "):
                    lines_a.append(line[2:])
                    lines_b.append(line[2:])
                    colors_a.append("")
                    colors_b.append("")
                elif line.startswith("- "):
                    lines_a.append(line[2:])
                    colors_a.append("#ffcccc")
                elif line.startswith("+ "):
                    lines_b.append(line[2:])
                    colors_b.append("#ccffcc")

            self._set_colored_text(left, lines_a, colors_a)
            self._set_colored_text(right, lines_b, colors_b)
        except Exception as exc:
            left.setPlainText(f"Error: {exc}")
            right.setPlainText(f"Error: {exc}")

        split.addWidget(left)
        split.addWidget(right)
        layout.addWidget(split)
        return widget

    def _make_text_diff(self, path_a: str, path_b: str) -> QWidget:
        widget = QWidget()
        layout = QHBoxLayout(widget)
        split = QSplitter()

        left = QTextEdit()
        right = QTextEdit()
        left.setReadOnly(True)
        right.setReadOnly(True)
        left.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        right.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)

        try:
            text_a = Path(path_a).read_text(errors="replace").splitlines()
            text_b = Path(path_b).read_text(errors="replace").splitlines()
            diff = list(difflib.unified_diff(text_a, text_b,
                                              fromfile=path_a, tofile=path_b, lineterm=""))
            left.setPlainText("\n".join(text_a))
            right.setPlainText("\n".join(diff))
        except Exception as exc:
            left.setPlainText(f"Error: {exc}")
            right.setPlainText(f"Error: {exc}")

        split.addWidget(left)
        split.addWidget(right)
        layout.addWidget(split)
        return widget

    def _make_meta_diff(self, path_a: str, path_b: str) -> QWidget:
        widget = QWidget()
        layout = QHBoxLayout(widget)
        split = QSplitter()

        left = QTextEdit()
        right = QTextEdit()
        left.setReadOnly(True)
        right.setReadOnly(True)

        try:
            meta_a = run_exiftool(path_a)
            meta_b = run_exiftool(path_b)
            left.setPlainText("\n".join(f"{k}: {v}" for k, v in sorted(meta_a.items())))
            right.setPlainText("\n".join(f"{k}: {v}" for k, v in sorted(meta_b.items())))
        except Exception as exc:
            left.setPlainText(f"Error: {exc}")
            right.setPlainText(f"Error: {exc}")

        split.addWidget(left)
        split.addWidget(right)
        layout.addWidget(split)
        return widget

    # ------------------------------------------------------------------

    def _bytes_to_hex_lines(self, data: bytes, bpr: int = 16) -> list[str]:
        lines = []
        for i in range(0, len(data), bpr):
            chunk = data[i:i + bpr]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in chunk)
            lines.append(f"{i:08x}  {hex_part:<{bpr*3-1}}  |{ascii_part}|")
        return lines

    def _set_colored_text(self, edit: QTextEdit, lines: list[str], colors: list[str]) -> None:
        edit.clear()
        cursor = edit.textCursor()
        for line, color in zip(lines, colors):
            fmt = QTextCharFormat()
            if color:
                fmt.setBackground(QColor(color))
            cursor.insertText(line + "\n", fmt)
        edit.setTextCursor(cursor)
