"""
Hex viewer widget: displays binary data with offset annotations and
highlighted positions for finding offsets and flag pattern hits.
"""
from __future__ import annotations

from PyQt6.QtWidgets import QPlainTextEdit, QWidget, QVBoxLayout, QLabel
from PyQt6.QtGui import QFont, QTextCharFormat, QColor, QTextCursor
from PyQt6.QtCore import Qt


class HexViewer(QWidget):
    """Displays file bytes in hex + ASCII with highlighted offsets."""

    BYTES_PER_ROW = 16

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self._label = QLabel("Hex Viewer")
        self._label.setStyleSheet("font-weight: bold; padding: 2px;")
        layout.addWidget(self._label)

        self._text = QPlainTextEdit()
        self._text.setReadOnly(True)
        self._text.setFont(QFont("Courier New", 9))
        self._text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        layout.addWidget(self._text)

        self._data: bytes = b""
        self._highlights: list[tuple[int, int, str]] = []  # (offset, length, color)

    def load_file(self, path: str, max_bytes: int = 1024 * 256) -> None:
        try:
            with open(path, "rb") as fh:
                self._data = fh.read(max_bytes)
            self._label.setText(f"Hex Viewer — {path}  ({len(self._data)} bytes shown)")
        except Exception as exc:
            self._data = b""
            self._label.setText(f"Hex Viewer — Error: {exc}")
        self._highlights = []
        self._render()

    def load_bytes(self, data: bytes, label: str = "") -> None:
        self._data = data
        self._highlights = []
        self._label.setText(f"Hex Viewer {label}")
        self._render()

    def highlight_offset(self, offset: int, length: int = 16, color: str = "#FFD700") -> None:
        """Add a highlight region and re-render."""
        self._highlights.append((offset, length, color))
        self._render()

    def jump_to_offset(self, offset: int) -> None:
        """Scroll to the line containing the given byte offset."""
        if not self._data or offset < 0:
            return
        row = offset // self.BYTES_PER_ROW
        cursor = self._text.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.Start)
        for _ in range(row):
            cursor.movePosition(QTextCursor.MoveOperation.Down)
        self._text.setTextCursor(cursor)
        self._text.ensureCursorVisible()

    def _render(self) -> None:
        rows: list[str] = []
        for row_start in range(0, len(self._data), self.BYTES_PER_ROW):
            row_bytes = self._data[row_start:row_start + self.BYTES_PER_ROW]
            hex_part = " ".join(f"{b:02x}" for b in row_bytes)
            hex_part = hex_part.ljust(self.BYTES_PER_ROW * 3 - 1)
            ascii_part = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in row_bytes)
            rows.append(f"{row_start:08x}  {hex_part}  |{ascii_part}|")

        self._text.setPlainText("\n".join(rows))

        # Apply highlights
        doc = self._text.document()
        cursor = QTextCursor(doc)
        for (off, length, color) in self._highlights:
            if off < 0 or off >= len(self._data):
                continue
            row = off // self.BYTES_PER_ROW
            col_in_row = off % self.BYTES_PER_ROW
            # Position within hex section: offset 10 + col*3
            char_pos_hex = row * (10 + self.BYTES_PER_ROW * 3 + 2 + self.BYTES_PER_ROW + 3) + 10 + col_in_row * 3
            fmt = QTextCharFormat()
            fmt.setBackground(QColor(color))
            cursor.setPosition(char_pos_hex)
            cursor.movePosition(QTextCursor.MoveOperation.Right,
                                QTextCursor.MoveMode.KeepAnchor,
                                min(length, self.BYTES_PER_ROW - col_in_row) * 3)
            cursor.mergeCharFormat(fmt)
