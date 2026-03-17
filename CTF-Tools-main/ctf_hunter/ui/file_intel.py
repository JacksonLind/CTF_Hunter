"""
File Intel tab: hashes, entropy visualisation, strings extractor, and a
decode playground for the currently selected file.
"""
from __future__ import annotations

import hashlib
import math
import re
import string
import urllib.parse
import binascii
import base64
from pathlib import Path
from typing import Optional

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QTextEdit, QSpinBox, QGroupBox, QScrollArea, QSizePolicy,
    QApplication, QTabWidget,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QObject
from PyQt6.QtGui import QFont, QColor

# Pre-computed set of printable byte values (used in strings extraction)
_PRINTABLE_BYTES: frozenset[int] = frozenset(string.printable.encode())


# ---------------------------------------------------------------------------
# Background worker for hash computation (avoids blocking the UI thread)
# ---------------------------------------------------------------------------

class _HashWorkerSignals(QObject):
    done = pyqtSignal(str, str, str, str, str)   # md5, sha1, sha256, sha512, path


class _HashWorker(QThread):
    def __init__(self, path: str):
        super().__init__()
        self._path = path
        self.signals = _HashWorkerSignals()

    def run(self) -> None:
        try:
            md5 = hashlib.md5()
            sha1 = hashlib.sha1()
            sha256 = hashlib.sha256()
            sha512 = hashlib.sha512()
            with open(self._path, "rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    md5.update(chunk)
                    sha1.update(chunk)
                    sha256.update(chunk)
                    sha512.update(chunk)
            self.signals.done.emit(
                md5.hexdigest(),
                sha1.hexdigest(),
                sha256.hexdigest(),
                sha512.hexdigest(),
                self._path,
            )
        except Exception as exc:
            self.signals.done.emit(str(exc), "", "", "", self._path)


# ---------------------------------------------------------------------------
# File Intel tab
# ---------------------------------------------------------------------------

class FileIntelTab(QWidget):
    """
    Multi-section tab for rapid file intelligence:

    * **Hashes** – MD5 / SHA-1 / SHA-256 / SHA-512, each with a ⧉ copy button.
    * **Entropy** – Shannon entropy per 256-byte block, rendered as an ASCII
      bar chart inside a scrollable text widget; overall file entropy shown
      alongside a plain-English randomness verdict.
    * **Strings** – Extract printable strings with a configurable minimum
      length; output is copyable in full.
    * **Decode Playground** – Paste arbitrary text and try Base64, Base32,
      hex, URL-encoding, and ROT-13 in one click.
    """

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._file_path: str = ""
        self._hash_worker: Optional[_HashWorker] = None

        outer = QVBoxLayout(self)
        outer.setContentsMargins(6, 6, 6, 6)

        inner_tabs = QTabWidget()
        inner_tabs.addTab(self._build_hash_section(),    "🔑 Hashes")
        inner_tabs.addTab(self._build_entropy_section(), "📊 Entropy")
        inner_tabs.addTab(self._build_strings_section(), "🧵 Strings")
        inner_tabs.addTab(self._build_decode_section(),  "🔓 Decode")
        outer.addWidget(inner_tabs)

    # ------------------------------------------------------------------
    # Hash section
    # ------------------------------------------------------------------

    def _build_hash_section(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        self._hash_file_label = QLabel("No file selected")
        self._hash_file_label.setStyleSheet("font-style: italic; color: #888;")
        layout.addWidget(self._hash_file_label)

        self._compute_hashes_btn = QPushButton("🔑 Compute Hashes")
        self._compute_hashes_btn.setEnabled(False)
        self._compute_hashes_btn.clicked.connect(self._compute_hashes)
        layout.addWidget(self._compute_hashes_btn)

        self._hash_rows: dict[str, QLineEdit] = {}
        for alg in ("MD5", "SHA-1", "SHA-256", "SHA-512"):
            row = QHBoxLayout()
            lbl = QLabel(f"{alg}:")
            lbl.setFixedWidth(72)
            lbl.setFont(QFont("Courier", 9))
            row.addWidget(lbl)
            le = QLineEdit()
            le.setReadOnly(True)
            le.setFont(QFont("Courier", 9))
            le.setPlaceholderText("(not computed)")
            row.addWidget(le)
            copy_btn = QPushButton("⧉")
            copy_btn.setFixedWidth(28)
            copy_btn.setToolTip(f"Copy {alg} hash")
            alg_key = alg  # capture for lambda
            copy_btn.clicked.connect(lambda _, k=alg_key: self._copy_hash(k))
            row.addWidget(copy_btn)
            layout.addLayout(row)
            self._hash_rows[alg] = le

        layout.addStretch()
        return w

    # ------------------------------------------------------------------
    # Entropy section
    # ------------------------------------------------------------------

    def _build_entropy_section(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        header = QHBoxLayout()
        self._entropy_label = QLabel("Overall entropy: —")
        self._entropy_label.setFont(QFont("", 10, QFont.Weight.Bold))
        header.addWidget(self._entropy_label)
        header.addStretch()
        calc_btn = QPushButton("📊 Calculate Entropy")
        calc_btn.clicked.connect(self._calculate_entropy)
        header.addWidget(calc_btn)
        layout.addLayout(header)

        self._verdict_label = QLabel("")
        self._verdict_label.setWordWrap(True)
        layout.addWidget(self._verdict_label)

        self._entropy_view = QTextEdit()
        self._entropy_view.setReadOnly(True)
        self._entropy_view.setFont(QFont("Courier", 8))
        self._entropy_view.setPlaceholderText(
            "Select a file and click 'Calculate Entropy' to visualise byte entropy."
        )
        layout.addWidget(self._entropy_view)
        return w

    # ------------------------------------------------------------------
    # Strings section
    # ------------------------------------------------------------------

    def _build_strings_section(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        ctrl = QHBoxLayout()
        ctrl.addWidget(QLabel("Min length:"))
        self._strings_min_len = QSpinBox()
        self._strings_min_len.setRange(3, 128)
        self._strings_min_len.setValue(6)
        ctrl.addWidget(self._strings_min_len)
        ctrl.addWidget(QLabel("  Filter regex (optional):"))
        self._strings_filter = QLineEdit()
        self._strings_filter.setPlaceholderText("e.g. flag|CTF|pass")
        ctrl.addWidget(self._strings_filter)
        extract_btn = QPushButton("🧵 Extract Strings")
        extract_btn.clicked.connect(self._extract_strings)
        ctrl.addWidget(extract_btn)
        copy_all_btn = QPushButton("⧉ Copy All")
        copy_all_btn.clicked.connect(self._copy_strings)
        ctrl.addWidget(copy_all_btn)
        layout.addLayout(ctrl)

        self._strings_count_label = QLabel("")
        layout.addWidget(self._strings_count_label)

        self._strings_view = QTextEdit()
        self._strings_view.setReadOnly(True)
        self._strings_view.setFont(QFont("Courier", 9))
        self._strings_view.setPlaceholderText(
            "Select a file and click 'Extract Strings'."
        )
        layout.addWidget(self._strings_view)
        return w

    # ------------------------------------------------------------------
    # Decode playground
    # ------------------------------------------------------------------

    def _build_decode_section(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        layout.addWidget(QLabel("Paste text to decode:"))
        self._decode_input = QTextEdit()
        self._decode_input.setMaximumHeight(80)
        self._decode_input.setPlaceholderText("Paste ciphertext / encoded text here…")
        layout.addWidget(self._decode_input)

        btn_row = QHBoxLayout()
        for label, fn in (
            ("Base64",  self._decode_b64),
            ("Base32",  self._decode_b32),
            ("Hex",     self._decode_hex),
            ("URL",     self._decode_url),
            ("ROT-13",  self._decode_rot13),
            ("XOR key?",self._decode_xor),
        ):
            btn = QPushButton(label)
            btn.clicked.connect(fn)
            btn_row.addWidget(btn)
        layout.addLayout(btn_row)

        layout.addWidget(QLabel("Output:"))
        self._decode_output = QTextEdit()
        self._decode_output.setReadOnly(True)
        self._decode_output.setFont(QFont("Courier", 9))
        layout.addWidget(self._decode_output)

        # XOR key row
        xor_row = QHBoxLayout()
        xor_row.addWidget(QLabel("XOR key (hex byte, e.g. 0x41):"))
        self._xor_key_edit = QLineEdit()
        self._xor_key_edit.setPlaceholderText("0x41")
        self._xor_key_edit.setMaximumWidth(100)
        xor_row.addWidget(self._xor_key_edit)
        xor_row.addStretch()
        layout.addLayout(xor_row)

        copy_output_btn = QPushButton("⧉ Copy Output")
        copy_output_btn.clicked.connect(self._copy_decode_output)
        layout.addWidget(copy_output_btn)

        return w

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load_file(self, path: str) -> None:
        """Called by the main window when the user selects a different file."""
        self._file_path = path
        name = Path(path).name if path else "No file selected"
        self._hash_file_label.setText(name)
        self._compute_hashes_btn.setEnabled(bool(path))

        # Reset hash fields on new file selection
        for le in self._hash_rows.values():
            le.clear()
            le.setPlaceholderText("(not computed)")

        self._entropy_label.setText("Overall entropy: —")
        self._verdict_label.setText("")
        self._entropy_view.clear()
        self._strings_view.clear()
        self._strings_count_label.setText("")

    # ------------------------------------------------------------------
    # Hash implementation
    # ------------------------------------------------------------------

    def _compute_hashes(self) -> None:
        if not self._file_path:
            return
        for le in self._hash_rows.values():
            le.setPlaceholderText("Computing…")
        self._compute_hashes_btn.setEnabled(False)

        self._hash_worker = _HashWorker(self._file_path)
        self._hash_worker.signals.done.connect(self._on_hashes_done)
        self._hash_worker.start()

    def _on_hashes_done(self, md5: str, sha1: str, sha256: str, sha512: str, path: str) -> None:
        if path != self._file_path:
            return  # stale result
        self._hash_rows["MD5"].setText(md5)
        self._hash_rows["SHA-1"].setText(sha1)
        self._hash_rows["SHA-256"].setText(sha256)
        self._hash_rows["SHA-512"].setText(sha512)
        self._compute_hashes_btn.setEnabled(True)

    def _copy_hash(self, alg: str) -> None:
        text = self._hash_rows[alg].text()
        if text:
            QApplication.clipboard().setText(text)

    # ------------------------------------------------------------------
    # Entropy implementation
    # ------------------------------------------------------------------

    def _calculate_entropy(self) -> None:
        if not self._file_path:
            return
        try:
            data = Path(self._file_path).read_bytes()
        except Exception as exc:
            self._entropy_view.setPlainText(f"Error reading file: {exc}")
            return

        overall = _shannon_entropy(data)
        self._entropy_label.setText(f"Overall entropy: {overall:.4f} bits/byte")

        verdict = _entropy_verdict(overall)
        self._verdict_label.setText(verdict)

        # Block-level entropy visualisation (256-byte blocks)
        block_size = 256
        lines: list[str] = []
        lines.append(
            f"Block entropy ({block_size}-byte blocks)  —  "
            f"overall: {overall:.4f} bits/byte\n"
            f"{'Offset':<10}  {'Entropy':>7}  Bar"
        )
        lines.append("─" * 60)
        for i in range(0, len(data), block_size):
            chunk = data[i: i + block_size]
            ent = _shannon_entropy(chunk)
            bar_len = int(ent / 8.0 * 40)
            bar = "█" * bar_len + "░" * (40 - bar_len)
            lines.append(f"0x{i:<8x}  {ent:>6.3f}  {bar}")

        self._entropy_view.setPlainText("\n".join(lines))

    # ------------------------------------------------------------------
    # Strings implementation
    # ------------------------------------------------------------------

    def _extract_strings(self) -> None:
        if not self._file_path:
            return
        try:
            data = Path(self._file_path).read_bytes()
        except Exception as exc:
            self._strings_view.setPlainText(f"Error reading file: {exc}")
            return

        min_len = self._strings_min_len.value()
        pattern_text = self._strings_filter.text().strip()
        try:
            filter_re = re.compile(pattern_text, re.IGNORECASE) if pattern_text else None
        except re.error:
            filter_re = None

        printable = _PRINTABLE_BYTES
        results: list[str] = []
        buf: list[int] = []

        for byte in data:
            if byte in printable:
                buf.append(byte)
            else:
                if len(buf) >= min_len:
                    s = bytes(buf).decode("ascii", errors="replace")
                    if filter_re is None or filter_re.search(s):
                        results.append(s)
                buf = []
        if len(buf) >= min_len:
            s = bytes(buf).decode("ascii", errors="replace")
            if filter_re is None or filter_re.search(s):
                results.append(s)

        self._strings_count_label.setText(
            f"{len(results)} string(s) found "
            f"(min length {min_len}"
            + (f", filter '{pattern_text}'" if pattern_text else "")
            + ")"
        )
        self._strings_view.setPlainText("\n".join(results))

    def _copy_strings(self) -> None:
        QApplication.clipboard().setText(self._strings_view.toPlainText())

    # ------------------------------------------------------------------
    # Decode playground
    # ------------------------------------------------------------------

    def _input_text(self) -> str:
        return self._decode_input.toPlainText().strip()

    def _set_output(self, text: str) -> None:
        self._decode_output.setPlainText(text)

    def _decode_b64(self) -> None:
        raw = self._input_text()
        try:
            padded = raw + "=" * (-len(raw) % 4)
            result = base64.b64decode(padded).decode("utf-8", errors="replace")
            self._set_output(result)
        except Exception as exc:
            self._set_output(f"Base64 decode error: {exc}")

    def _decode_b32(self) -> None:
        raw = self._input_text().upper()
        try:
            padded = raw + "=" * (-len(raw) % 8)
            result = base64.b32decode(padded).decode("utf-8", errors="replace")
            self._set_output(result)
        except Exception as exc:
            self._set_output(f"Base32 decode error: {exc}")

    def _decode_hex(self) -> None:
        raw = self._input_text().replace(" ", "").replace("0x", "")
        try:
            result = binascii.unhexlify(raw).decode("utf-8", errors="replace")
            self._set_output(result)
        except Exception as exc:
            self._set_output(f"Hex decode error: {exc}")

    def _decode_url(self) -> None:
        raw = self._input_text()
        try:
            result = urllib.parse.unquote_plus(raw)
            self._set_output(result)
        except Exception as exc:
            self._set_output(f"URL decode error: {exc}")

    def _decode_rot13(self) -> None:
        raw = self._input_text()
        result = raw.translate(
            str.maketrans(
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
            )
        )
        self._set_output(result)

    def _decode_xor(self) -> None:
        raw = self._input_text()
        key_text = self._xor_key_edit.text().strip()
        try:
            key_byte = int(key_text, 16)
        except Exception:
            self._set_output("XOR: provide a valid hex key byte (e.g. 0x41 or 41).")
            return
        try:
            # Treat input as hex bytes if it looks like it, else as raw text
            cleaned = raw.replace(" ", "").replace(":", "")
            if all(c in "0123456789abcdefABCDEF" for c in cleaned) and len(cleaned) % 2 == 0:
                data = binascii.unhexlify(cleaned)
            else:
                data = raw.encode("latin-1", errors="replace")
            xored = bytes(b ^ key_byte for b in data)
            self._set_output(xored.decode("latin-1", errors="replace"))
        except Exception as exc:
            self._set_output(f"XOR error: {exc}")

    def _copy_decode_output(self) -> None:
        QApplication.clipboard().setText(self._decode_output.toPlainText())


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def _shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy of *data* in bits per byte (0.0 – 8.0)."""
    if not data:
        return 0.0
    freq: dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    total = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def _entropy_verdict(entropy: float) -> str:
    if entropy < 1.0:
        return "⬜ Very low entropy — likely sparse / mostly-null data."
    if entropy < 3.5:
        return "🟦 Low entropy — structured text, source code, or data with repeated patterns."
    if entropy < 6.0:
        return "🟩 Medium entropy — typical binary or mixed data."
    if entropy < 7.2:
        return "🟧 High entropy — compressed data, encrypted content, or packed binary."
    return "🟥 Very high entropy — likely encrypted, compressed, or random data (possible steganography payload)."
