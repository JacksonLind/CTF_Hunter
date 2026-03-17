"""
Transform Pipeline panel for CTF Hunter.

A dockable panel with a vertical chain of transform nodes. Each node has:
  - Input display (hex + ASCII)
  - Transform selector dropdown
  - Parameter field
  - Output display

The output of each node feeds the next node's input automatically.

Supported transforms:
  base64 encode/decode, hex encode/decode, XOR (key input), ROT-N,
  zlib compress/decompress, AES-ECB/CBC decrypt (key + IV input),
  reverse bytes, integer base conversion, URL encode/decode,
  custom regex extract.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
import urllib.parse
import zlib
from typing import Callable, List, Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QComboBox,
    QDockWidget,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

# ---------------------------------------------------------------------------
# Optional AES support
# ---------------------------------------------------------------------------
try:
    from Crypto.Cipher import AES as _AES
    _AES_AVAILABLE = True
except ImportError:
    _AES_AVAILABLE = False


# ---------------------------------------------------------------------------
# Transform operations
# ---------------------------------------------------------------------------

def _b64_encode(data: bytes, _param: str) -> bytes:
    return base64.b64encode(data)


def _b64_decode(data: bytes, _param: str) -> bytes:
    padded = data + b"=" * (4 - len(data) % 4)
    return base64.b64decode(padded, validate=False)


def _hex_encode(data: bytes, _param: str) -> bytes:
    return data.hex().encode("ascii")


def _hex_decode(data: bytes, _param: str) -> bytes:
    clean = re.sub(rb"\s+", b"", data)
    return bytes.fromhex(clean.decode("ascii"))


def _xor(data: bytes, param: str) -> bytes:
    try:
        key = bytes.fromhex(param) if re.fullmatch(r"[0-9a-fA-F]+", param) else param.encode("utf-8")
    except Exception:
        key = param.encode("utf-8") or b"\x00"
    if not key:
        key = b"\x00"
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def _rot_n(data: bytes, param: str) -> bytes:
    try:
        n = int(param) % 26
    except Exception:
        n = 13
    result = bytearray()
    for b in data:
        if 65 <= b <= 90:
            result.append((b - 65 + n) % 26 + 65)
        elif 97 <= b <= 122:
            result.append((b - 97 + n) % 26 + 97)
        else:
            result.append(b)
    return bytes(result)


def _zlib_compress(data: bytes, _param: str) -> bytes:
    return zlib.compress(data)


def _zlib_decompress(data: bytes, _param: str) -> bytes:
    try:
        return zlib.decompress(data)
    except zlib.error:
        return zlib.decompress(data, -15)  # raw deflate fallback


def _aes_ecb_decrypt(data: bytes, param: str) -> bytes:
    # NOTE: AES-ECB is intentionally included as a CTF analysis/decryption transform
    # for challenge data. It is *not* intended for production cryptographic use.
    if not _AES_AVAILABLE:
        raise RuntimeError("pycryptodome not installed — AES unavailable")
    key = bytes.fromhex(param) if re.fullmatch(r"[0-9a-fA-F]+", param) else param.encode("utf-8")
    cipher = _AES.new(key, _AES.MODE_ECB)  # nosec B501 — CTF analysis tool
    return cipher.decrypt(data)


def _aes_cbc_decrypt(data: bytes, param: str) -> bytes:
    if not _AES_AVAILABLE:
        raise RuntimeError("pycryptodome not installed — AES unavailable")
    parts = param.split(",", 1)
    key_hex = parts[0].strip()
    iv_hex = parts[1].strip() if len(parts) > 1 else "0" * 32
    key = bytes.fromhex(key_hex)
    iv = bytes.fromhex(iv_hex)
    cipher = _AES.new(key, _AES.MODE_CBC, iv)
    return cipher.decrypt(data)


def _reverse_bytes(data: bytes, _param: str) -> bytes:
    return data[::-1]


def _int_base_convert(data: bytes, param: str) -> bytes:
    parts = param.split(",")
    from_base = int(parts[0].strip()) if parts else 10
    to_base = int(parts[1].strip()) if len(parts) > 1 else 16
    text = data.decode("utf-8", errors="replace").strip()
    n = int(text, from_base)
    if to_base == 16:
        result = hex(n)
    elif to_base == 2:
        result = bin(n)
    elif to_base == 8:
        result = oct(n)
    else:
        # Generic base conversion
        digits = []
        while n:
            digits.append(n % to_base)
            n //= to_base
        result = "".join(str(d) for d in reversed(digits)) or "0"
    return result.encode("ascii")


def _url_encode(data: bytes, _param: str) -> bytes:
    return urllib.parse.quote_from_bytes(data).encode("ascii")


def _url_decode(data: bytes, _param: str) -> bytes:
    return urllib.parse.unquote_to_bytes(data.decode("ascii", errors="replace"))


def _regex_extract(data: bytes, param: str) -> bytes:
    text = data.decode("utf-8", errors="replace")
    pattern = param or r"[A-Za-z0-9+/=]{8,}"
    matches = re.findall(pattern, text)
    return "\n".join(matches).encode("utf-8")


# ---------------------------------------------------------------------------
# Transform registry
# ---------------------------------------------------------------------------

TRANSFORMS: list[tuple[str, Callable[[bytes, str], bytes], str]] = [
    ("Base64 Decode",         _b64_decode,         ""),
    ("Base64 Encode",         _b64_encode,         ""),
    ("Hex Decode",            _hex_decode,         ""),
    ("Hex Encode",            _hex_encode,         ""),
    ("XOR",                   _xor,                "key (hex or text)"),
    ("ROT-N",                 _rot_n,              "N (default 13)"),
    ("Zlib Decompress",       _zlib_decompress,    ""),
    ("Zlib Compress",         _zlib_compress,      ""),
    ("AES-ECB Decrypt",       _aes_ecb_decrypt,    "key (hex)"),
    ("AES-CBC Decrypt",       _aes_cbc_decrypt,    "key_hex,iv_hex"),
    ("Reverse Bytes",         _reverse_bytes,      ""),
    ("Int Base Convert",      _int_base_convert,   "from_base,to_base"),
    ("URL Decode",            _url_decode,         ""),
    ("URL Encode",            _url_encode,         ""),
    ("Regex Extract",         _regex_extract,      "regex pattern"),
]

_TRANSFORM_NAMES = [t[0] for t in TRANSFORMS]
_TRANSFORM_MAP = {t[0]: t[1] for t in TRANSFORMS}
_TRANSFORM_HINT = {t[0]: t[2] for t in TRANSFORMS}


# ---------------------------------------------------------------------------
# Transform Node widget
# ---------------------------------------------------------------------------

def _to_hex_ascii(data: bytes, max_bytes: int = 256) -> str:
    """Format bytes as 'hex  |  ASCII' display."""
    chunk = data[:max_bytes]
    hex_part = " ".join(f"{b:02x}" for b in chunk)
    ascii_part = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in chunk)
    suffix = f"\n… ({len(data)} bytes total)" if len(data) > max_bytes else ""
    return f"HEX:   {hex_part}\nASCII: {ascii_part}{suffix}"


class TransformNode(QFrame):
    """A single node in the transform chain."""

    output_changed = pyqtSignal()  # emitted when output data changes

    def __init__(self, index: int, parent=None) -> None:
        super().__init__(parent)
        self._index = index
        self._input_data: bytes = b""
        self._output_data: bytes = b""

        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)

        # Header
        header = QHBoxLayout()
        header.addWidget(QLabel(f"Node {index + 1}"))
        self._del_btn = QPushButton("✕")
        self._del_btn.setFixedWidth(28)
        self._del_btn.setToolTip("Remove this node")
        header.addStretch()
        header.addWidget(self._del_btn)
        layout.addLayout(header)

        # Input display
        layout.addWidget(QLabel("Input:"))
        self._input_display = QTextEdit()
        self._input_display.setReadOnly(True)
        self._input_display.setMaximumHeight(70)
        self._input_display.setFont(QFont("Courier", 8))
        layout.addWidget(self._input_display)

        # Transform selector + parameter
        ctrl = QHBoxLayout()
        self._transform_combo = QComboBox()
        self._transform_combo.addItems(_TRANSFORM_NAMES)
        self._transform_combo.currentTextChanged.connect(self._on_transform_changed)
        ctrl.addWidget(self._transform_combo, 2)
        self._param_edit = QLineEdit()
        self._param_edit.setPlaceholderText("parameter…")
        self._param_edit.textChanged.connect(self._run_transform)
        ctrl.addWidget(self._param_edit, 1)
        run_btn = QPushButton("▶")
        run_btn.setFixedWidth(28)
        run_btn.setToolTip("Run transform")
        run_btn.clicked.connect(self._run_transform)
        ctrl.addWidget(run_btn)
        layout.addLayout(ctrl)

        # Output display
        layout.addWidget(QLabel("Output:"))
        self._output_display = QTextEdit()
        self._output_display.setReadOnly(True)
        self._output_display.setMaximumHeight(70)
        self._output_display.setFont(QFont("Courier", 8))
        layout.addWidget(self._output_display)

        # Error label
        self._error_label = QLabel("")
        self._error_label.setStyleSheet("color: red;")
        layout.addWidget(self._error_label)

        self.setFrameShape(QFrame.Shape.Box)
        self._on_transform_changed(self._transform_combo.currentText())

    def set_input(self, data: bytes) -> None:
        self._input_data = data
        self._input_display.setPlainText(_to_hex_ascii(data))
        self._run_transform()

    def output_data(self) -> bytes:
        return self._output_data

    def to_config(self) -> dict:
        return {
            "transform": self._transform_combo.currentText(),
            "param": self._param_edit.text(),
        }

    def from_config(self, cfg: dict) -> None:
        idx = self._transform_combo.findText(cfg.get("transform", ""))
        if idx >= 0:
            self._transform_combo.setCurrentIndex(idx)
        self._param_edit.setText(cfg.get("param", ""))

    # ------------------------------------------------------------------

    def _on_transform_changed(self, name: str) -> None:
        hint = _TRANSFORM_HINT.get(name, "")
        self._param_edit.setPlaceholderText(hint or "parameter…")
        self._run_transform()

    def _run_transform(self) -> None:
        name = self._transform_combo.currentText()
        fn = _TRANSFORM_MAP.get(name)
        if fn is None:
            return
        param = self._param_edit.text()
        try:
            self._output_data = fn(self._input_data, param)
            self._error_label.setText("")
        except Exception as exc:
            self._output_data = self._input_data  # passthrough on error
            self._error_label.setText(f"Error: {exc}")
        self._output_display.setPlainText(_to_hex_ascii(self._output_data))
        self.output_changed.emit()


# ---------------------------------------------------------------------------
# Transform Pipeline panel
# ---------------------------------------------------------------------------

class TransformPipelinePanel(QWidget):
    """
    Dockable transform pipeline panel.  Load as a QDockWidget:

        dock = QDockWidget("Transform Pipeline", parent)
        panel = TransformPipelinePanel()
        dock.setWidget(panel)
    """

    hypothesis_requested = pyqtSignal(str, str)  # (final_output_text, transforms_applied)

    def __init__(self, ai_client=None, parent=None) -> None:
        super().__init__(parent)
        self._ai_client = ai_client
        self._nodes: List[TransformNode] = []

        outer = QVBoxLayout(self)
        outer.setContentsMargins(4, 4, 4, 4)

        # Toolbar
        toolbar = QHBoxLayout()
        add_btn = QPushButton("+ Add Node")
        add_btn.clicked.connect(self._add_node)
        toolbar.addWidget(add_btn)

        clear_btn = QPushButton("Clear All")
        clear_btn.clicked.connect(self._clear_nodes)
        toolbar.addWidget(clear_btn)

        save_btn = QPushButton("💾 Save Pipeline")
        save_btn.clicked.connect(self._save_pipeline)
        toolbar.addWidget(save_btn)

        load_btn = QPushButton("📂 Load Pipeline")
        load_btn.clicked.connect(self._load_pipeline)
        toolbar.addWidget(load_btn)

        hyp_btn = QPushButton("🤔 Run as Hypothesis")
        hyp_btn.setToolTip("Submit final output to AI client with transform context")
        hyp_btn.clicked.connect(self._run_as_hypothesis)
        toolbar.addWidget(hyp_btn)

        toolbar.addStretch()
        outer.addLayout(toolbar)

        # Input area (top-level text entry)
        outer.addWidget(QLabel("Pipeline Input (paste text or load from finding):"))
        self._input_edit = QTextEdit()
        self._input_edit.setPlaceholderText("Paste encoded data here, or use 'Pin finding' button in results…")
        self._input_edit.setMaximumHeight(60)
        self._input_edit.textChanged.connect(self._on_input_changed)
        outer.addWidget(self._input_edit)

        # Scrollable node chain
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        self._chain_widget = QWidget()
        self._chain_layout = QVBoxLayout(self._chain_widget)
        self._chain_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        scroll.setWidget(self._chain_widget)
        outer.addWidget(scroll, 1)

        # Add first node by default
        self._add_node()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load_finding(self, raw_text: str) -> None:
        """Load a finding's raw content into the pipeline's first node."""
        self._input_edit.setPlainText(raw_text)

    def get_pipeline_config(self) -> list[dict]:
        """Return the current pipeline configuration as a list of node configs."""
        return [n.to_config() for n in self._nodes]

    def set_pipeline_config(self, configs: list[dict]) -> None:
        """Restore a pipeline from a list of node configs."""
        self._clear_nodes()
        for cfg in configs:
            self._add_node(cfg)

    # ------------------------------------------------------------------
    # Node management
    # ------------------------------------------------------------------

    def _add_node(self, config: Optional[dict] = None) -> None:
        idx = len(self._nodes)
        node = TransformNode(idx, self)
        if config:
            node.from_config(config)
        node._del_btn.clicked.connect(lambda: self._remove_node(node))
        node.output_changed.connect(self._on_node_output_changed)
        self._nodes.append(node)
        self._chain_layout.addWidget(node)
        self._propagate_from(len(self._nodes) - 1)

    def _remove_node(self, node: TransformNode) -> None:
        if node in self._nodes:
            idx = self._nodes.index(node)
            self._nodes.pop(idx)
            self._chain_layout.removeWidget(node)
            node.deleteLater()
            self._propagate_from(idx)

    def _clear_nodes(self) -> None:
        for node in list(self._nodes):
            self._chain_layout.removeWidget(node)
            node.deleteLater()
        self._nodes.clear()

    # ------------------------------------------------------------------
    # Data flow
    # ------------------------------------------------------------------

    def _on_input_changed(self) -> None:
        self._propagate_from(0)

    def _on_node_output_changed(self) -> None:
        sending_node = self.sender()
        if sending_node in self._nodes:
            idx = self._nodes.index(sending_node)
            self._propagate_from(idx + 1)

    def _propagate_from(self, start_idx: int) -> None:
        """Feed output of node[start_idx-1] into node[start_idx] and onwards."""
        if not self._nodes:
            return
        if start_idx == 0:
            # First node gets pipeline input
            raw = self._input_edit.toPlainText().encode("utf-8", errors="replace")
        else:
            if start_idx > len(self._nodes):
                return
            raw = self._nodes[start_idx - 1].output_data()

        for i in range(start_idx, len(self._nodes)):
            self._nodes[i].set_input(raw)
            raw = self._nodes[i].output_data()

    # ------------------------------------------------------------------
    # Save / Load pipeline
    # ------------------------------------------------------------------

    def _save_pipeline(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Pipeline", "", "Pipeline JSON (*.json)"
        )
        if not path:
            return
        cfg = self.get_pipeline_config()
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh, indent=2)

    def _load_pipeline(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Load Pipeline", "", "Pipeline JSON (*.json)"
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as fh:
                cfg = json.load(fh)
            self.set_pipeline_config(cfg)
        except Exception as exc:
            QMessageBox.warning(self, "Load Error", str(exc))

    # ------------------------------------------------------------------
    # Hypothesis
    # ------------------------------------------------------------------

    def _run_as_hypothesis(self) -> None:
        if not self._nodes:
            return
        final_output = self._nodes[-1].output_data()
        transforms_applied = " → ".join(n.to_config()["transform"] for n in self._nodes)
        final_text = final_output.decode("utf-8", errors="replace")
        self.hypothesis_requested.emit(final_text, transforms_applied)


# ---------------------------------------------------------------------------
# Dockable wrapper
# ---------------------------------------------------------------------------

def make_transform_pipeline_dock(parent, ai_client=None) -> QDockWidget:
    """Create and return a dockable Transform Pipeline panel."""
    dock = QDockWidget("🔧 Transform Pipeline", parent)
    dock.setObjectName("TransformPipelineDock")
    dock.setAllowedAreas(
        Qt.DockWidgetArea.LeftDockWidgetArea
        | Qt.DockWidgetArea.RightDockWidgetArea
        | Qt.DockWidgetArea.BottomDockWidgetArea
    )
    panel = TransformPipelinePanel(ai_client=ai_client, parent=dock)
    dock.setWidget(panel)
    return dock
