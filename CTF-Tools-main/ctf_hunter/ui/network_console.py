"""
Network Console tab: netcat-style terminal for interacting with CTF services.

Provides TCP/UDP/TLS connections, side-by-side ASCII+hex output display,
auto-decode pipeline, session logging, send-from-file, and message history.
"""
from __future__ import annotations

import re
import socket
import ssl
import struct
import threading
import base64
from collections import deque
from pathlib import Path
from typing import Optional

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QComboBox, QTextEdit, QCheckBox, QSplitter, QFileDialog, QMessageBox,
    QScrollArea,
)
from PyQt6.QtCore import Qt, QEvent, QObject, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor, QTextCharFormat, QTextCursor, QKeyEvent

from core.report import Session

# ---------------------------------------------------------------------------
# Decode pipeline helpers
# ---------------------------------------------------------------------------

_FLAG_PATTERN_DEFAULT = re.compile(r"CTF\{[^}]+\}", re.IGNORECASE)


def _try_base64(data: str) -> Optional[str]:
    try:
        decoded = base64.b64decode(data + "==").decode("utf-8", errors="replace")
        if decoded and all(0x20 <= ord(c) <= 0x7E or c in "\r\n\t" for c in decoded):
            return decoded
    except Exception:
        pass
    return None


def _try_hex(data: str) -> Optional[str]:
    clean = re.sub(r"\s+", "", data)
    if len(clean) >= 4 and len(clean) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", clean):
        try:
            decoded = bytes.fromhex(clean).decode("utf-8", errors="replace")
            if decoded and all(0x20 <= ord(c) <= 0x7E or c in "\r\n\t" for c in decoded):
                return decoded
        except Exception:
            pass
    return None


def _try_rot13(data: str) -> Optional[str]:
    result = data.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
    ))
    if result != data and any(c.isalpha() for c in result):
        return result
    return None


def _try_xor_brute(data: str) -> Optional[str]:
    raw = data.encode("latin-1", errors="replace")
    for key in range(1, 256):
        decoded = bytes(b ^ key for b in raw)
        try:
            text = decoded.decode("utf-8")
            if sum(1 for c in text if c.isprintable()) / max(len(text), 1) > 0.85:
                return f"XOR(0x{key:02X}): {text}"
        except UnicodeDecodeError:
            pass
    return None


def _try_reverse(data: str) -> Optional[str]:
    rev = data[::-1]
    if rev != data:
        return rev
    return None


def _run_decode_pipeline(line: str, flag_pattern: re.Pattern) -> list[tuple[str, str, bool]]:
    """
    Run decoding attempts on a line. Returns list of (method, decoded, is_flag_match).
    """
    results = []
    decoders = [
        ("Base64", _try_base64),
        ("Hex",    _try_hex),
        ("ROT13",  _try_rot13),
        ("Reverse", _try_reverse),
        ("XOR",    _try_xor_brute),
    ]
    for name, fn in decoders:
        try:
            decoded = fn(line.strip())
            if decoded and decoded != line:
                is_flag = bool(flag_pattern.search(decoded))
                results.append((name, decoded, is_flag))
        except Exception:
            pass
    return results


def _hex_dump_line(raw: bytes, offset: int = 0) -> str:
    """Format a line of bytes as offset + hex + ASCII side-by-side."""
    hex_part = " ".join(f"{b:02x}" for b in raw)
    ascii_part = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in raw)
    return f"{offset:08x}  {hex_part:<47}  |{ascii_part}|"


def _format_hex_dump(raw: bytes) -> str:
    lines = []
    for i in range(0, len(raw), 16):
        lines.append(_hex_dump_line(raw[i:i + 16], i))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Worker signals
# ---------------------------------------------------------------------------

class _NetSignals(QObject):
    data_received = pyqtSignal(bytes)
    connected = pyqtSignal()
    disconnected = pyqtSignal(str)
    error = pyqtSignal(str)


# ---------------------------------------------------------------------------
# Network Console Widget
# ---------------------------------------------------------------------------

class NetworkConsoleTab(QWidget):
    # Emitted when a flag is auto-detected in received data
    flag_detected = pyqtSignal(str, str)  # (file_context, flag_text)

    def __init__(self, session: Optional[Session] = None, parent=None):
        super().__init__(parent)
        self._session = session
        self._sock: Optional[socket.socket] = None
        self._connected = False
        self._recv_thread: Optional[threading.Thread] = None
        self._signals = _NetSignals()
        self._log_buffer: list[str] = []
        self._history: deque[str] = deque(maxlen=20)
        self._history_idx = -1
        self._flag_pattern = _FLAG_PATTERN_DEFAULT
        self._recv_offset = 0

        self._signals.data_received.connect(self._on_data_received)
        self._signals.connected.connect(self._on_connected)
        self._signals.disconnected.connect(self._on_disconnected)
        self._signals.error.connect(self._on_error)

        self._build_ui()

    def set_session(self, session: Session) -> None:
        self._session = session

    def set_flag_pattern(self, pattern: re.Pattern) -> None:
        self._flag_pattern = pattern

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)

        # Connection controls
        conn_row = QHBoxLayout()

        conn_row.addWidget(QLabel("Host:"))
        self._host_edit = QLineEdit()
        self._host_edit.setPlaceholderText("hostname or IP")
        self._host_edit.setMinimumWidth(160)
        conn_row.addWidget(self._host_edit)

        conn_row.addWidget(QLabel("Port:"))
        self._port_edit = QLineEdit()
        self._port_edit.setPlaceholderText("1337")
        self._port_edit.setFixedWidth(70)
        conn_row.addWidget(self._port_edit)

        conn_row.addWidget(QLabel("Protocol:"))
        self._proto_combo = QComboBox()
        self._proto_combo.addItems(["TCP", "UDP", "TLS"])
        conn_row.addWidget(self._proto_combo)

        self._connect_btn = QPushButton("Connect")
        self._connect_btn.setCheckable(True)
        self._connect_btn.clicked.connect(self._toggle_connection)
        conn_row.addWidget(self._connect_btn)

        conn_row.addStretch()

        self._log_session_btn = QPushButton("💾 Log to Session")
        self._log_session_btn.clicked.connect(self._log_to_session)
        self._log_session_btn.setEnabled(False)
        conn_row.addWidget(self._log_session_btn)

        layout.addLayout(conn_row)

        # Output area
        self._output = QTextEdit()
        self._output.setReadOnly(True)
        self._output.setFont(QFont("Courier New", 10))
        self._output.setStyleSheet("background:#0d1117; color:#c9d1d9;")
        layout.addWidget(self._output, stretch=1)

        # Input row
        input_row = QHBoxLayout()

        self._raw_hex_chk = QCheckBox("Send Raw Hex")
        self._raw_hex_chk.setToolTip(
            "Interpret input as hex bytes before sending (e.g. 41 42 43)"
        )
        input_row.addWidget(self._raw_hex_chk)

        self._input_edit = QLineEdit()
        self._input_edit.setPlaceholderText("Type message and press Enter or Send…")
        self._input_edit.returnPressed.connect(self._send_message)
        self._input_edit.installEventFilter(self)
        input_row.addWidget(self._input_edit, stretch=1)

        self._send_btn = QPushButton("Send")
        self._send_btn.setEnabled(False)
        self._send_btn.clicked.connect(self._send_message)
        input_row.addWidget(self._send_btn)

        self._send_file_btn = QPushButton("📂 Send from File")
        self._send_file_btn.setEnabled(False)
        self._send_file_btn.clicked.connect(self._send_from_file)
        input_row.addWidget(self._send_file_btn)

        layout.addLayout(input_row)

    # ------------------------------------------------------------------
    # Event filter for Up/Down arrow key history
    # ------------------------------------------------------------------

    def eventFilter(self, obj, event) -> bool:
        if obj is self._input_edit and event.type() == QEvent.Type.KeyPress:
            key = event.key()
            if key == Qt.Key.Key_Up:
                self._history_navigate(-1)
                return True
            elif key == Qt.Key.Key_Down:
                self._history_navigate(1)
                return True
        return super().eventFilter(obj, event)

    def _history_navigate(self, direction: int) -> None:
        if not self._history:
            return
        history_list = list(self._history)
        new_idx = self._history_idx + direction
        if 0 <= new_idx < len(history_list):
            self._history_idx = new_idx
            self._input_edit.setText(history_list[-(self._history_idx + 1)])
        elif new_idx < 0:
            self._history_idx = -1
            self._input_edit.clear()

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def _toggle_connection(self, checked: bool) -> None:
        if checked:
            self._do_connect()
        else:
            self._do_disconnect()

    def _do_connect(self) -> None:
        host = self._host_edit.text().strip()
        port_text = self._port_edit.text().strip()
        proto = self._proto_combo.currentText()

        if not host or not port_text:
            QMessageBox.warning(self, "Connection", "Please enter host and port.")
            self._connect_btn.setChecked(False)
            return

        try:
            port = int(port_text)
        except ValueError:
            QMessageBox.warning(self, "Connection", "Port must be a number.")
            self._connect_btn.setChecked(False)
            return

        self._append_output(f"[*] Connecting to {host}:{port} ({proto})…\n", color="#58a6ff")

        try:
            if proto == "UDP":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.connect((host, port))
            else:
                raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                raw_sock.settimeout(10)
                raw_sock.connect((host, port))
                raw_sock.settimeout(None)
                if proto == "TLS":
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    # Enforce at least TLSv1.2 to avoid insecure protocol versions
                    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                    sock = ctx.wrap_socket(raw_sock, server_hostname=host)
                else:
                    sock = raw_sock

            self._sock = sock
            self._connected = True
            self._connect_btn.setText("Disconnect")

            # Start receive thread
            self._recv_thread = threading.Thread(
                target=self._recv_loop, daemon=True
            )
            self._recv_thread.start()
            self._signals.connected.emit()

        except Exception as exc:
            self._connect_btn.setChecked(False)
            self._signals.error.emit(str(exc))

    def _do_disconnect(self) -> None:
        self._connected = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
        self._connect_btn.setText("Connect")
        self._connect_btn.setChecked(False)
        self._send_btn.setEnabled(False)
        self._send_file_btn.setEnabled(False)
        self._append_output("[*] Disconnected.\n", color="#58a6ff")

    def _recv_loop(self) -> None:
        """Receive data in a background thread."""
        sock = self._sock
        proto = self._proto_combo.currentText()
        while self._connected and sock:
            try:
                if proto == "UDP":
                    chunk, _ = sock.recvfrom(4096)
                else:
                    chunk = sock.recv(4096)
                if not chunk:
                    self._signals.disconnected.emit("Server closed connection.")
                    break
                self._signals.data_received.emit(chunk)
            except OSError:
                if self._connected:
                    self._signals.disconnected.emit("Connection lost.")
                break

    # ------------------------------------------------------------------
    # Send
    # ------------------------------------------------------------------

    def _send_message(self) -> None:
        if not self._connected or not self._sock:
            return
        text = self._input_edit.text()
        if not text:
            return

        if self._raw_hex_chk.isChecked():
            # Interpret as hex
            try:
                payload = bytes.fromhex(text.replace(" ", ""))
            except ValueError:
                self._append_output("[!] Invalid hex input.\n", color="#f85149")
                return
        else:
            payload = (text + "\n").encode("utf-8", errors="replace")

        self._do_send(payload)
        self._history.append(text)
        self._history_idx = -1
        self._log_buffer.append(f">>> {text}")
        self._input_edit.clear()

    def _send_from_file(self) -> None:
        if not self._connected or not self._sock:
            return
        path, _ = QFileDialog.getOpenFileName(self, "Select File to Send", "", "All Files (*)")
        if not path:
            return
        try:
            payload = Path(path).read_bytes()
            self._do_send(payload)
            self._append_output(
                f"[*] Sent {len(payload)} bytes from file: {path}\n", color="#58a6ff"
            )
            self._log_buffer.append(f">>> [file: {path}, {len(payload)} bytes]")
        except Exception as exc:
            self._append_output(f"[!] Error reading file: {exc}\n", color="#f85149")

    def _do_send(self, payload: bytes) -> None:
        try:
            if self._proto_combo.currentText() == "UDP":
                self._sock.send(payload)
            else:
                self._sock.sendall(payload)
            hex_preview = payload[:32].hex()
            display = payload.decode("utf-8", errors="replace").rstrip("\n")
            self._append_output(
                f">>> {display}  [{hex_preview}{'…' if len(payload) > 32 else ''}]\n",
                color="#3fb950",
            )
        except Exception as exc:
            self._append_output(f"[!] Send error: {exc}\n", color="#f85149")

    # ------------------------------------------------------------------
    # Receive handler
    # ------------------------------------------------------------------

    def _on_data_received(self, chunk: bytes) -> None:
        self._log_buffer.append(f"<<< [{len(chunk)} bytes]")
        # Hex dump
        hex_dump = _format_hex_dump(chunk)
        self._append_output(hex_dump + "\n", color="#c9d1d9")

        # Decode pipeline per line
        try:
            text_lines = chunk.decode("utf-8", errors="replace").splitlines()
        except Exception:
            text_lines = []

        for line in text_lines:
            line_stripped = line.strip()
            if not line_stripped:
                continue
            # Show decoded ASCII line
            self._append_output(f"    {line}\n", color="#e6edf3")
            self._log_buffer.append(f"    {line}")

            # Run decode pipeline
            decodes = _run_decode_pipeline(line_stripped, self._flag_pattern)
            for method, decoded, is_flag in decodes:
                color = "#f85149" if is_flag else "#e3b341"  # Red if flag, yellow otherwise
                self._append_output(
                    f"    [{method}] {decoded[:200]}\n", color=color
                )
                if is_flag:
                    self.flag_detected.emit("network", decoded)

    def _on_connected(self) -> None:
        self._send_btn.setEnabled(True)
        self._send_file_btn.setEnabled(True)
        self._log_session_btn.setEnabled(True)
        self._append_output("[✓] Connected.\n", color="#3fb950")

    def _on_disconnected(self, msg: str) -> None:
        self._do_disconnect()
        self._append_output(f"[*] {msg}\n", color="#58a6ff")

    def _on_error(self, msg: str) -> None:
        self._append_output(f"[!] Error: {msg}\n", color="#f85149")

    # ------------------------------------------------------------------
    # Output display
    # ------------------------------------------------------------------

    def _append_output(self, text: str, color: str = "#c9d1d9") -> None:
        cursor = self._output.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        fmt = QTextCharFormat()
        fmt.setForeground(QColor(color))
        cursor.setCharFormat(fmt)
        cursor.insertText(text)
        self._output.setTextCursor(cursor)
        self._output.ensureCursorVisible()

    # ------------------------------------------------------------------
    # Session logging
    # ------------------------------------------------------------------

    def _log_to_session(self) -> None:
        if not self._session:
            QMessageBox.information(
                self, "Log to Session", "No active session. Load or create a session first."
            )
            return
        host = self._host_edit.text().strip()
        port = self._port_edit.text().strip()
        key = f"network:{host}:{port}"
        existing = self._session.notes.get(key, "")
        log_text = "\n".join(self._log_buffer)
        self._session.notes[key] = (existing + "\n" + log_text).strip()
        QMessageBox.information(
            self, "Log to Session",
            f"Network exchange logged to session under key:\n{key}"
        )

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def closeEvent(self, event) -> None:
        self._do_disconnect()
        super().closeEvent(event)
