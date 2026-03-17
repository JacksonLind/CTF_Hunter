"""
Settings dialog: Claude API key input, stored in local config file.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QFileDialog, QDialogButtonBox, QDoubleSpinBox,
    QSpinBox,
)
from PyQt6.QtCore import Qt

_CONFIG_PATH = Path.home() / ".ctf_hunter" / "config.json"


def load_config() -> dict:
    try:
        if _CONFIG_PATH.exists():
            return json.loads(_CONFIG_PATH.read_text())
    except Exception:
        pass
    return {}


def save_config(data: dict) -> None:
    try:
        _CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        _CONFIG_PATH.write_text(json.dumps(data, indent=2))
    except Exception:
        pass


class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setModal(True)
        self.resize(500, 280)

        self._config = load_config()

        layout = QVBoxLayout(self)

        # --- API Key ---
        api_row = QHBoxLayout()
        api_row.addWidget(QLabel("Claude API Key:"))
        self._api_key_edit = QLineEdit()
        self._api_key_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._api_key_edit.setPlaceholderText("sk-ant-...")
        self._api_key_edit.setText(self._config.get("api_key", ""))
        api_row.addWidget(self._api_key_edit)
        layout.addLayout(api_row)

        # --- Custom wordlist ---
        wl_row = QHBoxLayout()
        wl_row.addWidget(QLabel("Custom Wordlist:"))
        self._wordlist_edit = QLineEdit()
        self._wordlist_edit.setPlaceholderText("Path to wordlist file...")
        self._wordlist_edit.setText(self._config.get("wordlist_path", ""))
        wl_row.addWidget(self._wordlist_edit)
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self._browse_wordlist)
        wl_row.addWidget(browse_btn)
        layout.addLayout(wl_row)

        # --- Watch folder max file size ---
        wf_row = QHBoxLayout()
        wf_row.addWidget(QLabel("Watchfolder max file size (MB):"))
        self._max_file_mb_spin = QDoubleSpinBox()
        self._max_file_mb_spin.setRange(1.0, 10000.0)
        self._max_file_mb_spin.setDecimals(0)
        self._max_file_mb_spin.setSingleStep(10.0)
        self._max_file_mb_spin.setValue(float(self._config.get("max_file_mb", 50)))
        self._max_file_mb_spin.setToolTip(
            "Files larger than this will be skipped by the watch folder (default: 50 MB)"
        )
        wf_row.addWidget(self._max_file_mb_spin)
        wf_row.addStretch()
        layout.addLayout(wf_row)

        # --- Frida timeout ---
        frida_row = QHBoxLayout()
        frida_row.addWidget(QLabel("Frida analysis timeout (seconds):"))
        self._frida_timeout_spin = QSpinBox()
        self._frida_timeout_spin.setRange(1, 120)
        self._frida_timeout_spin.setValue(int(self._config.get("frida_timeout_seconds", 10)))
        self._frida_timeout_spin.setToolTip(
            "How long to collect Frida messages before killing the process (default: 10 s)"
        )
        frida_row.addWidget(self._frida_timeout_spin)
        frida_row.addStretch()
        layout.addLayout(frida_row)

        # --- Dialog buttons ---
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._save_and_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _browse_wordlist(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select Wordlist", "", "Text Files (*.txt);;All Files (*)")
        if path:
            self._wordlist_edit.setText(path)

    def _save_and_accept(self) -> None:
        self._config["api_key"] = self._api_key_edit.text().strip()
        self._config["wordlist_path"] = self._wordlist_edit.text().strip()
        self._config["max_file_mb"] = self._max_file_mb_spin.value()
        self._config["frida_timeout_seconds"] = self._frida_timeout_spin.value()
        save_config(self._config)
        self.accept()

    def get_api_key(self) -> str:
        return self._config.get("api_key", "")

    def get_wordlist_path(self) -> str:
        return self._config.get("wordlist_path", "")

    def get_max_file_mb(self) -> float:
        return float(self._config.get("max_file_mb", 50))

    def get_frida_timeout_seconds(self) -> int:
        return int(self._config.get("frida_timeout_seconds", 10))

