"""
Session save/load helpers for the UI layer.
Wraps core.report.Session with file dialog integration.
"""
from __future__ import annotations

from PyQt6.QtWidgets import QFileDialog, QMessageBox, QWidget

from core.report import Session


def save_session_dialog(parent: QWidget, session: Session) -> bool:
    """Show a save file dialog and save the session. Returns True on success."""
    path, _ = QFileDialog.getSaveFileName(
        parent, "Save Session", "", "CTF Hunter Session (*.ctfs);;All Files (*)"
    )
    if not path:
        return False
    if not path.endswith(".ctfs"):
        path += ".ctfs"
    try:
        session.save(path)
        return True
    except Exception as exc:
        QMessageBox.critical(parent, "Save Error", f"Failed to save session:\n{exc}")
        return False


def load_session_dialog(parent: QWidget) -> Session | None:
    """Show an open file dialog and load a session. Returns Session or None."""
    path, _ = QFileDialog.getOpenFileName(
        parent, "Load Session", "", "CTF Hunter Session (*.ctfs);;All Files (*)"
    )
    if not path:
        return None
    try:
        return Session.load(path)
    except Exception as exc:
        QMessageBox.critical(parent, "Load Error", f"Failed to load session:\n{exc}")
        return None
