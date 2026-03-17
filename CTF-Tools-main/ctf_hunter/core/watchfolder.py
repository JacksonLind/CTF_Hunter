"""
Watchfolder: monitors a directory and emits Qt signals for new files.
Uses the watchdog library for cross-platform filesystem events.

Improvements:
- 2-second debounce timer per file path (prevents duplicate analysis for
  files written in multiple chunks).
- File size gate: files exceeding max_file_mb are skipped with a warning
  signal instead of being queued.
- All signal emissions happen on the Qt signal mechanism so that UI code
  is always updated from the correct thread.
"""
from __future__ import annotations

import os
import threading
from PyQt6.QtCore import QObject, pyqtSignal
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileModifiedEvent

_DEBOUNCE_SECONDS = 2.0
_DEFAULT_MAX_FILE_MB = 50


class _Handler(FileSystemEventHandler):
    def __init__(self, on_ready, on_skip):
        super().__init__()
        self._on_ready = on_ready   # callable(path) — called after debounce
        self._on_skip = on_skip     # callable(path, reason) — called for oversized files
        self._timers: dict[str, threading.Timer] = {}
        self._lock = threading.Lock()
        self.max_file_mb: float = _DEFAULT_MAX_FILE_MB

    def cancel_all(self) -> None:
        """Cancel every pending debounce timer.  Call this before shutting down."""
        with self._lock:
            for timer in self._timers.values():
                timer.cancel()
            self._timers.clear()

    def _schedule(self, path: str) -> None:
        with self._lock:
            # Cancel existing timer for this path if any
            existing = self._timers.get(path)
            if existing is not None:
                existing.cancel()
            timer = threading.Timer(_DEBOUNCE_SECONDS, self._fire, args=(path,))
            timer.daemon = True
            timer.start()
            # Only add to the dict after start() succeeds so that cancel_all()
            # only ever sees actually-running timers.  A start() exception must
            # not leave a dead timer entry that would prevent a future
            # _schedule() call from cancelling it.
            self._timers[path] = timer

    def _fire(self, path: str) -> None:
        with self._lock:
            self._timers.pop(path, None)
        # Size gate
        try:
            size_mb = os.path.getsize(path) / (1024 * 1024)
        except OSError:
            return  # file disappeared
        if size_mb > self.max_file_mb:
            self._on_skip(
                path,
                f"File exceeds size limit ({size_mb:.1f} MB > {self.max_file_mb} MB); skipped.",
            )
            return
        self._on_ready(path)

    def on_created(self, event):
        if not event.is_directory:
            self._schedule(event.src_path)

    def on_modified(self, event):
        # Only reschedule if a timer is already pending (resetting the debounce)
        # or if no timer exists yet (first event for this path).  Either way,
        # _schedule handles the cancel-and-reschedule logic atomically.
        if not event.is_directory:
            self._schedule(event.src_path)


class WatchfolderManager(QObject):
    """Emits `file_detected` signal when a new file appears in the watched directory.

    All signals are emitted through Qt's signal mechanism so connected slots
    run in the GUI thread even though the underlying watchdog callbacks fire
    from a background thread.
    """

    file_detected = pyqtSignal(str)
    file_skipped = pyqtSignal(str, str)   # (path, reason)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._observer: Observer | None = None
        self._handler: _Handler | None = None
        self._path: str = ""
        self._max_file_mb: float = _DEFAULT_MAX_FILE_MB

    @property
    def max_file_mb(self) -> float:
        return self._max_file_mb

    @max_file_mb.setter
    def max_file_mb(self, value: float) -> None:
        self._max_file_mb = value
        if self._handler is not None:
            self._handler.max_file_mb = value

    def start(self, directory: str) -> None:
        self.stop()
        self._path = directory
        self._handler = _Handler(
            on_ready=lambda p: self.file_detected.emit(p),
            on_skip=lambda p, r: self.file_skipped.emit(p, r),
        )
        self._handler.max_file_mb = self._max_file_mb
        self._observer = Observer()
        self._observer.schedule(self._handler, directory, recursive=False)
        self._observer.start()

    def stop(self) -> None:
        # Cancel pending debounce timers before stopping the observer so no
        # timer can fire after the watcher has shut down and attempt to emit
        # signals on a destroyed object.
        if self._handler is not None:
            self._handler.cancel_all()
        if self._observer and self._observer.is_alive():
            self._observer.stop()
            self._observer.join()
        self._observer = None
        self._handler = None

    @property
    def active(self) -> bool:
        return self._observer is not None and self._observer.is_alive()

    @property
    def watched_path(self) -> str:
        return self._path
