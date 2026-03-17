"""
Dynamic Frida instrumentation analyzer for ELF and PE binaries.

This analyzer is NEVER auto-run.  It must be explicitly invoked via the
"Run Dynamic Analysis" button in the UI.

Optional dependency — frida and frida-tools are not in the mandatory
requirements.txt.  If they are absent the analyzer reports a single INFO
finding explaining that it is unavailable.
"""
from __future__ import annotations

import logging
import re
import threading
import time
from pathlib import Path
from typing import List, Optional

from core.report import Finding
from core.ai_client import AIClient
from core.deduplicator import deduplicate
from .base import Analyzer

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional frida import — degrade gracefully
# ---------------------------------------------------------------------------
try:
    import frida as _frida
    _FRIDA_AVAILABLE = True
except ImportError:
    _frida = None  # type: ignore[assignment]
    _FRIDA_AVAILABLE = False
    logger.info("frida not installed; dynamic analysis disabled.")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DANGEROUS_HOOKS = {
    "system", "execve", "gets", "strcpy", "printf",
    "read", "mmap", "mprotect",
}

_WALL_CLOCK_TIMEOUT = 30  # hard upper bound (seconds)

# Maximum number of messages accepted from the Frida agent.  A pathological
# binary that generates many rwx regions or hooks many calls on every tick can
# otherwise exhaust host memory before the 30-second hard timeout fires.
_MAX_FRIDA_MESSAGES = 500

# Frida JavaScript agent injected into the target process
_JS_AGENT = r"""
(function () {
    'use strict';

    var dangerousNames = ['system','execve','gets','strcpy','printf','read','mmap','mprotect'];
    var openNames      = ['open','fopen','openat'];
    var exportLimit    = 5;
    var exportCount    = 0;
    var rwxScanInterval = 2000; // ms

    // --- Hook dangerous imports ---
    dangerousNames.forEach(function (name) {
        try {
            var sym = Module.findExportByName(null, name);
            if (!sym) return;
            Interceptor.attach(sym, {
                onEnter: function (args) {
                    send({type: 'dangerous_call', name: name,
                          args: [args[0], args[1], args[2]].map(function(a){
                              try { return a.toString(); } catch(e) { return '?'; }
                          })});
                }
            });
        } catch (e) { /* symbol not found */ }
    });

    // --- Hook open() / fopen() ---
    openNames.forEach(function (name) {
        try {
            var sym = Module.findExportByName(null, name);
            if (!sym) return;
            Interceptor.attach(sym, {
                onEnter: function (args) {
                    try {
                        var filename = Memory.readUtf8String(args[0]);
                        send({type: 'file_open', name: name, filename: filename});
                    } catch(e) {}
                }
            });
        } catch (e) {}
    });

    // --- Hook first N exported functions from .so files ---
    Process.enumerateModules().forEach(function (mod) {
        if (!mod.path.endsWith('.so')) return;
        mod.enumerateExports().forEach(function (exp) {
            if (exportCount >= exportLimit) return;
            if (exp.type !== 'function') return;
            exportCount++;
            try {
                Interceptor.attach(exp.address, {
                    onEnter: function (args) {
                        this._name = exp.name;
                        this._args = [args[0], args[1], args[2]].map(function(a){
                            try { return a.toString(); } catch(e) { return '?'; }
                        });
                    },
                    onLeave: function (retval) {
                        send({type: 'export_call', name: this._name, args: this._args,
                              retval: retval ? retval.toString() : '?'});
                    }
                });
            } catch (e) {}
        });
    });

    // --- Periodic rwx region scanner ---
    setInterval(function () {
        Process.enumerateRanges('rwx').forEach(function (range) {
            try {
                var dump = Memory.readByteArray(range.base, Math.min(64, range.size));
                send({type: 'rwx_region', base: range.base.toString(),
                      size: range.size, dump: dump ? Array.from(new Uint8Array(dump)) : []});
            } catch (e) {}
        });
    }, rwxScanInterval);
})();
"""


def _is_elf(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == b"\x7fELF"
    except OSError:
        return False


def _is_pe(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(2) == b"MZ"
    except OSError:
        return False


class FridaAnalyzer(Analyzer):
    """Dynamic instrumentation via Frida.  Must be explicitly invoked."""

    def analyze(
        self,
        path: str,
        flag_pattern: re.Pattern,
        depth: str,
        ai_client: Optional[AIClient],
        frida_args: Optional[List[str]] = None,
        timeout_seconds: int = 10,
    ) -> List[Finding]:
        findings: List[Finding] = []

        if not _FRIDA_AVAILABLE:
            findings.append(self._finding(
                path,
                "Frida not installed — dynamic analysis unavailable",
                detail=(
                    "Install frida and frida-tools (pip install frida frida-tools) "
                    "to enable runtime instrumentation."
                ),
                severity="INFO",
                confidence=1.0,
            ))
            return findings

        if not (_is_elf(path) or _is_pe(path)):
            findings.append(self._finding(
                path,
                "Dynamic analysis skipped — not an ELF or PE binary",
                severity="INFO",
                confidence=1.0,
            ))
            return findings

        spawn_argv = [path] + (frida_args or [])
        messages: list[dict] = []
        pid: Optional[int] = None
        killed = threading.Event()
        _cap_logged = False  # emit the cap-exceeded warning at most once

        def _on_message(message, data):
            nonlocal _cap_logged
            if message.get("type") == "send":
                if len(messages) >= _MAX_FRIDA_MESSAGES:
                    # Cap reached — stop accepting to prevent memory exhaustion.
                    # We do not call script.unload() here because Frida's
                    # message callback is invoked from an internal thread where
                    # unloading the script is not safe.  The hard wall-clock
                    # timer will kill the process within _WALL_CLOCK_TIMEOUT
                    # seconds regardless.
                    if not _cap_logged:
                        import warnings
                        warnings.warn(
                            f"FridaAnalyzer: message cap ({_MAX_FRIDA_MESSAGES}) reached "
                            "for {path!r}; further messages will be discarded.",
                            RuntimeWarning,
                            stacklevel=0,
                        )
                        _cap_logged = True
                    return
                payload = message.get("payload")
                if isinstance(payload, dict):
                    if data is not None:
                        payload["_data"] = data
                    messages.append(payload)

        def _hard_kill():
            if killed.is_set():
                return  # already killed or timer cancelled — do nothing
            try:
                if pid is not None:
                    _frida.kill(pid)
            except Exception:
                pass
            killed.set()
            findings.append(self._finding(
                path,
                "Frida session exceeded hard wall-clock timeout",
                detail=f"Session forcibly killed after {_WALL_CLOCK_TIMEOUT}s.",
                severity="WARNING",
                confidence=1.0,
            ))

        hard_timer = threading.Timer(_WALL_CLOCK_TIMEOUT, _hard_kill)
        hard_timer.daemon = True
        hard_timer.start()

        try:
            pid = _frida.spawn(spawn_argv, stdio="pipe")
            session = _frida.attach(pid)
            script = session.create_script(_JS_AGENT)
            script.on("message", _on_message)
            script.load()
            _frida.resume(pid)

            deadline = time.monotonic() + timeout_seconds
            while time.monotonic() < deadline and not killed.is_set():
                time.sleep(0.25)

        except Exception as exc:
            findings.append(self._finding(
                path,
                "Frida instrumentation error",
                detail=str(exc),
                severity="HIGH",
                confidence=0.9,
            ))
        finally:
            hard_timer.cancel()
            if pid is not None and not killed.is_set():
                try:
                    _frida.kill(pid)
                except Exception:
                    pass
                killed.set()

        # Parse messages into findings
        for msg in messages:
            mtype = msg.get("type")
            if mtype == "dangerous_call":
                name = msg.get("name", "?")
                args = msg.get("args", [])
                findings.append(self._finding(
                    path,
                    f"Dangerous import called: {name}",
                    detail=f"Function '{name}' was called with arguments: {args}",
                    severity="HIGH",
                    confidence=0.85,
                ))
            elif mtype == "rwx_region":
                base = msg.get("base", "?")
                size = msg.get("size", 0)
                dump_bytes = msg.get("dump", [])
                hex_dump = " ".join(f"{b:02x}" for b in dump_bytes)
                findings.append(self._finding(
                    path,
                    "Self-modifying / unpacked region detected",
                    detail=f"RWX region at {base} (size={size}): {hex_dump}",
                    severity="HIGH",
                    confidence=0.8,
                ))
            elif mtype == "file_open":
                name = msg.get("name", "open")
                filename = msg.get("filename", "?")
                findings.append(self._finding(
                    path,
                    f"File opened: {filename}",
                    detail=f"Syscall '{name}' opened path: {filename}",
                    severity="MEDIUM",
                    confidence=0.75,
                ))
            elif mtype == "export_call":
                fname = msg.get("name", "?")
                args = msg.get("args", [])
                retval = msg.get("retval", "?")
                findings.append(self._finding(
                    path,
                    f"Exported function called: {fname}",
                    detail=f"args={args}, retval={retval}",
                    severity="INFO",
                    confidence=0.6,
                ))

        # Run through deduplicator
        findings = deduplicate(findings)

        return findings
