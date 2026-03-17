"""
Challenge Panel tab: paste a CTF challenge description to receive immediate
HIGH findings from a local regex pass, followed by a Claude AI-powered
prioritized attack plan.
"""
from __future__ import annotations

import re
import base64
from typing import List

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QTextEdit, QSplitter,
)
from PyQt6.QtCore import Qt

from core.report import Finding

# ---------------------------------------------------------------------------
# Local regex patterns for the immediate pre-pass
# ---------------------------------------------------------------------------

# Flag format hints: literal flag strings or descriptive phrases
_FLAG_HINTS: list[tuple[str, str]] = [
    (
        r'\b(?:CTF|flag|HTB|picoCTF|DUCTF|RCTF|zer0pts|DawgCTF|JerseyCTF)\{[^}]*\}',
        "Flag string found in description",
    ),
    (r'\bflag\s+(?:format\s+)?(?:is\s+)?[A-Za-z0-9_]+\{', "Flag format hint"),
    (
        r'\bsubmit\s+(?:as|in\s+the\s+form(?:at)?(?:\s+of)?)\s+[A-Za-z0-9_]+\{',
        "Flag format hint",
    ),
]

# Well-known CTF tool names
_TOOL_RE = re.compile(
    r'\b(strings|binwalk|steghide|stegsolve|exiftool|foremost|zsteg|stegseek|'
    r'volatility|wireshark|tshark|hashcat|john(?:\s+the\s+ripper)?|aircrack|openssl|'
    r'ghidra|radare2|r2|gdb|ltrace|strace|xxd|hexdump|pngcheck|stegdetect|'
    r'openstego|outguess|snow|mp3stego|wavsteg|DeepSound|coagula|'
    r'sonic\s*visualizer|audacity)\b',
    re.IGNORECASE,
)

# Common file type keywords
_FILETYPE_RE = re.compile(
    r'\b(PNG|JPEG|JPG|GIF|BMP|TIFF|WAV|MP3|FLAC|OGG|PDF|ZIP|TAR|'
    r'GZIP|RAR|7z|ELF|PE|DLL|PCAP|PCAPNG|SQLite|CAP|DOCX?|XLSX?|PPTX?|'
    r'PEM|KEY|CRT|BZ2|XZ|ISO|IMG|vmdk|vmem)\b',
    re.IGNORECASE,
)

# Base64: 20+ base64 characters with optional padding, not part of a longer run
_B64_RE = re.compile(
    r'(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{20,}={0,2})(?![A-Za-z0-9+/=])'
)

# Hex run: 16+ consecutive hex digits (representing at least 8 bytes)
_HEX_RE = re.compile(r'\b([0-9a-fA-F]{16,})\b')

# URL-encoded data: 3+ percent-encoded bytes in a row
_URL_RE = re.compile(r'(%[0-9a-fA-F]{2}){3,}')


def _local_regex_pass(description: str) -> list[dict]:
    """
    Run local regex patterns against *description*.

    Returns a list of finding dicts with keys ``title``, ``detail``,
    and ``severity`` (always ``"HIGH"``).  Results are deduplicated so
    the same match is not reported twice.
    """
    findings: list[dict] = []
    seen: set[str] = set()

    def _add(title: str, detail: str) -> None:
        key = f"{title}|{detail}"
        if key not in seen:
            seen.add(key)
            findings.append({"title": title, "detail": detail, "severity": "HIGH"})

    # Flag format hints
    for pattern, label in _FLAG_HINTS:
        for m in re.finditer(pattern, description, re.IGNORECASE):
            _add(f"🚩 {label}", f'Found: "{m.group()}"')

    # Tool name mentions
    tools_found = sorted({m.group(1) for m in _TOOL_RE.finditer(description)})
    if tools_found:
        _add("🔧 Tool name(s) mentioned", "Tools referenced: " + ", ".join(tools_found))

    # File type hints
    types_found = sorted({m.group(1).upper() for m in _FILETYPE_RE.finditer(description)})
    if types_found:
        _add("📄 File type(s) mentioned", "File types: " + ", ".join(types_found))

    # Possible Base64 strings
    for m in _B64_RE.finditer(description):
        raw = m.group(1)
        try:
            # Add only the minimum padding needed to make the length a multiple of 4
            padding = (4 - len(raw) % 4) % 4
            decoded = base64.b64decode(raw + "=" * padding).decode("utf-8", errors="replace")
            printable = sum(c.isprintable() for c in decoded) / max(len(decoded), 1)
            if printable >= 0.7:
                _add(
                    "🔐 Possible Base64 in description",
                    f'Raw: "{raw[:40]}…" → decoded: "{decoded[:60]}"',
                )
            else:
                _add("🔐 Possible Base64 in description", f'Raw: "{raw[:60]}"')
        except Exception:
            _add("🔐 Possible Base64 in description", f'Raw: "{raw[:60]}"')

    # Possible hex strings
    for m in _HEX_RE.finditer(description):
        _add("🔢 Possible hex string in description", f'Hex: "{m.group(1)[:80]}"')

    # URL-encoded data
    for m in _URL_RE.finditer(description):
        _add(
            "🌐 Possible URL-encoded data in description",
            f'Encoded: "{m.group()[:80]}"',
        )

    return findings


# Maximum number of file findings included in the AI context to avoid
# exceeding the model's prompt length limits.
_MAX_FINDINGS_FOR_AI_CONTEXT = 150


# ---------------------------------------------------------------------------
# Widget
# ---------------------------------------------------------------------------

class ChallengePanelTab(QWidget):
    """
    A tab where the analyst pastes a CTF challenge description and clicks
    **Parse Challenge** to receive:

    * Immediate HIGH findings from a local regex pass (flag formats, tool
      mentions, file type hints, embedded encoded strings) — shown without
      waiting for the AI.
    * A Claude AI-generated, numbered, prioritized attack plan that takes
      both the description and all current file findings into account.
    """

    def __init__(self, ai_client=None, parent=None):
        super().__init__(parent)
        self._ai_client = ai_client
        self._all_findings: List[Finding] = []
        self._build_ui()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(8, 8, 8, 8)

        splitter = QSplitter(Qt.Orientation.Vertical)

        # --- Top: description input ---
        top = QWidget()
        top_layout = QVBoxLayout(top)
        top_layout.setContentsMargins(0, 0, 0, 0)

        hdr = QHBoxLayout()
        lbl = QLabel("Challenge Description:")
        lbl.setStyleSheet("font-weight: bold;")
        hdr.addWidget(lbl)
        hdr.addStretch()
        self._parse_btn = QPushButton("🔍 Parse Challenge")
        self._parse_btn.setToolTip(
            "Run a local regex analysis then query Claude AI for a "
            "prioritized attack plan"
        )
        self._parse_btn.clicked.connect(self._on_parse)
        hdr.addWidget(self._parse_btn)
        top_layout.addLayout(hdr)

        self._desc_input = QTextEdit()
        self._desc_input.setPlaceholderText(
            "Paste the CTF challenge description here…\n\n"
            "Include any hints, file names, or context provided by the challenge."
        )
        top_layout.addWidget(self._desc_input)
        splitter.addWidget(top)

        # --- Bottom: results ---
        bottom = QWidget()
        bottom_layout = QVBoxLayout(bottom)
        bottom_layout.setContentsMargins(0, 0, 0, 0)

        imm_lbl = QLabel("⚡ Immediate Findings (regex pass — HIGH priority):")
        imm_lbl.setStyleSheet("font-weight: bold;")
        bottom_layout.addWidget(imm_lbl)

        self._immediate_box = QTextEdit()
        self._immediate_box.setReadOnly(True)
        self._immediate_box.setMaximumHeight(200)
        self._immediate_box.setPlaceholderText(
            "Immediate HIGH findings (regex pass) will appear here…"
        )
        self._immediate_box.setStyleSheet(
            "background: #fff8f0; border: 1px solid #ffcc80;"
        )
        bottom_layout.addWidget(self._immediate_box)

        ai_lbl = QLabel("🤖 AI Attack Plan:")
        ai_lbl.setStyleSheet("font-weight: bold; color: #1a237e;")
        bottom_layout.addWidget(ai_lbl)

        self._ai_box = QTextEdit()
        self._ai_box.setReadOnly(True)
        self._ai_box.setPlaceholderText(
            "AI-generated prioritized attack plan will appear here…\n"
            "(Requires Claude API key in Settings)"
        )
        bottom_layout.addWidget(self._ai_box)
        splitter.addWidget(bottom)

        splitter.setSizes([300, 500])
        outer.addWidget(splitter)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_ai_client(self, ai_client) -> None:
        """Update the AI client (called after settings change)."""
        self._ai_client = ai_client

    def update_findings(self, all_findings: List[Finding]) -> None:
        """Receive the latest file findings from MainWindow."""
        self._all_findings = all_findings

    def set_additional_context(self, context: str) -> None:
        """Append additional context (e.g., from Transform Pipeline) to the description input."""
        existing = self._desc_input.toPlainText()
        separator = "\n\n--- Transform Pipeline Output ---\n"
        if separator in existing:
            # Replace existing pipeline context
            existing = existing[:existing.index(separator)]
        self._desc_input.setPlainText(existing + separator + context)

    # ------------------------------------------------------------------
    # Parse logic
    # ------------------------------------------------------------------

    def _on_parse(self) -> None:
        description = self._desc_input.toPlainText().strip()
        if not description:
            self._immediate_box.setPlainText("⚠ Please enter a challenge description.")
            return

        # 1. Immediate local regex pass — shown without waiting for AI
        local_hits = _local_regex_pass(description)
        self._show_immediate(local_hits)

        # 2. Build a summary of current file findings for the AI prompt
        findings_lines: list[str] = []
        for f in self._all_findings:
            if not f.duplicate_of:
                findings_lines.append(
                    f"[{f.severity}] {f.file}: {f.title} — {f.detail[:200]}"
                )
        findings_summary = (
            "\n".join(findings_lines[:_MAX_FINDINGS_FOR_AI_CONTEXT])
            or "(no file findings yet)"
        )

        # 3. Query AI
        if self._ai_client and self._ai_client.available:
            self._ai_box.setPlainText("🤖 Querying Claude AI… please wait.")
            response = self._ai_client.parse_challenge_description(
                description, findings_summary
            )
            self._show_ai_response(response or "No response from AI.")
        else:
            self._ai_box.setPlainText(
                "⚠ Claude AI is not configured.\n"
                "Set your API key in Settings to enable AI attack plan generation."
            )

    # ------------------------------------------------------------------
    # Display helpers
    # ------------------------------------------------------------------

    def _show_immediate(self, hits: list[dict]) -> None:
        if not hits:
            self._immediate_box.setHtml(
                '<p style="color:#555;">No immediate findings from regex pass.</p>'
            )
            return

        parts = ["<b>⚡ Immediate HIGH Findings</b><br>"]
        for h in hits:
            title = _esc(h["title"])
            detail = _esc(h["detail"])
            parts.append(
                f'<div style="margin:4px 0; padding:4px 8px; '
                f'background:#ffeeee; border-left:4px solid #cc0000;">'
                f"<b>{title}</b><br>"
                f'<code style="font-size:11px;">{detail}</code>'
                f"</div>"
            )
        self._immediate_box.setHtml("".join(parts))

    def _show_ai_response(self, text: str) -> None:
        """
        Render the AI response as HTML.  Numbered attack-plan lines
        (e.g. ``1.`` or ``2)``) are highlighted in bold blue.
        """
        attack_re = re.compile(r"^\s*\d+[.)]\s")
        parts: list[str] = []
        for line in text.splitlines():
            escaped = _esc(line)
            if attack_re.match(line):
                parts.append(
                    f'<p style="margin:2px 0; color:#0d47a1; font-weight:bold;">'
                    f"{escaped}</p>"
                )
            else:
                parts.append(f'<p style="margin:2px 0;">{escaped}</p>')
        self._ai_box.setHtml("".join(parts))


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _esc(text: str) -> str:
    """Minimal HTML escaping for safe insertion into setHtml content."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
