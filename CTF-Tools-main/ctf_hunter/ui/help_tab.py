"""
Help tab for CTF Hunter.

Provides a scrollable reference guide covering every tab and workflow,
so users can quickly understand each feature without leaving the application.
"""
from __future__ import annotations

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QTextBrowser
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont

# ---------------------------------------------------------------------------
# Help content (HTML)
# ---------------------------------------------------------------------------

_HELP_HTML = """
<html>
<head>
<style>
  body        { font-family: sans-serif; font-size: 13px; margin: 16px; }
  h1          { color: #4a9eff; border-bottom: 2px solid #4a9eff; padding-bottom: 4px; }
  h2          { color: #e8b84b; margin-top: 24px; border-left: 4px solid #e8b84b;
                padding-left: 8px; }
  h3          { color: #7ec86b; margin-top: 16px; }
  p           { margin: 6px 0; line-height: 1.5; }
  ul, ol      { margin: 6px 0 6px 24px; line-height: 1.6; }
  li          { margin-bottom: 2px; }
  code        { background: #2d2d2d; color: #f8f8f2; padding: 1px 4px;
                border-radius: 3px; font-family: monospace; }
  .tab-icon   { font-size: 18px; }
  .tip        { background: #1e3a5f; border-left: 4px solid #4a9eff;
                padding: 8px 12px; margin: 10px 0; border-radius: 0 4px 4px 0; }
  .warn       { background: #3a2a00; border-left: 4px solid #e8b84b;
                padding: 8px 12px; margin: 10px 0; border-radius: 0 4px 4px 0; }
  table       { border-collapse: collapse; width: 100%; margin: 8px 0; }
  th          { background: #2a2a2a; color: #ccc; padding: 6px 10px;
                text-align: left; border: 1px solid #444; }
  td          { padding: 5px 10px; border: 1px solid #444; vertical-align: top; }
  tr:nth-child(even) { background: #1a1a1a; }
</style>
</head>
<body>

<h1>CTF Hunter — User Guide</h1>
<p>
  Welcome to <strong>CTF Hunter</strong>! This guide walks you through every tab
  and feature so you can hit the ground running during competitions.
</p>

<!-- ======================================================= QUICK START -->
<h2>⚡ Quick Start</h2>
<ol>
  <li><strong>Add files</strong> — drag-and-drop files/folders onto the left panel,
      or use the toolbar buttons <em>Add Files</em> / <em>Add Folder</em>.</li>
  <li><strong>Choose a depth</strong> — select <code>Fast</code>, <code>Deep</code>,
      or <code>Auto</code> from the mode drop-down in the toolbar.</li>
  <li><strong>Set a flag format</strong> — pick the competition's flag format
      (e.g. <code>CTF{}</code>, <code>HTB{}</code>) or enter a custom regex.</li>
  <li><strong>Click ▶ Analyze All</strong> — all files are dispatched to the
      appropriate analysers simultaneously.</li>
  <li><strong>Review findings</strong> — browse the Findings tree, Flag Summary,
      and the specialist tabs for deeper analysis.</li>
</ol>

<!-- ============================================================ TOOLBAR -->
<h2>🔧 Toolbar</h2>
<table>
  <tr><th>Control</th><th>Purpose</th></tr>
  <tr><td>▶ <strong>Analyze All</strong></td>
      <td>Start parallel analysis of every loaded file.</td></tr>
  <tr><td><strong>Mode</strong> (Fast / Deep / Auto)</td>
      <td><code>Fast</code> runs lightweight checks only.
          <code>Deep</code> enables expensive operations (entropy, strings, AI).
          <code>Auto</code> picks depth based on file size.</td></tr>
  <tr><td><strong>Flag Format</strong></td>
      <td>Pre-set regex patterns for common CTF flag styles.
          Choose <em>Custom…</em> to type your own regex.</td></tr>
  <tr><td><strong>Tool dots</strong> (coloured circles)</td>
      <td>Green = external tool found; red = missing.
          Hover a dot to see the tool name.</td></tr>
  <tr><td>💾 <strong>Save / Load</strong></td>
      <td>Persist or restore a full session (files + findings) as a
          <code>.ctfs</code> JSON file.</td></tr>
  <tr><td>📁 <strong>Watchfolder</strong></td>
      <td>Monitor a directory; any new file is analysed automatically.</td></tr>
  <tr><td>📤 <strong>Export</strong></td>
      <td>Export all findings to <em>Markdown</em>, <em>CSV</em>, or
          <em>HTML</em>.</td></tr>
  <tr><td>⚙ <strong>Settings</strong></td>
      <td>Configure your Claude API key and custom wordlist path.</td></tr>
  <tr><td>🔧 <strong>Transform Pipeline</strong></td>
      <td>Toggle the chainable data-transform sidebar (see below).</td></tr>
</table>

<!-- =========================================================== TAB 1 -->
<h2><span class="tab-icon">📋</span> Analysis Tab</h2>
<p>
  The <strong>Analysis</strong> tab is the main workspace. It contains three
  resizable panels:
</p>
<h3>Left Panel — File List</h3>
<ul>
  <li>Shows every loaded file with a per-file progress bar and a severity badge
      (<span style="color:#e74c3c;">HIGH</span> /
       <span style="color:#e8b84b;">MEDIUM</span> /
       <span style="color:#3498db;">LOW</span> /
       <span style="color:#2ecc71;">INFO</span>).</li>
  <li><strong>Right-click</strong> a file for a context menu: <em>Analyze</em>,
      <em>Diff with…</em>, <em>Open in Steg Viewer</em>, <em>Remove</em>.</li>
  <li>The <strong>Notes</strong> text area below the list lets you jot down
      per-session thoughts.</li>
</ul>
<h3>Top-Right Panel — Findings Tree</h3>
<ul>
  <li>Columns: <em>Severity</em> · <em>Analyzer</em> · <em>Title</em> ·
      <em>Confidence</em> · <em>Offset</em>.</li>
  <li>Click a finding to see its full detail in the panel below; the hex viewer
      jumps to the relevant offset automatically.</li>
  <li><strong>Right-click</strong> a finding to <em>Copy Detail</em> or
      <em>Pin to Transform Pipeline</em>.</li>
  <li>The <strong>🤖 Analyze with AI</strong> button sends all current findings
      to Claude for a holistic summary.</li>
</ul>
<h3>Bottom-Right Panel — Hex Viewer</h3>
<ul>
  <li>Displays the selected file in classic hex-dump format (16 bytes/row).</li>
  <li>Relevant offsets are highlighted in yellow when a finding is selected.</li>
  <li>Displays up to 256 KB by default.</li>
</ul>

<!-- =========================================================== TAB 2 -->
<h2><span class="tab-icon">🚩</span> Flag Summary Tab</h2>
<p>
  Aggregates every finding whose title contains a recognised flag pattern
  across <em>all</em> loaded files, giving you a single place to review
  potential flags.
</p>
<ul>
  <li>The header count turns red as soon as any flags are found.</li>
  <li>Click a row to see the full detail text below the table.</li>
  <li><strong>🤖 Ask AI: Best Lead?</strong> — sends all flag candidates to
      Claude, which ranks them and explains which is most likely the real
      flag.</li>
</ul>
<div class="tip">
  💡 <strong>Tip:</strong> If you load multiple files from the same challenge,
  the AI's holistic view here is often more useful than per-file analysis.
</div>

<!-- =========================================================== TAB 3 -->
<h2><span class="tab-icon">🔬</span> Steg Viewer Tab</h2>
<p>
  Dedicated image steganography toolkit.  Load any image (PNG, BMP, JPEG, etc.)
  from the file list, then use the controls to reveal hidden data.
</p>
<table>
  <tr><th>Tool</th><th>What it does</th></tr>
  <tr><td><strong>Channel Selector</strong></td>
      <td>Display only the R, G, B, Alpha, or Luminance channel.</td></tr>
  <tr><td><strong>Bit Plane Viewer</strong></td>
      <td>Extracts a single bit plane (0 = LSB … 7 = MSB) as a B&amp;W image.
          Hidden messages are often in bit planes 0–2.</td></tr>
  <tr><td><strong>LSB Plane</strong></td>
      <td>One-click least-significant-bit extraction across all pixels.</td></tr>
  <tr><td><strong>Channel Isolator</strong></td>
      <td>Sets all other channels to zero, leaving only the selected channel.</td></tr>
  <tr><td><strong>Histogram</strong></td>
      <td>ASCII bar chart of pixel value distribution; unusual spikes can
          indicate embedded data.</td></tr>
</table>
<div class="tip">
  💡 <strong>Tip:</strong> Start with <em>Bit Plane 0</em> on each channel.
  If you see recognisable shapes or patterns, data is likely embedded there.
</div>

<!-- =========================================================== TAB 4 -->
<h2><span class="tab-icon">🔑</span> File Intel Tab</h2>
<p>
  Four sub-tabs give you quick access to common file-intelligence tasks:
</p>
<h3>Hashes</h3>
<p>
  Computes MD5, SHA-1, SHA-256, and SHA-512 in the background.  Use the
  <em>Copy</em> button beside each hash to paste it into a cracking tool or
  online database.
</p>
<h3>Entropy</h3>
<p>
  Shows the Shannon entropy (0–8 bits/byte) for the whole file and for each
  256-byte block.  High entropy (≥ 7.5) typically means the data is encrypted
  or compressed; low entropy (≤ 2) means mostly repeated bytes.
</p>
<h3>Strings</h3>
<p>
  Extracts printable strings, equivalent to running <code>strings</code>.
  Adjust the minimum length slider and optionally filter by regex to narrow
  results.
</p>
<h3>Decode Playground</h3>
<p>
  One-click decoders: <em>Base64</em>, <em>Base32</em>, <em>Hex</em>,
  <em>URL</em>, <em>ROT-13</em>, and <em>XOR</em> (enter the key as a hex
  byte, e.g. <code>0x41</code>).  Paste any suspicious string and try each
  decoder in turn.
</p>

<!-- =========================================================== TAB 5 -->
<h2><span class="tab-icon">🎯</span> Challenge Tab</h2>
<p>
  Paste the CTF challenge description into the top text area and CTF Hunter
  analyses it in two passes:
</p>
<ol>
  <li><strong>Immediate (local regex)</strong> — extracts flag format hints,
      tool names, file type hints, and encoded data snippets.  Results appear
      instantly in the yellow box.</li>
  <li><strong>AI-powered plan</strong> — if a Claude API key is configured,
      sends the description together with all current file findings to Claude,
      which returns a numbered, prioritised attack plan.  Results appear in the
      blue box.</li>
</ol>
<div class="tip">
  💡 <strong>Tip:</strong> Always paste the challenge description here before
  analysing files; the AI uses both the description and the findings together
  for a much richer response.
</div>

<!-- =========================================================== TAB 6 -->
<h2><span class="tab-icon">🕒</span> Timeline Tab</h2>
<p>
  Builds a chronological table of every timestamp found in the loaded files —
  from filesystem metadata (atime/mtime/ctime), EXIF tags, PDF/DOCX document
  properties, OLE streams, and ZIP central directory records.
</p>
<ul>
  <li>Select a file from the drop-down to view its timestamps.</li>
  <li>Rows highlighted in <strong style="color:#e8b84b;">yellow</strong>
      indicate anomalous timestamps (e.g. suspicious clock skew).</li>
  <li>Rows highlighted in <strong style="color:#e74c3c;">red</strong> indicate
      timestamps set in the future — a common forensic indicator of tampering.</li>
</ul>
<div class="tip">
  💡 <strong>Tip:</strong> In forensics challenges, manipulated timestamps are
  often the puzzle.  Look for dates that don't match the narrative of the
  challenge.
</div>

<!-- =========================================================== TAB 7 -->
<h2><span class="tab-icon">🌐</span> Network Tab</h2>
<p>
  An interactive TCP/UDP/TLS console — like <code>netcat</code> built into the
  tool — for connecting to remote CTF services.
</p>
<h3>Connecting</h3>
<ol>
  <li>Enter the host and port.</li>
  <li>Choose the protocol: <strong>TCP</strong>, <strong>UDP</strong>, or
      <strong>TLS</strong>.</li>
  <li>Click <strong>Connect</strong>.</li>
</ol>
<h3>Features</h3>
<ul>
  <li><strong>Dual display</strong>: received data shown as ASCII and hex
      side-by-side.</li>
  <li><strong>Auto-decode pipeline</strong>: incoming data is automatically
      tested against Base64, hex, ROT-13, XOR, and reverse — decoded values
      appear inline.</li>
  <li><strong>Flag detection</strong>: if a flag matching the active pattern
      is received, the Flag Summary tab is highlighted and the flag is added
      automatically.</li>
  <li><strong>Message history</strong>: press ↑/↓ in the input box to cycle
      through previously sent commands.</li>
  <li><strong>Session logging</strong>: save and reload the full
      send/receive history.</li>
</ul>

<!-- =========================================================== TAB 8 -->
<h2><span class="tab-icon">⚔️</span> Attack Plan Tab</h2>
<p>
  Displays ranked attack hypotheses generated from the loaded files and the
  challenge description.  Two sources contribute:
</p>
<ul>
  <li><strong>Hypothesis Engine</strong> (rule-based) — fires rules against
      file type, entropy, magic bytes, and existing findings to suggest likely
      attack vectors.</li>
  <li><strong>Claude AI</strong> — if an API key is set, generates additional
      hypotheses from a broader understanding of CTF patterns.</li>
</ul>
<p>
  Hypotheses are sorted by confidence.  Double-click a row to expand the full
  detail and copy the suggested command.
</p>

<!-- ==================================================== TRANSFORM PIPELINE -->
<h2><span class="tab-icon">🔧</span> Transform Pipeline (Sidebar)</h2>
<p>
  Toggle the sidebar with the <strong>🔧 Transform Pipeline</strong> toolbar
  button.  It lets you chain multiple data transformations in sequence — the
  output of each step feeds the next.
</p>
<table>
  <tr><th>Category</th><th>Available Transforms</th></tr>
  <tr><td>Encoding</td>
      <td>Base64 encode/decode, Hex encode/decode, URL encode/decode</td></tr>
  <tr><td>Classical cipher</td>
      <td>ROT-N (configurable shift), XOR (hex key)</td></tr>
  <tr><td>Compression</td>
      <td>zlib compress/decompress</td></tr>
  <tr><td>Cryptographic</td>
      <td>AES-ECB/CBC decrypt (key + IV)</td></tr>
  <tr><td>Utility</td>
      <td>Reverse bytes, integer base conversion, regex extract</td></tr>
</table>
<p>
  To start a pipeline, right-click a finding in the Analysis tab and choose
  <em>Pin to Transform Pipeline</em>, or paste raw data directly into the
  first node's input box.
</p>
<div class="tip">
  💡 <strong>Tip:</strong> Once you've built a useful chain (e.g.
  Base64 decode → XOR → hex decode), click <em>Send to Challenge</em> to
  add the pipeline as a hypothesis in the Challenge tab.
</div>

<!-- =========================================================== SETTINGS -->
<h2>⚙️ Settings</h2>
<p>Open Settings from the toolbar to configure:</p>
<ul>
  <li><strong>Claude API Key</strong> — enables all AI features (Flag Summary
      AI, Challenge AI, Attack Plan AI, per-finding AI analysis). Get a key
      at <em>console.anthropic.com</em>.</li>
  <li><strong>Custom Wordlist</strong> — path to a wordlist (e.g.
      <code>rockyou.txt</code>) used for hash and archive password cracking.</li>
</ul>
<p>Settings are saved to <code>~/.ctf_hunter/config.json</code>.</p>

<!-- ======================================================= EXTERNAL TOOLS -->
<h2>🛠️ External Tools</h2>
<p>
  CTF Hunter integrates with optional command-line tools when they are on
  your <code>PATH</code>.  The coloured dots in the toolbar show which are
  available:
</p>
<table>
  <tr><th>Tool</th><th>Used for</th></tr>
  <tr><td><code>exiftool</code></td><td>Rich metadata extraction</td></tr>
  <tr><td><code>binwalk</code></td><td>Embedded file detection</td></tr>
  <tr><td><code>strings</code></td><td>Printable string extraction</td></tr>
  <tr><td><code>file</code></td><td>Magic-byte file-type identification</td></tr>
  <tr><td><code>tshark</code></td><td>PCAP packet analysis</td></tr>
</table>

<!-- ========================================================== SESSIONS -->
<h2>💾 Sessions</h2>
<p>
  A <em>session</em> captures the full state of your workspace: which files
  are loaded, all findings, notes, and configuration.
</p>
<ul>
  <li><strong>Save</strong> — toolbar 💾 button → choose a
      <code>.ctfs</code> file location.</li>
  <li><strong>Load</strong> — toolbar 💾 button (load mode) → open a
      <code>.ctfs</code> file to restore a previous session.</li>
</ul>
<div class="warn">
  ⚠️ <strong>Note:</strong> Sessions do <em>not</em> embed the original files;
  they store only the file paths and findings.  Keep the original files
  alongside the session file.
</div>

<!-- ============================================================ WORKFLOW -->
<h2>📖 Recommended Workflow</h2>
<ol>
  <li>Paste the challenge description into the <strong>Challenge</strong> tab.</li>
  <li>Add all provided files via drag-and-drop.</li>
  <li>Set the correct flag format and analysis depth, then click
      <strong>▶ Analyze All</strong>.</li>
  <li>Check the <strong>Flag Summary</strong> tab first — flags are often
      found automatically.</li>
  <li>For image files, switch to <strong>Steg Viewer</strong> and examine
      bit planes and channels.</li>
  <li>Use <strong>File Intel → Entropy</strong> to spot encrypted or
      compressed regions; jump to high-entropy offsets in the Hex Viewer.</li>
  <li>Check the <strong>Attack Plan</strong> tab for suggested next steps,
      especially after AI analysis.</li>
  <li>If the challenge involves a live service, use the
      <strong>Network</strong> tab to interact with it.</li>
  <li>Use the <strong>Transform Pipeline</strong> to decode any suspicious
      byte sequences found in findings.</li>
  <li>Save your session regularly so you can resume later.</li>
</ol>

</body>
</html>
"""


# ---------------------------------------------------------------------------
# Widget
# ---------------------------------------------------------------------------

class HelpTab(QWidget):
    """Scrollable HTML help/reference guide for CTF Hunter."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        browser = QTextBrowser()
        browser.setOpenExternalLinks(True)
        browser.setHtml(_HELP_HTML)
        # Ensure a readable font size in case the system default is tiny
        font = QFont()
        font.setPointSize(11)
        browser.setFont(font)

        layout.addWidget(browser)
