# CLAUDE.md — CTF Hunter

## Project Overview

CTF Hunter is a desktop/CLI tool for analyzing CTF challenge files. It dispatches **19 specialized analyzers**, runs a **multi-stage intelligence pipeline** (confidence scoring → re-dispatch → key registry → hypothesis engine → exploit generation → workspace correlation), and optionally integrates Claude AI for hypothesis augmentation and disassembly summaries.

Entry point: `ctf_hunter/main.py` (GUI default, `--cli` flag for headless mode).

---

## Repository Layout

```
ctf_hunter/
├── main.py                  # Entry point — GUI or CLI
├── cli.py                   # Headless CLI runner
├── build.py                 # PyInstaller packaging
├── requirements.txt
├── core/                    # Intelligence pipeline & shared utilities
├── analyzers/               # One file per analyzer (19 total)
├── ui/                      # PyQt6 panels and tabs
└── wordlists/
    └── rockyou_top1000.txt
```

---

## Architecture: How Analysis Flows

```
File drop / CLI args
       ↓
core/dispatcher.py          ← detects file type (magic bytes + MIME), selects analyzers
       ↓
analyzers/*.py              ← each returns List[Finding]  (see core/report.py)
       ↓
core/confidence.py          ← scores each Finding 0–1
core/content_redispatcher.py← re-routes extracted blobs (up to 5 levels, 45s timeout)
core/key_registry.py        ← stores discovered keys for cross-file correlation
core/hypothesis_engine.py   ← 30 built-in rules + optional Claude AI path
core/exploit_generator.py   ← auto-generates pwntools/RSA scripts (≥0.6 pwn confidence)
core/workspace_correlator.py← pairwise cross-file finding correlation
       ↓
ui/ panels                  ← display findings, hypotheses, hex, transforms, etc.
```

---

## Key Data Contracts

### `Finding` (`core/report.py`)
Every analyzer returns `List[Finding]`. Fields:
- `title: str` — short description
- `severity: str` — `"HIGH"`, `"MEDIUM"`, `"LOW"`, `"INFO"`
- `description: str` — detail text shown in the UI
- `confidence: float` — 0.0–1.0, set by `core/confidence.py`
- `byte_offset: int | None` — location in file (enables hex viewer jump)
- `data: bytes | None` — raw extracted blob for re-dispatch
- `tags: list[str]` — e.g. `["flag_match", "base64", "xor"]`

### `ExtractedContent` (`core/extracted_content.py`)
Wrap decoded/decompressed bytes here before returning them from an analyzer. The `ContentRedispatcher` reads this type and routes it back through `dispatcher.py`.

### `KeyRegistry` (`core/key_registry.py`)
Session-scoped singleton. Call `KeyRegistry.register(key_type, value)` from any analyzer to make a discovered key available globally (e.g., a ZIP password found in a `.txt` file will be tried automatically against any encrypted archive in the session).

---

## Adding a New Analyzer

1. **Create** `analyzers/my_analyzer.py`:

```python
from .base import BaseAnalyzer
from core.report import Finding

class MyAnalyzer(BaseAnalyzer):
    NAME = "My Analyzer"           # shown in UI progress bar
    ALWAYS_RUN = False             # True = runs on every file type

    def analyze(self, file_path: str, data: bytes, mode: str) -> list[Finding]:
        """
        mode: "fast" | "deep" | "auto"
        Return an empty list if nothing found — never raise.
        """
        findings = []
        # ... detection logic ...
        return findings
```

2. **Register** it in `core/dispatcher.py`:
   - Add to `ALWAYS_RUN_ANALYZERS` list if `ALWAYS_RUN = True`, **or**
   - Add a file-type condition in `_select_analyzers()`.

3. **Tag findings** — use existing tags where possible (`flag_match`, `entropy_high`, `xor`, `base64`, `steg`, `crypto`, etc.) so the Hypothesis Engine can correlate them with existing rules.

4. **Respect `mode`** — skip expensive loops/brute-force when `mode == "fast"`.

5. **Register keys** — call `KeyRegistry.register(...)` for any cryptographic key or password discovered.

6. **Tests** — add a test file under `tests/analyzers/test_my_analyzer.py` (see existing test files for the pattern).

---

## Adding a New Hypothesis Rule

Open `core/hypothesis_engine.py`. Each rule is a dict in the `RULES` list:

```python
{
    "id": "my_rule_001",
    "category": "steg",          # pwn | rev | crypto | steg | forensics | web
    "title": "Hidden LSB payload in image",
    "confidence_base": 0.65,
    "required_tags": ["steg", "lsb"],
    "supporting_tags": ["entropy_low", "flag_match"],
    "next_steps": "Run zsteg or stegsolve on the image.",
    "commands": ["zsteg challenge.png", "stegsolve challenge.png"],
    "transform_pipeline": ["lsb_extract", "base64_decode"],
}
```

- `required_tags`: all must appear in the session's findings for the rule to fire.
- `supporting_tags`: each match boosts `confidence_base` by `+0.05`.
- Confidence is capped at `0.99` by `confidence.py`.

---

## Adding a New Transform Step

Open `ui/transform_pipeline.py`. Each step is registered in `TRANSFORM_REGISTRY`:

```python
TRANSFORM_REGISTRY["my_transform"] = {
    "label": "My Transform",
    "fn": lambda data, params: my_transform_fn(data, params),
    "params": [{"name": "key", "type": "hex", "default": "00"}],
}
```

`fn` receives `bytes` and a `dict` of param values; it must return `bytes`.

---

## Adding a New UI Tab / Panel

1. Create `ui/my_tab.py` with a class extending `QWidget`.
2. Import and instantiate it in `ui/main_window.py`.
3. Add it to the `QTabWidget` in `MainWindow._build_tabs()`.

---

## Analysis Modes — Behavioral Contract

| Mode | Expectation |
|------|-------------|
| `fast` | Return in < 2 s per file. Skip brute-force, extended entropy scans, nested archive extraction, LSB chi-square. |
| `deep` | Exhaustive. All checks enabled, including brute-force key search and frequency-domain steg. |
| `auto` | Run `fast` first, then selectively re-run `deep`-only checks only on high-confidence regions (confidence ≥ 0.6). |

Analyzers must honor `mode` — guard expensive code with `if mode == "deep":`.

---

## Confidence Scoring Reference (`core/confidence.py`)

| Signal | Delta |
|--------|-------|
| Flag pattern match in decoded output | +0.20 |
| Entropy reduction after decoding | +0.10 |
| Second independent analyzer corroborates same byte range | +0.15 |
| High-entropy or non-printable garbage in output | −0.15 |
| Hard cap | 0.99 |

---

## AI Integration (`core/ai_client.py`)

- Model: `claude-sonnet-4` (do not change without updating token budgets).
- Called from: `hypothesis_engine.py` (top 15 findings), `challenge_panel.py` (free-text), `disassembly.py` (assembly summary).
- API key is stored in settings, never hard-coded.
- All AI calls are **optional** — every code path must degrade gracefully when no key is set.

---

## Optional Dependencies — Graceful Degradation Pattern

```python
try:
    import pytsk3
    HAS_PYTSK3 = True
except ImportError:
    HAS_PYTSK3 = False

# Inside analyze():
if not HAS_PYTSK3:
    return [Finding("Sleuth Kit unavailable", "INFO", "Install pytsk3 for disk image forensics.")]
```

Follow this pattern for: `pytsk3`, `frida`, `pycryptodome`, `r2pipe`, `scapy`.

---

## CLI Output Formats

`cli.py` supports `text`, `json`, `markdown`, `csv`, `html`. When adding new Finding fields, update all five formatters in `cli.py` and the export functions in `core/report.py`.

---

## Session Format (`.ctfs`)

Sessions are JSON. Schema lives in `ui/session.py`. Backwards compatibility: always use `session.get("field", default)` when reading — never assume a field exists (older sessions may lack newer fields).

---

## Build

```bash
cd ctf_hunter
pip install -r requirements.txt
python main.py               # GUI
python main.py --cli --help  # CLI
python build.py              # PyInstaller → dist/ctf_hunter[.exe]
```

The bundled wordlist (`wordlists/rockyou_top1000.txt`) is included automatically by `build.py`. Frida is attempted as optional inclusion.

---

## External Tool Mapping (`core/tool_suggester.py`)

To map new analyzer findings to an external tool recommendation, add an entry to `TOOL_MAP`:

```python
"my_tag": {
    "tools": ["mytool"],
    "install": "apt install mytool",
    "usage": "mytool {file}",
}
```

`{file}` is substituted with the target file path at display time.

---

## Common Pitfalls

- **Never raise** inside `analyze()` — catch all exceptions and return an `INFO` finding describing the error.
- **Never block the main thread** — all analysis runs in `core/dispatcher.py`'s thread pool. UI updates must go through Qt signals.
- **Deduplication** — `core/deduplicator.py` merges findings with identical `(title, byte_offset)` pairs. Emit one precise finding rather than many near-duplicates.
- **Re-dispatch loop** — `ExtractedContent` objects returned from analyzers are re-routed automatically (max 5 levels, 45 s). Do not manually call other analyzers from within an analyzer.
- **Key registration order** — `KeyRegistry` is flushed between sessions, not between files. Keys from file A are available when analyzing file B in the same session.
