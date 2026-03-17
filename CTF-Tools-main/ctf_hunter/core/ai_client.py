"""
Claude AI client wrapper for CTF Hunter.
Uses the Anthropic Python SDK with claude-sonnet-4-20250514.
"""
from __future__ import annotations

import json
import os
from typing import List, Optional

_ANTHROPIC_AVAILABLE = False
try:
    import anthropic
    _ANTHROPIC_AVAILABLE = True
except ImportError:
    pass

MODEL = "claude-sonnet-4-20250514"
MAX_TOKENS = 1024
# Maximum characters of description / findings included in a single prompt
# to stay comfortably within the model's context window.
_MAX_DESCRIPTION_LENGTH = 3000
_MAX_FINDINGS_LENGTH = 3000


class AIClient:
    """Wraps the Anthropic Claude API; silently disabled if key is not set."""

    def __init__(self, api_key: Optional[str] = None):
        self._key: Optional[str] = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self._client = None
        self._init_client()

    def _init_client(self) -> None:
        if _ANTHROPIC_AVAILABLE and self._key:
            try:
                self._client = anthropic.Anthropic(api_key=self._key)
            except Exception:
                self._client = None

    def set_api_key(self, key: str) -> None:
        self._key = key
        self._init_client()

    @property
    def available(self) -> bool:
        return self._client is not None

    def _ask(self, prompt: str) -> str:
        if not self.available:
            return ""
        try:
            response = self._client.messages.create(
                model=MODEL,
                max_tokens=MAX_TOKENS,
                messages=[{"role": "user", "content": prompt}],
            )
            return response.content[0].text if response.content else ""
        except Exception as exc:
            return f"[AI error: {exc}]"

    def complete_with_system(self, system_prompt: str, user_message: str) -> str:
        """Send a message with an explicit system prompt; returns raw response text."""
        if not self.available:
            return ""
        try:
            response = self._client.messages.create(
                model=MODEL,
                max_tokens=MAX_TOKENS,
                system=system_prompt,
                messages=[{"role": "user", "content": user_message}],
            )
            return response.content[0].text if response.content else ""
        except Exception as exc:
            return f"[AI error: {exc}]"

    def analyze_findings(
        self,
        file_path: str,
        findings_summary: str,
        hex_context: str,
    ) -> str:
        """Return plain-English attack hypothesis for a single file."""
        prompt = (
            f"You are a CTF (Capture the Flag) challenge analyst. "
            f"Analyze the following findings for the file '{file_path}' and provide a "
            f"concise plain-English hypothesis about what steganographic, cryptographic, "
            f"or forensic technique might be hiding the flag.\n\n"
            f"Findings:\n{findings_summary}\n\n"
            f"Hex context (256 bytes around highest-confidence offset):\n{hex_context}\n\n"
            f"Provide a numbered list of the most likely attack paths to try."
        )
        return self._ask(prompt)

    def explain_disassembly(self, asm_text: str) -> str:
        """Return plain-English summary of disassembled code."""
        prompt = (
            "You are a reverse-engineering expert. Summarize the following x86/x64/ARM "
            "disassembly in plain English, avoiding heavy jargon. Focus on what the code "
            "does at a high level, any suspicious operations, and any patterns relevant to "
            "a CTF challenge.\n\n"
            f"Assembly:\n{asm_text[:4000]}"
        )
        return self._ask(prompt)

    def holistic_analysis(self, all_findings_summary: str) -> str:
        """Return prioritized recommendation across all files in the session."""
        prompt = (
            "You are a CTF competition analyst. Below are findings from multiple files "
            "in a CTF challenge session. Identify the most promising lead and explain "
            "step-by-step what to investigate first.\n\n"
            f"All findings:\n{all_findings_summary[:6000]}"
        )
        return self._ask(prompt)

    def analyze_binary(
        self,
        file_path: str,
        high_complexity_functions: "list[dict]",
        flagged_imports: "list[str]",
        crypto_constants: "list[str]",
        xref_strings: "list[str]",
    ) -> str:
        """Return a structured CTF attack plan from all binary-analysis data.

        Sends a rich JSON context to Claude that ties together the outputs of
        Steps 4–7 into a single prioritised attack plan.  The payload includes:

        * ``high_complexity_functions`` – decompiled pseudocode (or pdf text)
          for the most complex / interesting functions.
        * ``flagged_imports``          – dangerous import names found in the binary.
        * ``crypto_constants``         – cryptographic primitives detected by
          byte-pattern search.
        * ``xref_strings``             – strings with caller cross-references.

        This is the highest-value AI output in the pipeline because it reasons
        across all data simultaneously rather than commenting on each finding
        in isolation.
        """
        # Truncate pseudocode fields proportionally *before* serialisation so
        # that the JSON sent to the API is always syntactically valid.  A blind
        # [:5000] on the already-serialised string risks cutting in the middle
        # of a string literal or key, producing malformed JSON.
        funcs = high_complexity_functions[:10]
        if funcs:
            # Distribute a 3 000-character budget evenly across all functions.
            per_func_budget = max(100, 3000 // len(funcs))
            funcs = [
                {**f, "pseudocode": (f.get("pseudocode") or "")[:per_func_budget]}
                for f in funcs
            ]

        payload = {
            "file": file_path,
            "high_complexity_functions": funcs,
            "flagged_imports": flagged_imports,
            "crypto_constants": crypto_constants,
            "xref_strings": xref_strings[:30],
        }
        payload_json = json.dumps(payload, indent=2)

        # System prompt instructs Claude to go straight to the attack plan
        # without spending tokens re-describing the input format.
        system_prompt = (
            "You are an expert reverse-engineer and CTF competition analyst. "
            "The user message contains structured JSON produced by radare2. "
            "Do NOT describe or re-explain what the JSON contains — go straight "
            "to the analysis. Your only output should be a numbered, prioritised "
            "CTF attack plan.\n\n"
            "When analysing the data:\n"
            "1. Identify the most suspicious decompiled functions — look for loops "
            "   with XOR/shift operations, comparisons against static buffers, "
            "   string-decryption patterns, or recursion.\n"
            "2. Cross-reference flagged imports with detected crypto constants — "
            "   e.g. 'system' + AES S-box implies a shell is spawned post-decryption.\n"
            "3. Use xref_strings to map interesting literals to their callers and "
            "   pinpoint flag comparison or decryption routines.\n"
            "4. Treat LD_PRELOAD hooks and constructor functions as highest priority.\n"
            "5. Be concise and actionable. Do not restate the input."
        )

        if not self.available:
            return ""
        try:
            response = self._client.messages.create(
                model=MODEL,
                max_tokens=1500,
                system=system_prompt,
                messages=[{
                    "role": "user",
                    "content": (
                        f"Analyse this binary and produce a CTF attack plan.\n\n"
                        f"Analysis data (JSON):\n{payload_json}"
                    ),
                }],
            )
            return response.content[0].text if response.content else ""
        except Exception as exc:
            return f"[AI error: {exc}]"

    def parse_challenge_description(
        self,
        description: str,
        findings: str,
    ) -> str:
        """Return a prioritized attack plan derived from a CTF challenge description."""
        prompt = (
            "You are an expert CTF (Capture the Flag) competition analyst. "
            "Analyze the following challenge description and current file analysis findings.\n\n"
            "Your task:\n"
            "1. Extract all implied techniques and file types from the description\n"
            "2. Identify keywords suggesting specific steganography, cryptography, "
            "or forensics methods\n"
            "3. Flag any likely rabbit holes (misleading clues) and explain why\n"
            "4. Produce a numbered, prioritized attack plan\n"
            "5. Suggest which files to analyze first and why\n\n"
            f"Challenge description:\n{description[:_MAX_DESCRIPTION_LENGTH]}\n\n"
            f"Current file findings:\n{findings[:_MAX_FINDINGS_LENGTH]}\n\n"
            "Respond with a concise, actionable attack plan."
        )
        return self._ask(prompt)
