"""
Multi-Stage Cross-File Attack Chain Builder for CTF Hunter.

Constructs a directed data-flow graph from a workspace of findings and
enumerates the top-N multi-stage attack chains that link discoveries
across files.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .report import Finding
from .key_registry import KeyRegistry


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ChainStep:
    """One step in a multi-stage cross-file attack chain."""

    file: str           # Source file for this step
    finding: Finding    # The finding that contributes at this step
    transform: str      # Name of transform to apply (matches pipeline names where possible)
    transform_param: str = ""  # Optional parameter for the transform (e.g. XOR key)
    rationale: str = ""        # Human-readable explanation of why this link exists


Chain = List[ChainStep]


# ---------------------------------------------------------------------------
# Transform keyword detection helpers
# ---------------------------------------------------------------------------

# Ordered mapping: keyword → (transform_name, default_param)
_TRANSFORM_KEYWORDS: List[Tuple[str, str, str]] = [
    ("base64",      "Base64 Decode",      ""),
    ("b64",         "Base64 Decode",      ""),
    ("hex encod",   "Hex Decode",         ""),
    ("hex string",  "Hex Decode",         ""),
    ("rot-13",      "ROT-N",             "13"),
    ("rot13",       "ROT-N",             "13"),
    ("caesar",      "ROT-N",             ""),
    ("rot-",        "ROT-N",             ""),
    ("xor",         "XOR",               ""),
    ("aes-cbc",     "AES-CBC Decrypt",    ""),
    ("aes-ecb",     "AES-ECB Decrypt",    ""),
    ("aes",         "AES-ECB Decrypt",    ""),
    ("zlib",        "Zlib Decompress",    ""),
    ("deflat",      "Zlib Decompress",    ""),
    ("compress",    "Zlib Decompress",    ""),
    ("url encod",   "URL Decode",         ""),
    ("percent encod", "URL Decode",       ""),
    ("reversal",    "Reverse Bytes",      ""),
    ("reversed",    "Reverse Bytes",      ""),
]

# Keywords indicating an encrypted / ciphertext artifact
_ENCRYPTED_KEYWORDS = frozenset([
    "encrypt", "cipher", "aes", "des", "rsa", "xor",
    "password", "passphrase", "zip password", "locked",
    "ciphertext", "encoded", "obfuscat",
])


def _detect_transform(
    finding_a: Finding,
    finding_b: Finding,
    edge_type: str,
) -> Tuple[str, str]:
    """Heuristically select a pipeline transform name and param for this edge.

    Args:
        finding_a: Source finding (whose output drives the transform).
        finding_b: Destination finding (target artifact).
        edge_type: One of ``"value_match"``, ``"key_registry"``,
            ``"flag_pattern"``.

    Returns:
        ``(transform_name, param)`` matching names in the Transform Pipeline.
    """
    combined = (
        finding_a.title + " " + finding_a.detail + " " +
        finding_b.title + " " + finding_b.detail
    ).lower()

    if edge_type == "key_registry":
        if "xor" in combined:
            return "XOR", ""
        if "aes-cbc" in combined:
            return "AES-CBC Decrypt", ""
        if "aes" in combined:
            return "AES-ECB Decrypt", ""
        if "zip" in combined or "password" in combined:
            return "XOR", ""
        return "XOR", ""

    for kw, tname, tparam in _TRANSFORM_KEYWORDS:
        if kw in combined:
            return tname, tparam

    return "Base64 Decode", ""


# ---------------------------------------------------------------------------
# ChainBuilder
# ---------------------------------------------------------------------------

class ChainBuilder:
    """Build multi-stage cross-file attack chains from a workspace of findings.

    Usage::

        builder = ChainBuilder(workspace, key_registry, flag_pattern)
        chains = builder.build()

    Args:
        workspace: Sequence of ``(filename, findings_list)`` pairs covering
            every file in the analysis session.
        key_registry: Session :class:`~core.key_registry.KeyRegistry` holding
            discovered key candidates.
        flag_pattern: Compiled regex used to look for flag matches.  Defaults
            to the standard ``CTF{...}`` pattern.
    """

    MAX_DEPTH = 5
    TOP_N = 5

    def __init__(
        self,
        workspace: List[Tuple[str, List[Finding]]],
        key_registry: KeyRegistry,
        flag_pattern: Optional[re.Pattern] = None,
    ) -> None:
        self._workspace = workspace
        self._key_registry = key_registry
        self._flag_re = flag_pattern or re.compile(r"CTF\{[^}]+\}", re.IGNORECASE)

        # Nodes: (filename, finding)  — duplicates excluded
        self._nodes: List[Tuple[str, Finding]] = [
            (fname, f)
            for fname, findings in workspace
            for f in findings
            if not f.duplicate_of
        ]

        # Adjacency: node_idx → list of (dst_idx, edge_type, transform, param, rationale)
        self._adj: Dict[int, List[Tuple[int, str, str, str, str]]] = {}
        self._build_graph()

    # ------------------------------------------------------------------
    # Value extraction
    # ------------------------------------------------------------------

    def _extract_values(self, finding: Finding) -> List[str]:
        """Extract significant string tokens from a finding's detail."""
        values: List[str] = []
        detail = finding.detail or ""

        # Quoted strings
        values.extend(re.findall(r'"([^"]{4,})"', detail))
        values.extend(re.findall(r"'([^']{4,})'", detail))

        # Long hex tokens (potential hashes / encoded data)
        values.extend(re.findall(r"\b([0-9a-fA-F]{8,})\b", detail))

        # Base64-like tokens (letters + digits + +/= of 8+ chars)
        values.extend(re.findall(r"([A-Za-z0-9+/]{8,}={0,2})", detail))

        # Long alphanumeric tokens (keys, identifiers, encoded data)
        values.extend(
            tok for tok in re.findall(r"\b([A-Za-z0-9_-]{8,})\b", detail)
            if tok not in values
        )

        # First 256 chars of detail as a value (substring matching)
        stripped = detail.strip()
        if len(stripped) >= 4:
            values.append(stripped[:256])

        return values

    @staticmethod
    def _value_overlap(val_a: str, val_b: str) -> bool:
        """Return True if *val_a* appears as substring in *val_b*, or their hashes match."""
        if not val_a or not val_b or len(val_a) < 4:
            return False
        if val_a in val_b:
            return True
        # MD5 hash of val_a appears in val_b (e.g. a hash stored in another file)
        try:
            h = hashlib.md5(val_a.encode(errors="replace")).hexdigest()
            if h in val_b:
                return True
        except Exception:
            pass
        return False

    # ------------------------------------------------------------------
    # Graph construction
    # ------------------------------------------------------------------

    def _build_graph(self) -> None:
        """Populate the adjacency list with directed edges."""
        # Map: finding_id → list of key types registered from that finding
        key_by_source: Dict[str, List[str]] = {}
        for kc in self._key_registry.get_candidates():
            key_by_source.setdefault(kc.source_finding_id, []).append(kc.key_type)

        # Map: key value → key type (for value-based matching)
        key_values: Dict[str, str] = {
            kc.value: kc.key_type
            for kc in self._key_registry.get_candidates()
        }

        for i, (file_a, finding_a) in enumerate(self._nodes):
            vals_a = self._extract_values(finding_a)
            detail_a_lower = (finding_a.title + " " + finding_a.detail).lower()

            for j, (file_b, finding_b) in enumerate(self._nodes):
                if i == j or file_a == file_b:
                    continue

                detail_b_lower = (finding_b.title + " " + finding_b.detail).lower()
                vals_b = self._extract_values(finding_b)

                edge = (
                    self._check_value_overlap(finding_a, vals_a, finding_b, vals_b)
                    or self._check_key_registry(finding_a, vals_a, finding_b,
                                               detail_b_lower, key_by_source, key_values)
                    or self._check_flag_pattern(finding_a, finding_b, detail_a_lower, vals_b)
                )
                if edge:
                    self._adj.setdefault(i, []).append((j, *edge))

    def _check_value_overlap(
        self,
        finding_a: Finding,
        vals_a: List[str],
        finding_b: Finding,
        vals_b: List[str],
    ) -> Optional[Tuple[str, str, str, str]]:
        """Return edge tuple if a value from finding_a appears in finding_b."""
        for va in vals_a:
            for vb in vals_b:
                if self._value_overlap(va, vb):
                    transform, param = _detect_transform(finding_a, finding_b, "value_match")
                    rationale = (
                        f"Value from '{finding_a.title}' appears in "
                        f"'{finding_b.title}' — potential data flow link"
                    )
                    return ("value_match", transform, param, rationale)
        return None

    def _check_key_registry(
        self,
        finding_a: Finding,
        vals_a: List[str],
        finding_b: Finding,
        detail_b_lower: str,
        key_by_source: Dict[str, List[str]],
        key_values: Dict[str, str],
    ) -> Optional[Tuple[str, str, str, str]]:
        """Return edge tuple if a key from finding_a can unlock finding_b."""
        if not any(kw in detail_b_lower for kw in _ENCRYPTED_KEYWORDS):
            return None

        # Case A: finding_a is the registered source of a key candidate
        if finding_a.id in key_by_source:
            key_types = key_by_source[finding_a.id]
            key_type = key_types[0] if key_types else "generic"
            transform, param = _detect_transform(finding_a, finding_b, "key_registry")
            rationale = (
                f"Key (type: {key_type}) extracted from "
                f"'{finding_a.title}' may unlock encrypted "
                f"artifact in '{finding_b.title}'"
            )
            return ("key_registry", transform, param, rationale)

        # Case B: a value extracted from finding_a matches a registered key
        for va in vals_a:
            if va in key_values:
                key_type = key_values[va]
                transform, param = _detect_transform(finding_a, finding_b, "key_registry")
                rationale = (
                    f"Key '{va[:48]}' (type: {key_type}) from "
                    f"'{finding_a.title}' may unlock encrypted "
                    f"artifact in '{finding_b.title}'"
                )
                return ("key_registry", transform, param, rationale)

        return None

    def _check_flag_pattern(
        self,
        finding_a: Finding,
        finding_b: Finding,
        detail_a_lower: str,
        vals_b: List[str],
    ) -> Optional[Tuple[str, str, str, str]]:
        """Return edge tuple if applying finding_a's transform may reveal the flag."""
        is_transform_source = any(
            kw in detail_a_lower
            for kw in ("base64", "encoded", "obfuscat", "encrypt", "hex string")
        )
        if not is_transform_source:
            return None
        is_flag_destination = finding_b.flag_match or any(
            self._flag_re.search(v) for v in vals_b
        )
        if not is_flag_destination:
            return None
        transform, param = _detect_transform(finding_a, finding_b, "flag_pattern")
        rationale = (
            f"Applying transform from '{finding_a.title}' to content "
            f"in '{finding_b.title}' may reveal the flag"
        )
        return ("flag_pattern", transform, param, rationale)

    # ------------------------------------------------------------------
    # Path enumeration
    # ------------------------------------------------------------------

    def _dfs(
        self,
        node: int,
        visited: set,
        path: List[int],
        results: List[List[int]],
    ) -> None:
        """Depth-first enumeration of all simple paths from *node*."""
        if len(path) >= self.MAX_DEPTH:
            return
        for (dst, *_rest) in self._adj.get(node, []):
            if dst not in visited:
                visited.add(dst)
                path.append(dst)
                results.append(list(path))
                self._dfs(dst, visited, path, results)
                path.pop()
                visited.remove(dst)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build(self) -> List[Chain]:
        """Build and return the top-N attack chains, scored by confidence sum.

        Returns:
            A list of at most :attr:`TOP_N` chains, each a list of
            :class:`ChainStep` objects.  Chains are ordered from highest to
            lowest cumulative confidence.
        """
        all_paths: List[List[int]] = []

        for i in range(len(self._nodes)):
            if i not in self._adj:
                continue
            path = [i]
            visited: set = {i}
            all_paths.append([i])  # single-node "chain" (not emitted unless multi-step)
            self._dfs(i, visited, path, all_paths)

        # Keep only multi-step paths
        multi = [p for p in all_paths if len(p) >= 2]

        # Score: sum of finding confidences
        scored = sorted(
            ((sum(self._nodes[idx][1].confidence for idx in p), p) for p in multi),
            key=lambda x: -x[0],
        )

        # Deduplicate: treat same node-set as equivalent
        seen: set[frozenset] = set()
        top_chains: List[Chain] = []
        for _score, path in scored:
            node_set = frozenset(path)
            if node_set in seen:
                continue
            seen.add(node_set)

            steps: Chain = []
            for k, idx in enumerate(path):
                fname, finding = self._nodes[idx]
                if k == 0:
                    transform = "Initial finding"
                    param = ""
                    rationale = f"Starting point — [{finding.severity}] {finding.title}"
                else:
                    prev_idx = path[k - 1]
                    # Look up edge attributes
                    transform = "Data flow"
                    param = ""
                    rationale = ""
                    for (dst, _etype, t, p, r) in self._adj.get(prev_idx, []):
                        if dst == idx:
                            transform = t
                            param = p
                            rationale = r
                            break
                steps.append(
                    ChainStep(
                        file=fname,
                        finding=finding,
                        transform=transform,
                        transform_param=param,
                        rationale=rationale,
                    )
                )
            top_chains.append(steps)
            if len(top_chains) >= self.TOP_N:
                break

        return top_chains

    # ------------------------------------------------------------------
    # Serialization helpers
    # ------------------------------------------------------------------

    @staticmethod
    def chain_to_dict(chain: Chain) -> List[dict]:
        """Serialize a chain to a JSON-safe list of dicts."""
        return [
            {
                "file": step.file,
                "finding_id": step.finding.id,
                "finding_title": step.finding.title,
                "finding_severity": step.finding.severity,
                "finding_confidence": round(step.finding.confidence, 4),
                "transform": step.transform,
                "transform_param": step.transform_param,
                "rationale": step.rationale,
            }
            for step in chain
        ]

    @classmethod
    def chains_to_text(cls, chains: List[Chain]) -> str:
        """Render chains as numbered multi-line blocks for CLI text output."""
        if not chains:
            return ""
        lines = [
            "",
            "=" * 72,
            "Attack Chains (multi-stage cross-file)",
            "=" * 72,
        ]
        for n, chain in enumerate(chains, 1):
            score = sum(s.finding.confidence for s in chain)
            lines.append(f"\n  Chain #{n}  (score: {score:.2f}, steps: {len(chain)})")
            lines.append("  " + "-" * 50)
            for k, step in enumerate(chain):
                prefix = "  " + ("  → " if k > 0 else "    ")
                fname_short = step.file.split("/")[-1] if step.file else step.file
                lines.append(
                    f"{prefix}[{step.finding.severity}] {step.finding.title}"
                    f"  (conf: {step.finding.confidence:.2f})"
                )
                lines.append(f"{prefix}    File: {fname_short}")
                if k > 0:
                    lines.append(f"{prefix}    Transform: {step.transform}")
                    if step.rationale:
                        lines.append(f"{prefix}    Rationale: {step.rationale}")
        lines.append("")
        return "\n".join(lines) + "\n"
