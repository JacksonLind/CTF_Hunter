"""
Git Repository Forensics analyzer.

Discovers hidden/deleted content in git repositories by examining refs,
orphaned objects, and remote history.

Accepted inputs
    .bundle file         — git bundle; cloned to a temp dir for analysis
    .git directory       — bare or non-bare local repo (path to the .git dir)
    repo root directory  — a directory that contains a .git subdirectory
    URL text file        — a text file whose content begins with or contains
                           a GitHub / GitLab HTTPS URL

Fast mode
    • List all refs (including pull-request refs refs/pull/*/head)
    • Scan recent commit messages (up to 200) for flag pattern
    • Report dangling-object count from git fsck

Deep mode  (all of fast mode, plus)
    • Fetch and inspect content of each dangling commit / blob
    • Call the GitHub Events API for deleted-branch push events
    • Attempt to retrieve hidden PR refs via git ls-remote
    • Scan tree listings of interesting commits for flag pattern
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional, Tuple

from core.report import Finding
from core.ai_client import AIClient
from .base import Analyzer

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_GIT_CMD          = "git"
_CMD_TIMEOUT      = 30          # seconds per git command
_MAX_COMMITS      = 500         # commit log scan limit
_MAX_BLOB_BYTES   = 8_192       # max bytes to read from a dangling blob
_MAX_DANGLING     = 50          # max dangling objects to inspect in deep mode

_GITHUB_URL_RE = re.compile(
    r"https?://(?:www\.)?github\.com/([\w.\-]+)/([\w.\-]+?)(?:\.git)?(?:/|$)",
    re.IGNORECASE,
)
_GITLAB_URL_RE = re.compile(
    r"https?://(?:www\.)?gitlab\.com/([\w.\-/]+?)(?:\.git)?(?:/|$)",
    re.IGNORECASE,
)
_PR_REF_RE = re.compile(r"refs/pull/(\d+)/head")
_SHA_RE    = re.compile(r"\b([0-9a-fA-F]{40})\b")
_OBJ_RE    = re.compile(r"dangling (commit|blob|tree)\s+([0-9a-fA-F]{40})")


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class GitForensicsAnalyzer(Analyzer):
    """Enumerate hidden refs, dangling objects, and remote history in git repos."""

    def analyze(
        self,
        path: str,
        flag_pattern: re.Pattern,
        depth: str,
        ai_client: Optional[AIClient],
        session=None,
        dispatcher_module=None,
        **_kw,
    ) -> List[Finding]:
        findings: List[Finding] = []

        # Verify git is installed — fast fail otherwise
        if not _git_available():
            return [self._finding(
                path,
                "Git not available — install git to enable repo forensics",
                "PATH does not contain a 'git' executable.",
                severity="INFO",
                confidence=0.3,
            )]

        try:
            p = Path(path)

            # ── Route by input type ─────────────────────────────────────
            if p.is_dir():
                if p.name == ".git":
                    # Received the bare .git directory
                    findings.extend(
                        self._scan_local_repo(str(p.parent), path, flag_pattern, depth)
                    )
                elif (p / ".git").is_dir():
                    # Received the repo working-tree root
                    findings.extend(
                        self._scan_local_repo(path, str(p / ".git"), flag_pattern, depth)
                    )
                else:
                    return []

            elif p.suffix.lower() == ".bundle":
                findings.extend(self._scan_bundle(path, flag_pattern, depth))

            else:
                # Try to read as text and extract a remote URL
                url, owner, repo_name = _extract_github_url(path)
                if url:
                    findings.extend(
                        self._scan_remote_url(path, url, owner, repo_name,
                                               flag_pattern, depth)
                    )
                else:
                    return []

        except Exception as exc:
            findings.append(self._finding(
                path, "Git forensics error",
                f"{type(exc).__name__}: {exc}",
                severity="INFO", confidence=0.1,
            ))

        self._run_redispatch_hook(findings, session, dispatcher_module)
        return findings

    # ------------------------------------------------------------------
    # Bundle scanning
    # ------------------------------------------------------------------

    def _scan_bundle(
        self,
        path: str,
        flag_pattern: re.Pattern,
        depth: str,
    ) -> List[Finding]:
        findings: List[Finding] = []
        tmp_dir: Optional[str] = None

        try:
            # Verify the bundle
            heads_out, heads_err, rc = _run_git(
                ["bundle", "list-heads", path], timeout=_CMD_TIMEOUT
            )
            if rc != 0:
                findings.append(self._finding(
                    path, "Git bundle: invalid or corrupt",
                    heads_err.strip()[:400],
                    severity="INFO", confidence=0.4,
                ))
                return findings

            ref_lines = [l.strip() for l in heads_out.splitlines() if l.strip()]
            pr_refs   = [l for l in ref_lines if _PR_REF_RE.search(l)]

            findings.append(self._finding(
                path,
                f"Git bundle: {len(ref_lines)} ref(s) found",
                "Bundle refs:\n" + "\n".join(ref_lines[:40]),
                severity="MEDIUM" if ref_lines else "INFO",
                confidence=0.75,
            ))

            if pr_refs:
                findings.append(self._finding(
                    path,
                    f"Git bundle: {len(pr_refs)} pull-request ref(s) found",
                    "\n".join(pr_refs),
                    severity="MEDIUM", confidence=0.80,
                ))

            # Clone the bundle into a temp dir for full analysis
            tmp_dir = tempfile.mkdtemp(prefix="ctfhunter_git_")
            _, clone_err, rc = _run_git(
                ["clone", path, tmp_dir], timeout=60
            )
            if rc != 0:
                findings.append(self._finding(
                    path, "Git bundle: clone failed",
                    clone_err.strip()[:400],
                    severity="INFO", confidence=0.3,
                ))
                return findings

            git_dir = os.path.join(tmp_dir, ".git")
            findings.extend(
                self._scan_local_repo(tmp_dir, git_dir, flag_pattern, depth)
            )

        finally:
            if tmp_dir:
                try:
                    shutil.rmtree(tmp_dir, ignore_errors=True)
                except Exception:
                    pass

        return findings

    # ------------------------------------------------------------------
    # Local repo scanning
    # ------------------------------------------------------------------

    def _scan_local_repo(
        self,
        repo_root: str,
        git_dir: str,
        flag_pattern: re.Pattern,
        depth: str,
    ) -> List[Finding]:
        findings: List[Finding] = []

        # ── 1. All refs (includes PR refs if repo was fetched with them) ─
        refs_out, _, _ = _run_git(
            ["--git-dir", git_dir, "show-ref", "--head"],
            timeout=_CMD_TIMEOUT,
        )
        if not refs_out:
            refs_out, _, _ = _run_git(
                ["--git-dir", git_dir, "for-each-ref",
                 "--format=%(objectname) %(refname)"],
                timeout=_CMD_TIMEOUT,
            )

        ref_lines = [l.strip() for l in refs_out.splitlines() if l.strip()]
        pr_refs   = [l for l in ref_lines if _PR_REF_RE.search(l)]

        if ref_lines:
            findings.append(self._finding(
                repo_root,
                f"Git repo: {len(ref_lines)} ref(s) enumerated",
                "\n".join(ref_lines[:60]),
                severity="INFO", confidence=0.70,
            ))

        if pr_refs:
            pr_detail = "\n".join(pr_refs)
            fm = self._check_flag(pr_detail, flag_pattern)
            findings.append(self._finding(
                repo_root,
                f"Git repo: {len(pr_refs)} pull-request ref(s) found",
                pr_detail,
                severity="HIGH" if fm else "MEDIUM",
                flag_match=fm, confidence=0.82,
            ))

        # ── 2. Commit log — messages ──────────────────────────────────
        log_out, _, _ = _run_git(
            ["--git-dir", git_dir, "log", "--all",
             f"--max-count={_MAX_COMMITS}",
             "--format=%H %ae %s"],
            timeout=_CMD_TIMEOUT,
        )
        commit_lines = [l.strip() for l in log_out.splitlines() if l.strip()]
        n_commits    = len(commit_lines)

        flag_commits: list[str] = []
        for line in commit_lines:
            if self._check_flag(line, flag_pattern):
                flag_commits.append(line)

        if n_commits:
            findings.append(self._finding(
                repo_root,
                f"Git repo: {n_commits} commit(s) in history (all refs)",
                (f"Flag match(es) in commit messages: {len(flag_commits)}\n\n"
                 if flag_commits else "") + "\n".join(commit_lines[:30]),
                severity="INFO", confidence=0.65,
            ))

        if flag_commits:
            detail = "\n".join(flag_commits)
            findings.append(self._finding(
                repo_root,
                f"Flag pattern in {len(flag_commits)} commit message(s)",
                detail,
                severity="HIGH", flag_match=True, confidence=0.95,
            ))

        # ── 3. Dangling / orphaned objects ────────────────────────────
        fsck_out, _, _ = _run_git(
            ["--git-dir", git_dir, "fsck",
             "--unreachable", "--no-reflogs", "--no-progress"],
            timeout=_CMD_TIMEOUT,
        )
        dangling = _OBJ_RE.findall(fsck_out)

        if dangling:
            d_commits = [(t, s) for t, s in dangling if t == "commit"]
            d_blobs   = [(t, s) for t, s in dangling if t == "blob"]
            d_trees   = [(t, s) for t, s in dangling if t == "tree"]
            findings.append(self._finding(
                repo_root,
                f"Git repo: {len(dangling)} dangling object(s) "
                f"({len(d_commits)} commits, {len(d_blobs)} blobs, "
                f"{len(d_trees)} trees)",
                "\n".join(
                    f"{t} {s}"
                    for t, s in dangling[:30]
                ),
                severity="MEDIUM", confidence=0.80,
            ))

            # Deep mode: inspect dangling object content
            if depth == "deep":
                findings.extend(
                    self._inspect_dangling(
                        repo_root, git_dir, dangling, flag_pattern
                    )
                )

        # ── 4. Stash ──────────────────────────────────────────────────
        stash_out, _, _ = _run_git(
            ["--git-dir", git_dir, "stash", "list"],
            timeout=_CMD_TIMEOUT,
        )
        stash_lines = [l for l in stash_out.splitlines() if l.strip()]
        if stash_lines:
            fm = any(self._check_flag(l, flag_pattern) for l in stash_lines)
            findings.append(self._finding(
                repo_root,
                f"Git repo: {len(stash_lines)} stash entry(ies) found",
                "\n".join(stash_lines),
                severity="HIGH" if fm else "MEDIUM",
                flag_match=fm, confidence=0.82,
            ))

        # ── 5. Deep: full commit content scan ─────────────────────────
        if depth == "deep" and commit_lines:
            findings.extend(
                self._scan_commit_content(
                    repo_root, git_dir, commit_lines, flag_pattern
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Remote URL scanning
    # ------------------------------------------------------------------

    def _scan_remote_url(
        self,
        path: str,
        url: str,
        owner: str,
        repo_name: str,
        flag_pattern: re.Pattern,
        depth: str,
    ) -> List[Finding]:
        findings: List[Finding] = []

        findings.append(self._finding(
            path,
            f"GitHub repo URL detected: {owner}/{repo_name}",
            f"URL: {url}",
            severity="INFO", confidence=0.70,
        ))

        # ── ls-remote: all refs including PR refs ─────────────────────
        lsr_out, lsr_err, rc = _run_git(
            ["ls-remote", "--refs", "--heads", "--tags", url],
            timeout=_CMD_TIMEOUT,
        )

        if rc != 0:
            # Try including PR refs explicitly
            lsr_out, lsr_err, rc = _run_git(
                ["ls-remote", url, "HEAD",
                 "refs/heads/*", "refs/tags/*", "refs/pull/*/head"],
                timeout=_CMD_TIMEOUT,
            )

        if rc != 0:
            findings.append(self._finding(
                path,
                f"git ls-remote failed for {url}",
                lsr_err.strip()[:400],
                severity="INFO", confidence=0.3,
            ))
        else:
            ref_lines = [l.strip() for l in lsr_out.splitlines() if l.strip()]
            pr_refs   = [l for l in ref_lines if _PR_REF_RE.search(l)]

            if ref_lines:
                fm = any(self._check_flag(l, flag_pattern) for l in ref_lines)
                findings.append(self._finding(
                    path,
                    f"git ls-remote: {len(ref_lines)} ref(s) "
                    f"({len(pr_refs)} PR ref(s))",
                    "\n".join(ref_lines[:60]),
                    severity="HIGH" if fm else "MEDIUM",
                    flag_match=fm, confidence=0.85,
                ))

            if pr_refs:
                pr_detail = "\n".join(pr_refs)
                fm = self._check_flag(pr_detail, flag_pattern)
                findings.append(self._finding(
                    path,
                    f"Hidden PR ref(s) found: {len(pr_refs)} pull-request(s)",
                    pr_detail,
                    severity="HIGH" if fm else "MEDIUM",
                    flag_match=fm, confidence=0.88,
                ))

        # ── Deep: GitHub Events API ───────────────────────────────────
        if depth == "deep" and owner and repo_name:
            findings.extend(
                self._query_github_events(path, owner, repo_name, flag_pattern)
            )

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _inspect_dangling(
        self,
        repo_root: str,
        git_dir: str,
        dangling: list[Tuple[str, str]],
        flag_pattern: re.Pattern,
    ) -> List[Finding]:
        findings: List[Finding] = []
        inspected = 0

        for obj_type, sha in dangling[:_MAX_DANGLING]:
            if inspected >= _MAX_DANGLING:
                break
            content, _, rc = _run_git(
                ["--git-dir", git_dir, "cat-file", "-p", sha],
                timeout=15,
            )
            if rc != 0 or not content:
                continue
            inspected += 1

            # Truncate large blobs
            content_trunc = content[:_MAX_BLOB_BYTES]
            fm = self._check_flag(content_trunc, flag_pattern)

            if fm or obj_type == "commit":
                findings.append(self._finding(
                    repo_root,
                    f"Dangling {obj_type} {sha[:12]}"
                    + (" — flag match!" if fm else ""),
                    content_trunc[:600],
                    severity="HIGH" if fm else "MEDIUM",
                    flag_match=fm,
                    confidence=0.90 if fm else 0.72,
                ))

        return findings

    def _scan_commit_content(
        self,
        repo_root: str,
        git_dir: str,
        commit_lines: list[str],
        flag_pattern: re.Pattern,
    ) -> List[Finding]:
        """Show full diff + tree for each commit; stop on first flag match."""
        findings: List[Finding] = []
        for line in commit_lines[:_MAX_COMMITS]:
            m = _SHA_RE.match(line)
            if not m:
                continue
            sha = m.group(1)
            show_out, _, rc = _run_git(
                ["--git-dir", git_dir, "show", "--stat",
                 "--format=%H %ae%n%s%n%b", sha],
                timeout=20,
            )
            if rc != 0 or not show_out:
                continue
            fm = self._check_flag(show_out, flag_pattern)
            if fm:
                findings.append(self._finding(
                    repo_root,
                    f"Flag pattern in commit content {sha[:12]}",
                    show_out[:800],
                    severity="HIGH", flag_match=True, confidence=0.95,
                ))
                break  # one confirmed flag is enough for deep scan
        return findings

    def _query_github_events(
        self,
        path: str,
        owner: str,
        repo_name: str,
        flag_pattern: re.Pattern,
    ) -> List[Finding]:
        """Call the GitHub public Events API looking for deleted branches / force-pushes."""
        try:
            import urllib.request, json as _json
            api_url = (
                f"https://api.github.com/repos/{owner}/{repo_name}/events"
                "?per_page=100"
            )
            req = urllib.request.Request(
                api_url,
                headers={"User-Agent": "CTF-Hunter/1.0",
                         "Accept": "application/vnd.github+json"},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                events = _json.loads(resp.read().decode("utf-8", errors="replace"))
        except Exception as exc:
            return [self._finding(
                path, "GitHub Events API unavailable",
                str(exc)[:300],
                severity="INFO", confidence=0.3,
            )]

        if not isinstance(events, list):
            return []

        findings: List[Finding] = []
        delete_events: list[str] = []
        push_shas:     list[str] = []
        flag_events:   list[str] = []

        for ev in events:
            ev_type   = ev.get("type", "")
            ev_str    = str(ev)
            payload   = ev.get("payload", {})
            ref       = payload.get("ref", "") or payload.get("ref_name", "")
            push_id   = payload.get("push_id", "")

            if ev_type == "DeleteEvent":
                delete_events.append(f"Deleted {payload.get('ref_type','')} '{ref}'")
            if ev_type == "PushEvent":
                for commit in payload.get("commits", []):
                    push_shas.append(commit.get("sha", "")[:12])
            if self._check_flag(ev_str, flag_pattern):
                flag_events.append(ev_str[:300])

        if delete_events:
            findings.append(self._finding(
                path,
                f"GitHub Events: {len(delete_events)} branch/tag deletion(s) found",
                "\n".join(delete_events[:20]),
                severity="MEDIUM", confidence=0.80,
            ))

        if push_shas:
            findings.append(self._finding(
                path,
                f"GitHub Events: {len(push_shas)} commit SHA(s) from push events",
                "SHAs (may include deleted-branch commits):\n"
                + " ".join(push_shas[:40]),
                severity="INFO", confidence=0.65,
            ))

        if flag_events:
            findings.append(self._finding(
                path,
                f"Flag pattern in {len(flag_events)} GitHub event(s)",
                "\n---\n".join(flag_events[:5]),
                severity="HIGH", flag_match=True, confidence=0.95,
            ))

        return findings


# ---------------------------------------------------------------------------
# Module helpers
# ---------------------------------------------------------------------------

def _run_git(
    args: list[str],
    cwd: Optional[str] = None,
    timeout: int = _CMD_TIMEOUT,
) -> Tuple[str, str, int]:
    """Run a git sub-command safely (no shell=True).

    Returns (stdout, stderr, returncode).  Returns ("", error_msg, -1) on
    timeout or if git is not found.
    """
    try:
        result = subprocess.run(
            [_GIT_CMD] + args,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "git command timed out", -1
    except FileNotFoundError:
        return "", "git not found in PATH", -1
    except OSError as exc:
        return "", str(exc), -1


def _git_available() -> bool:
    """Return True if the git executable is available."""
    _, _, rc = _run_git(["--version"])
    return rc == 0


def _extract_github_url(path: str) -> Tuple[str, str, str]:
    """Read a file and extract the first GitHub / GitLab HTTPS URL.

    Returns (url, owner, repo_name) or ("", "", "") if none found.
    """
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except Exception:
        return "", "", ""

    m = _GITHUB_URL_RE.search(text)
    if m:
        owner     = m.group(1)
        repo_name = m.group(2).rstrip(".git").rstrip("/")
        url       = f"https://github.com/{owner}/{repo_name}.git"
        return url, owner, repo_name

    m = _GITLAB_URL_RE.search(text)
    if m:
        slug = m.group(1).rstrip(".git").rstrip("/")
        url  = f"https://gitlab.com/{slug}.git"
        return url, slug.split("/")[0] if "/" in slug else slug, ""

    return "", "", ""
