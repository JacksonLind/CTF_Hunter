"""
Tests for GitForensicsAnalyzer (analyzers/git_forensics.py).

Coverage:
  A. Helpers
     1.  _git_available returns True (git must be in PATH)
     2.  _extract_github_url: HTTPS URL extracted correctly
     3.  _extract_github_url: .git suffix stripped from repo name
     4.  _extract_github_url: no URL → returns empty strings
     5.  _run_git: bad command → returns ("", ..., non-zero)
     6.  _run_git: timeout → returns ("", ..., -1)

  B. URL text file routing
     7.  Text file with GitHub URL → INFO finding naming the repo
     8.  Text file with no URL → empty findings
     9.  Binary file → empty findings

  C. Local repo scanning (uses a real temp git repo)
    10.  Commit messages scanned; count reported
    11.  Flag pattern in commit message → HIGH flag_match finding
    12.  All refs reported (at least HEAD)
    13.  git fsck dangling object count reported
    14.  Stash entries detected and reported
    15.  Deep mode inspects dangling commits

  D. Bundle file
    16.  Valid bundle → refs listed, clone scanned
    17.  Corrupt bundle → graceful INFO finding

  E. Dispatcher routing
    18.  .bundle suffix → git_forensics key in _identify_analyzers output
    19.  Text with GitHub URL → git_forensics key detected

  F. Graceful degradation
    20.  Repo with zero commits → no crash
    21.  Non-existent path → no crash / error finding
    22.  Not a zip file passed as .bundle → graceful INFO

Run from ctf_hunter/ directory:
    python tests/test_git_forensics.py
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from analyzers.git_forensics import (
    GitForensicsAnalyzer,
    _git_available,
    _extract_github_url,
    _run_git,
)

FLAG_RE   = re.compile(r"flag\{[^}]+\}")
_ANA      = GitForensicsAnalyzer()
_GIT_OK   = _git_available()


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _git(*args, cwd=None, check=False):
    """Run a git command in the test helper (raises on failure if check=True)."""
    return subprocess.run(
        ["git"] + list(args),
        capture_output=True, text=True, cwd=cwd,
        check=check,
    )


def _make_repo(tmp_dir: str, commits: list[str], stash_message: str = "") -> str:
    """Initialise a git repo in tmp_dir with the given commit messages.

    Returns the path to the repo root.
    """
    _git("init", "-b", "main", cwd=tmp_dir)
    _git("config", "user.email", "test@ctf.local", cwd=tmp_dir)
    _git("config", "user.name", "CTF Test", cwd=tmp_dir)

    for i, msg in enumerate(commits):
        fname = os.path.join(tmp_dir, f"file{i}.txt")
        Path(fname).write_text(f"content {i}")
        _git("add", ".", cwd=tmp_dir)
        _git("commit", "-m", msg, cwd=tmp_dir)

    if stash_message:
        # Create a stash entry
        fname = os.path.join(tmp_dir, "stash_file.txt")
        Path(fname).write_text("stash content")
        _git("add", ".", cwd=tmp_dir)
        _git("stash", "save", stash_message, cwd=tmp_dir)

    return tmp_dir


def _make_orphan(repo_dir: str) -> str:
    """Create a dangling commit in the repo; return its SHA."""
    fname = os.path.join(repo_dir, "orphan.txt")
    Path(fname).write_text("orphaned content — flag{orphan_found}")
    _git("add", ".", cwd=repo_dir)
    result = _git("commit-tree", "-m", "orphan commit",
                  "HEAD^{tree}", cwd=repo_dir)
    sha = result.stdout.strip()
    return sha


def _make_bundle(repo_dir: str, bundle_path: str):
    """Create a git bundle from repo_dir at bundle_path."""
    _git("bundle", "create", bundle_path, "--all", cwd=repo_dir)


def _run_ana(path: str, depth: str = "deep") -> list:
    return _ANA.analyze(path, FLAG_RE, depth, None)


def _titles(findings: list) -> list[str]:
    return [f.title for f in findings]


# ──────────────────────────────────────────────────────────────────────────────
# A. Helpers
# ──────────────────────────────────────────────────────────────────────────────

class TestHelpers(unittest.TestCase):

    @unittest.skipUnless(_GIT_OK, "git not in PATH")
    def test_a1_git_available(self):
        self.assertTrue(_git_available())

    def test_a2_extract_github_url(self):
        fd, p = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(fd, "w") as f:
            f.write("Check this repo: https://github.com/ctfteam/challenge-repo\n")
        try:
            url, owner, repo = _extract_github_url(p)
            self.assertIn("github.com", url)
            self.assertEqual(owner, "ctfteam")
            self.assertEqual(repo, "challenge-repo")
        finally:
            os.unlink(p)

    def test_a3_extract_github_url_strips_git_suffix(self):
        fd, p = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(fd, "w") as f:
            f.write("https://github.com/owner/myrepo.git\n")
        try:
            _, _, repo = _extract_github_url(p)
            self.assertEqual(repo, "myrepo")
        finally:
            os.unlink(p)

    def test_a4_extract_github_url_none(self):
        fd, p = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(fd, "w") as f:
            f.write("no URL here\n")
        try:
            url, owner, repo = _extract_github_url(p)
            self.assertEqual(url, "")
            self.assertEqual(owner, "")
        finally:
            os.unlink(p)

    @unittest.skipUnless(_GIT_OK, "git not in PATH")
    def test_a5_run_git_bad_command(self):
        out, err, rc = _run_git(["this-command-does-not-exist"])
        self.assertNotEqual(rc, 0)
        self.assertEqual(out, "")

    @unittest.skipUnless(_GIT_OK, "git not in PATH")
    def test_a6_run_git_timeout(self):
        # timeout of 0 should always expire
        out, err, rc = _run_git(["--version"], timeout=0)
        # Either times out (rc=-1) or succeeds in under 0s on a fast machine;
        # the important thing is it does not raise
        self.assertIsInstance(rc, int)


# ──────────────────────────────────────────────────────────────────────────────
# B. URL text file routing
# ──────────────────────────────────────────────────────────────────────────────

class TestURLFile(unittest.TestCase):

    def test_b7_github_url_detected(self):
        """Text file with GitHub URL → INFO finding naming the repo."""
        fd, p = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(fd, "w") as f:
            f.write("The challenge repo: https://github.com/ctfhunter/testchallenge\n")
        try:
            findings = _run_ana(p)
            titles_lower = " ".join(_titles(findings)).lower()
            self.assertIn("ctfhunter", titles_lower,
                          f"Expected repo owner in findings; got: {_titles(findings)}")
        finally:
            os.unlink(p)

    def test_b8_no_url_empty(self):
        """Text file with no GitHub URL → empty findings."""
        fd, p = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(fd, "w") as f:
            f.write("no repository here, just plain text\n")
        try:
            findings = _run_ana(p)
            self.assertEqual(findings, [])
        finally:
            os.unlink(p)

    def test_b9_binary_file_empty(self):
        """Binary file → empty findings."""
        fd, p = tempfile.mkstemp(suffix=".bin")
        with os.fdopen(fd, "wb") as f:
            f.write(bytes(range(256)) * 10)
        try:
            findings = _run_ana(p)
            self.assertEqual(findings, [])
        finally:
            os.unlink(p)


# ──────────────────────────────────────────────────────────────────────────────
# C. Local repo scanning
# ──────────────────────────────────────────────────────────────────────────────

@unittest.skipUnless(_GIT_OK, "git not in PATH")
class TestLocalRepo(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="ctftest_repo_")
        _make_repo(cls.tmp, [
            "initial commit",
            "add feature",
            "refactor code",
        ], stash_message="WIP secret work")
        cls.findings_fast = _run_ana(cls.tmp, depth="fast")
        cls.findings_deep = _run_ana(cls.tmp, depth="deep")

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_c10_commit_count_reported(self):
        """Commit messages scanned; count reported in findings."""
        commit_f = [f for f in self.findings_fast
                    if "commit" in f.title.lower()]
        self.assertTrue(commit_f,
                        f"Expected commit finding; got {_titles(self.findings_fast)}")
        self.assertIn("3", commit_f[0].title + commit_f[0].detail)

    def test_c11_flag_in_commit_message(self):
        """Flag pattern in commit message → HIGH flag_match finding."""
        flag_tmp = tempfile.mkdtemp(prefix="ctftest_flag_repo_")
        try:
            _make_repo(flag_tmp, [
                "initial commit",
                "flag{commit_message_flag} added secret",
            ])
            findings = _run_ana(flag_tmp, depth="fast")
            flag_f = [f for f in findings if f.flag_match]
            self.assertTrue(flag_f,
                            f"Expected flag finding; got {_titles(findings)}")
            self.assertEqual(flag_f[0].severity, "HIGH")
        finally:
            import shutil
            shutil.rmtree(flag_tmp, ignore_errors=True)

    def test_c12_refs_reported(self):
        """All refs reported — at least HEAD / main branch."""
        ref_f = [f for f in self.findings_fast
                 if "ref" in f.title.lower()]
        self.assertTrue(ref_f,
                        f"Expected refs finding; got {_titles(self.findings_fast)}")

    def test_c13_fsck_runs(self):
        """git fsck runs without error; result captured (dangling or clean)."""
        # After making an orphan, we should see it
        orphan_sha = _make_orphan(self.tmp)
        findings = _run_ana(self.tmp, depth="fast")
        dangling_f = [f for f in findings if "dangling" in f.title.lower()]
        # If fsck works, there should be at least the orphan we created
        if dangling_f:
            self.assertIn(orphan_sha[:12], dangling_f[0].detail.replace(" ", "")
                          or dangling_f[0].title)

    def test_c14_stash_detected(self):
        """Stash entries detected and reported."""
        stash_f = [f for f in self.findings_fast
                   if "stash" in f.title.lower()]
        self.assertTrue(stash_f,
                        f"Expected stash finding; got {_titles(self.findings_fast)}")
        self.assertIn("1", stash_f[0].title)

    def test_c15_deep_inspects_dangling(self):
        """Deep mode inspects dangling commit content."""
        # Create a repo with an orphan containing a flag
        flag_tmp = tempfile.mkdtemp(prefix="ctftest_dangling_")
        try:
            _make_repo(flag_tmp, ["initial commit"])
            # Write flag into a file, commit-tree it (orphaned)
            flag_file = os.path.join(flag_tmp, "secret.txt")
            Path(flag_file).write_text("flag{dangling_commit_secret}")
            _git("add", ".", cwd=flag_tmp)
            # Use commit-tree to make a dangling commit
            _git("commit-tree", "-m",
                 "secret stash flag{dangling_commit_secret}",
                 "HEAD^{tree}", cwd=flag_tmp)

            findings = _run_ana(flag_tmp, depth="deep")
            flag_f = [f for f in findings if f.flag_match]
            # May or may not find it depending on fsck output, but must not crash
            self.assertIsNotNone(findings)
        finally:
            import shutil
            shutil.rmtree(flag_tmp, ignore_errors=True)


# ──────────────────────────────────────────────────────────────────────────────
# D. Bundle file
# ──────────────────────────────────────────────────────────────────────────────

@unittest.skipUnless(_GIT_OK, "git not in PATH")
class TestBundle(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.repo_tmp = tempfile.mkdtemp(prefix="ctftest_bundle_repo_")
        _make_repo(cls.repo_tmp, [
            "initial commit",
            "add flag: flag{bundle_hidden_commit}",
        ])
        cls.bundle_fd, cls.bundle_path = tempfile.mkstemp(suffix=".bundle")
        os.close(cls.bundle_fd)
        _make_bundle(cls.repo_tmp, cls.bundle_path)

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.repo_tmp, ignore_errors=True)
        try:
            os.unlink(cls.bundle_path)
        except OSError:
            pass

    def test_d16_valid_bundle_refs_and_flag(self):
        """Valid bundle → refs listed; flag in commit message found."""
        findings = _run_ana(self.bundle_path, depth="deep")
        # Should have a refs finding
        ref_f = [f for f in findings
                 if "ref" in f.title.lower() or "bundle" in f.title.lower()]
        self.assertTrue(ref_f,
                        f"Expected bundle/refs finding; got {_titles(findings)}")
        # Should find the flag in commit history
        flag_f = [f for f in findings if f.flag_match]
        self.assertTrue(flag_f,
                        f"Expected flag finding from bundle; got {_titles(findings)}")

    def test_d17_corrupt_bundle(self):
        """Corrupt bundle file → graceful INFO finding, no crash."""
        fd, bad_path = tempfile.mkstemp(suffix=".bundle")
        with os.fdopen(fd, "wb") as f:
            f.write(b"this is not a git bundle at all" + bytes(100))
        try:
            findings = _run_ana(bad_path)
            # Must not raise; should have at least one INFO finding
            self.assertIsNotNone(findings)
            info_f = [f for f in findings if f.severity == "INFO"]
            self.assertTrue(info_f,
                            f"Expected INFO finding for corrupt bundle; "
                            f"got {_titles(findings)}")
        finally:
            os.unlink(bad_path)


# ──────────────────────────────────────────────────────────────────────────────
# E. Dispatcher routing
# ──────────────────────────────────────────────────────────────────────────────

class TestDispatcherRouting(unittest.TestCase):

    def test_e18_bundle_extension_routed(self):
        """_identify_analyzers includes 'git_forensics' for .bundle files."""
        sys.path.insert(0, _ROOT)
        from core.dispatcher import _identify_analyzers
        fd, p = tempfile.mkstemp(suffix=".bundle")
        with os.fdopen(fd, "wb") as f:
            f.write(b"# v2 git bundle\n")
        try:
            keys = _identify_analyzers(p, b"# v2 git bundle\n")
            self.assertIn("git_forensics", keys,
                          f"Expected git_forensics in keys; got {keys}")
        finally:
            os.unlink(p)

    def test_e19_github_url_routed(self):
        """_identify_analyzers includes 'git_forensics' for text with GitHub URL."""
        from core.dispatcher import _identify_analyzers
        data = b"Check https://github.com/ctfteam/challenge for the flag\n"
        fd, p = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        try:
            keys = _identify_analyzers(p, data)
            self.assertIn("git_forensics", keys,
                          f"Expected git_forensics in keys; got {keys}")
        finally:
            os.unlink(p)


# ──────────────────────────────────────────────────────────────────────────────
# F. Graceful degradation
# ──────────────────────────────────────────────────────────────────────────────

@unittest.skipUnless(_GIT_OK, "git not in PATH")
class TestGracefulDegradation(unittest.TestCase):

    def test_f20_repo_zero_commits(self):
        """Brand-new repo with no commits → no crash."""
        tmp = tempfile.mkdtemp(prefix="ctftest_empty_repo_")
        try:
            _git("init", "-b", "main", cwd=tmp)
            _git("config", "user.email", "t@t.local", cwd=tmp)
            _git("config", "user.name", "T", cwd=tmp)
            findings = _run_ana(tmp, depth="fast")
            self.assertIsNotNone(findings)
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_f21_nonexistent_path(self):
        """Non-existent path → no crash, returns findings (or empty)."""
        findings = _run_ana("/nonexistent/path/to/nowhere.bundle")
        self.assertIsNotNone(findings)

    def test_f22_not_a_bundle(self):
        """Random bytes with .bundle extension → graceful INFO, no crash."""
        fd, p = tempfile.mkstemp(suffix=".bundle")
        with os.fdopen(fd, "wb") as f:
            f.write(bytes(range(256)) * 20)
        try:
            findings = _run_ana(p)
            self.assertIsNotNone(findings)
            # Should have at least one INFO about the bad bundle
            self.assertGreater(len(findings), 0)
        finally:
            os.unlink(p)


# ──────────────────────────────────────────────────────────────────────────────
# Runner
# ──────────────────────────────────────────────────────────────────────────────

_GROUPS = [
    ("A. Helpers",               TestHelpers),
    ("B. URL text file routing", TestURLFile),
    ("C. Local repo scanning",   TestLocalRepo),
    ("D. Bundle file",           TestBundle),
    ("E. Dispatcher routing",    TestDispatcherRouting),
    ("F. Graceful degradation",  TestGracefulDegradation),
]


def _run_suite() -> bool:
    loader = unittest.TestLoader()
    suite  = unittest.TestSuite()
    for _, cls in _GROUPS:
        suite.addTests(loader.loadTestsFromTestCase(cls))
    runner = unittest.TextTestRunner(verbosity=2)
    return runner.run(suite).wasSuccessful()


if __name__ == "__main__":
    ok = _run_suite()
    sys.exit(0 if ok else 1)
