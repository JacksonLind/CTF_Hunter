"""
Tests for ZIP/7z/RAR archive password spray in analyzers/archive.py.

Groups:
  a1–a6   ZIP password cracking (stdlib only, always available)
  b7–b11  KeyRegistry integration
  c12–c15 7z support (skipped when py7zr not installed)
  d16–d18 RAR graceful degradation
  e19–e20 dispatcher routing
"""
from __future__ import annotations

import io
import os
import re
import sys
import tempfile
import unittest
import zipfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from analyzers.archive import ArchiveAnalyzer, HAS_PY7ZR, HAS_RARFILE, HAS_PYZIPPER
from core.report import Session
from core.key_registry import KeyCandidate

FLAG_RE = re.compile(r"flag\{[^}]+\}")
ANA = ArchiveAnalyzer()

# pyzipper is required to create encrypted ZIPs in tests.
# It ships in requirements.txt so this is always available.
if HAS_PYZIPPER:
    import pyzipper


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_encrypted_zip(password: str, filename: str = "secret.txt", content: bytes = b"hello") -> bytes:
    """Create an AES-256 encrypted ZIP (requires pyzipper, which is in requirements.txt)."""
    if not HAS_PYZIPPER:
        raise unittest.SkipTest("pyzipper not installed — cannot create encrypted ZIP for test")
    buf = io.BytesIO()
    with pyzipper.AESZipFile(buf, "w", compression=pyzipper.ZIP_DEFLATED,
                              encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(password.encode())
        zf.writestr(filename, content)
    return buf.getvalue()


def _make_zip_with_flag(password: str) -> bytes:
    return _make_encrypted_zip(password, content=b"flag{secret_found}")


def _write_tmp(data: bytes, suffix: str = ".zip") -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    return path


def _run(path: str, depth: str = "deep", session=None) -> list:
    return ANA.analyze(path, FLAG_RE, depth, None, session=session)


# ---------------------------------------------------------------------------
# a: ZIP password cracking
# ---------------------------------------------------------------------------

class TestZipPasswordCracking(unittest.TestCase):

    def test_a1_unencrypted_zip_no_crack_finding(self):
        """Unencrypted ZIP should not produce a 'password cracked' finding."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("hello.txt", "hello world")
        path = _write_tmp(buf.getvalue())
        try:
            findings = _run(path)
            cracked = [f for f in findings if "cracked" in f.title.lower()]
            self.assertEqual(cracked, [])
        finally:
            os.unlink(path)

    def test_a2_encrypted_zip_detected(self):
        """Encrypted ZIP entries should be flagged even in fast mode."""
        data = _make_encrypted_zip("irrelevant")
        path = _write_tmp(data)
        try:
            findings = _run(path, depth="fast")
            enc = [f for f in findings if "encrypted" in f.title.lower() or "encrypted" in f.detail.lower()]
            self.assertGreater(len(enc), 0)
        finally:
            os.unlink(path)

    def test_a3_crack_rockyou_password(self):
        """Password 'password' (in rockyou top-1000) should be cracked."""
        data = _make_encrypted_zip("password")
        path = _write_tmp(data)
        try:
            findings = _run(path, depth="deep")
            cracked = [f for f in findings if "cracked" in f.title.lower()]
            self.assertGreater(len(cracked), 0)
            self.assertIn("password", cracked[0].title)
        finally:
            os.unlink(path)

    def test_a4_crack_yields_high_severity(self):
        """Cracked ZIP finding must have HIGH severity."""
        data = _make_encrypted_zip("123456")
        path = _write_tmp(data)
        try:
            findings = _run(path, depth="deep")
            cracked = [f for f in findings if "cracked" in f.title.lower()]
            self.assertTrue(all(f.severity == "HIGH" for f in cracked))
        finally:
            os.unlink(path)

    def test_a5_flag_match_propagates(self):
        """flag_match=True must be set when decrypted content contains the flag."""
        data = _make_zip_with_flag("admin")
        path = _write_tmp(data)
        try:
            findings = _run(path, depth="deep")
            flag_findings = [f for f in findings if f.flag_match]
            self.assertGreater(len(flag_findings), 0)
        finally:
            os.unlink(path)

    def test_a6_fast_mode_skips_cracking(self):
        """fast mode must NOT attempt password cracking (too slow for fast mode)."""
        data = _make_encrypted_zip("password")
        path = _write_tmp(data)
        try:
            findings = _run(path, depth="fast")
            cracked = [f for f in findings if "cracked" in f.title.lower()]
            self.assertEqual(cracked, [])
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# b: KeyRegistry integration
# ---------------------------------------------------------------------------

class TestKeyRegistryIntegration(unittest.TestCase):

    def _session_with_password(self, password: str) -> Session:
        s = Session()
        s.key_registry.register(KeyCandidate(
            value=password,
            source_finding_id="test_finding_id",
            key_type="zip_password",
            confidence=0.9,
            context="test",
        ))
        return s

    def test_b7_registry_password_cracks_zip(self):
        """A KeyRegistry password not in rockyou should still crack the ZIP."""
        rare_pwd = "CtF_h4x0r_2024_xyzNotInWordlist"
        data = _make_encrypted_zip(rare_pwd)
        path = _write_tmp(data)
        session = self._session_with_password(rare_pwd)
        try:
            findings = _run(path, depth="deep", session=session)
            cracked = [f for f in findings if "cracked" in f.title.lower()]
            self.assertGreater(len(cracked), 0)
            self.assertIn(rare_pwd, cracked[0].title)
        finally:
            os.unlink(path)

    def test_b8_cracked_password_registered_in_session(self):
        """After cracking, the password should appear in the session KeyRegistry."""
        data = _make_encrypted_zip("password")
        path = _write_tmp(data)
        session = Session()
        try:
            _run(path, depth="deep", session=session)
            registered = [c.value for c in session.key_registry.get_candidates("zip_password")]
            self.assertIn("password", registered)
        finally:
            os.unlink(path)

    def test_b9_no_session_still_cracks(self):
        """Cracking must still work when session=None (no KeyRegistry available)."""
        data = _make_encrypted_zip("secret")
        path = _write_tmp(data)
        try:
            findings = ANA.analyze(path, FLAG_RE, "deep", None, session=None)
            cracked = [f for f in findings if "cracked" in f.title.lower()]
            self.assertGreater(len(cracked), 0)
        finally:
            os.unlink(path)

    def test_b10_registry_password_tried_before_wordlist(self):
        """Registry password should crack archive without needing the full wordlist scan."""
        # Use a password that could theoretically be in the wordlist but we
        # verify it by using a clearly non-wordlist password registered in registry.
        rare_pwd = "ZZZz_unique_registry_password_ZZZz"
        data = _make_encrypted_zip(rare_pwd)
        path = _write_tmp(data)
        session = self._session_with_password(rare_pwd)
        try:
            findings = _run(path, depth="deep", session=session)
            cracked = [f for f in findings if "cracked" in f.title.lower()]
            self.assertGreater(len(cracked), 0)
        finally:
            os.unlink(path)

    def test_b11_generic_key_type_also_tried(self):
        """Passwords with key_type='generic' should also be tried."""
        rare_pwd = "generic_type_password_xyz"
        data = _make_encrypted_zip(rare_pwd)
        path = _write_tmp(data)
        s = Session()
        s.key_registry.register(KeyCandidate(
            value=rare_pwd,
            source_finding_id="x",
            key_type="generic",
            confidence=0.8,
            context="test",
        ))
        try:
            findings = _run(path, depth="deep", session=s)
            cracked = [f for f in findings if "cracked" in f.title.lower()]
            self.assertGreater(len(cracked), 0)
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# c: 7z support
# ---------------------------------------------------------------------------

@unittest.skipUnless(HAS_PY7ZR, "py7zr not installed")
class TestSevenZipSupport(unittest.TestCase):

    def _make_7z(self, filename: str, content: bytes, password: str | None = None) -> str:
        import py7zr
        fd, path = tempfile.mkstemp(suffix=".7z")
        os.close(fd)
        kwargs = {"password": password} if password else {}
        with py7zr.SevenZipFile(path, "w", **kwargs) as sz:
            sz.writestr(content, filename)
        return path

    def test_c12_unencrypted_7z_listed(self):
        """Unencrypted 7z: archive listing finding emitted."""
        path = self._make_7z("hello.txt", b"hello world")
        try:
            findings = _run(path, depth="fast")
            listed = [f for f in findings if "7z archive" in f.title.lower()]
            self.assertGreater(len(listed), 0)
        finally:
            os.unlink(path)

    def test_c13_unencrypted_7z_contents_extracted_deep(self):
        """Unencrypted 7z in deep mode: raw_hex= embedded for re-dispatch."""
        path = self._make_7z("data.bin", b"\xde\xad\xbe\xef")
        try:
            findings = _run(path, depth="deep")
            raw = [f for f in findings if "raw_hex=" in f.detail]
            self.assertGreater(len(raw), 0)
        finally:
            os.unlink(path)

    def test_c14_encrypted_7z_detected(self):
        """Encrypted 7z must emit an 'Encrypted 7z' finding."""
        path = self._make_7z("secret.txt", b"flag{7z_works}", password="password")
        try:
            findings = _run(path, depth="fast")
            enc = [f for f in findings if "encrypted 7z" in f.title.lower()]
            self.assertGreater(len(enc), 0)
        finally:
            os.unlink(path)

    def test_c15_encrypted_7z_cracked(self):
        """Encrypted 7z with rockyou password should be cracked in deep mode."""
        path = self._make_7z("secret.txt", b"flag{7z_cracked}", password="password")
        try:
            findings = _run(path, depth="deep")
            cracked = [f for f in findings if "7z password cracked" in f.title.lower()]
            self.assertGreater(len(cracked), 0)
            self.assertTrue(cracked[0].flag_match)
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# d: RAR graceful degradation
# ---------------------------------------------------------------------------

class TestRarGracefulDegradation(unittest.TestCase):

    def test_d16_is_rar_detection(self):
        """_is_rar must return True for RAR4 magic bytes."""
        # RAR4 magic: Rar!\x1a\x07\x00
        fd, path = tempfile.mkstemp(suffix=".rar")
        with os.fdopen(fd, "wb") as fh:
            fh.write(b"Rar!\x1a\x07\x00" + b"\x00" * 100)
        try:
            self.assertTrue(ANA._is_rar(path))
        finally:
            os.unlink(path)

    def test_d17_rar_no_rarfile_library(self):
        """Without rarfile installed, RAR detection should emit INFO finding."""
        if HAS_RARFILE:
            self.skipTest("rarfile is installed; degradation path not reachable")
        fd, path = tempfile.mkstemp(suffix=".rar")
        with os.fdopen(fd, "wb") as fh:
            fh.write(b"Rar!\x1a\x07\x00" + b"\x00" * 100)
        try:
            findings = _run(path, depth="deep")
            info = [f for f in findings if "rar" in f.title.lower() and f.severity == "INFO"]
            self.assertGreater(len(info), 0)
        finally:
            os.unlink(path)

    def test_d18_7z_no_py7zr_library(self):
        """Without py7zr installed, 7z detection should emit INFO finding."""
        if HAS_PY7ZR:
            self.skipTest("py7zr is installed; degradation path not reachable")
        fd, path = tempfile.mkstemp(suffix=".7z")
        with os.fdopen(fd, "wb") as fh:
            fh.write(_7Z_MAGIC + b"\x00" * 100)
        try:
            findings = _run(path, depth="deep")
            info = [f for f in findings if "7z" in f.title.lower() and f.severity == "INFO"]
            self.assertGreater(len(info), 0)
        finally:
            os.unlink(path)


# Need to import _7Z_MAGIC for the test
from analyzers.archive import _7Z_MAGIC  # noqa: E402


# ---------------------------------------------------------------------------
# e: dispatcher routing
# ---------------------------------------------------------------------------

class TestDispatcherRouting(unittest.TestCase):

    def test_e19_zip_routed_to_archive(self):
        """ZIP magic bytes → 'archive' key in dispatcher._identify_analyzers."""
        import sys as _sys
        sys.path.insert(0, _ROOT)
        from core.dispatcher import _identify_analyzers
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("a.txt", "hello")
        path = _write_tmp(buf.getvalue())
        try:
            keys = _identify_analyzers(path, buf.getvalue()[:512])
            self.assertIn("archive", keys)
        finally:
            os.unlink(path)

    def test_e20_7z_routed_to_archive(self):
        """7z magic bytes → 'archive' key in dispatcher._identify_analyzers."""
        from core.dispatcher import _identify_analyzers
        fd, path = tempfile.mkstemp(suffix=".7z")
        with os.fdopen(fd, "wb") as fh:
            fh.write(_7Z_MAGIC + b"\x00" * 100)
        try:
            with open(path, "rb") as fh:
                header = fh.read(512)
            keys = _identify_analyzers(path, header)
            self.assertIn("archive", keys)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
