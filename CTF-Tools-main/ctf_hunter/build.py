#!/usr/bin/env python3
"""
Build script: packages CTF Hunter into a single executable using PyInstaller.
Run: python build.py

Optional Frida support
----------------------
If frida is installed (pip install frida frida-tools), the dynamic analysis
analyzer (analyzers/dynamic_frida.py) will be active at runtime.  The
PyInstaller bundle does not embed frida automatically; users who want dynamic
analysis should install frida in the Python environment that runs CTF Hunter
rather than relying on the bundled executable.
"""
from __future__ import annotations

import os
import platform
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent


def _ensure_frida_downloaded() -> None:
    """Attempt to pip-install frida if available in the current environment.

    This is a best-effort operation that must never raise an exception or set a
    non-zero exit code — a frida install failure must not abort the PyInstaller
    build.
    """
    try:
        import frida  # noqa: F401 — already installed
        print("  frida already installed; dynamic analysis will be available.")
        return
    except ImportError:
        pass
    print("Optional: attempting to install frida for dynamic analysis support…")
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--quiet", "frida", "frida-tools"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            print("  frida installed successfully.")
        else:
            # Log the failure clearly so CI/build logs surface it, but continue.
            print(
                f"  WARNING: frida install failed (exit code {result.returncode}). "
                "Dynamic analysis will be unavailable in the built executable.\n"
                f"  pip stderr: {result.stderr.strip()}"
            )
    except Exception as exc:
        # e.g. pip binary not found or permission error — still not fatal
        print(
            f"  WARNING: frida install skipped due to unexpected error: {exc}. "
            "Dynamic analysis will be unavailable in the built executable."
        )


def main() -> None:
    dist_path = ROOT / "dist"
    build_path = ROOT / "build_pyinstaller"

    # Try to make frida available in the build environment (best-effort)
    _ensure_frida_downloaded()

    args = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--windowed",
        "--name", "ctf_hunter",
        "--distpath", str(dist_path),
        "--workpath", str(build_path),
        "--specpath", str(build_path),
        "--add-data", f"{ROOT / 'wordlists'}{os.pathsep}wordlists",
        "--paths", str(ROOT),
        str(ROOT / "main.py"),
    ]

    # Platform-specific extras
    if platform.system() == "Windows":
        # Optionally add an icon
        icon_path = ROOT / "icon.ico"
        if icon_path.exists():
            args += ["--icon", str(icon_path)]

    print("Running PyInstaller…")
    print(" ".join(str(a) for a in args))
    result = subprocess.run(args, cwd=str(ROOT))
    if result.returncode == 0:
        exe_name = "ctf_hunter.exe" if platform.system() == "Windows" else "ctf_hunter"
        print(f"\nBuild complete! Executable: {dist_path / exe_name}")
    else:
        print("\nBuild FAILED.")
        sys.exit(1)


if __name__ == "__main__":
    main()
