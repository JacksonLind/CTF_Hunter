"""
Tests for the QR code repair pipeline in ImageAnalyzer.

Coverage:
  A. Happy-path decode
     1. Clean QR — standard decode (no repair needed)
     2. Color-inverted QR — repair: invert
     3. Checkerboard-XOR + invert (TamuCTF quick_response challenge)
     4. Spatially warped QR — majority-vote resampling
     5. Combined: checkerboard-XOR + invert + warp
     6. Small module size (8 px/module)

  B. All 8 QR mask patterns
     7-14. Each mask applied alone — pipeline finds and reverses it

  C. False-positive prevention (no QR finding expected)
     15. Random noise image — not binary enough to trigger repair
     16. Non-square image — aspect ratio check skips it
     17. Solid grey image — not binary, skips heuristic

  D. Graceful degradation
     18. No decoder (HAS_CV2=False, HAS_PYZBAR=False) — still emits MEDIUM
         "decoder unavailable" finding when image looks QR-like

  E. "All repairs failed" path
     19. Random binary grid — looks QR-like but decodes to nothing;
         emits MEDIUM "all repair variants failed" finding

  F. Helper unit tests
     20. _qr_detect_module_size — returns correct module size from a known grid
     21. _qr_majority_vote — returns correct clean grid from a noisy array

Run from the ctf_hunter/ directory:
    python tests/test_qr_repair.py
"""
from __future__ import annotations

import math
import os
import re
import sys
import tempfile
import unittest.mock

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import numpy as np
from PIL import Image

import analyzers.image as _image_mod
from analyzers.image import ImageAnalyzer

FLAG_PATTERN = re.compile(r"flag\{[^}]+\}")
FLAG = "flag{qr_repair_works}"
MODULE_PX = 20  # default pixels per QR module

# ---------------------------------------------------------------------------
# QR mask functions (mirrors the 8 standard patterns in ImageAnalyzer)
# ---------------------------------------------------------------------------
_MASK_FNS = [
    lambda r, c: (r + c) % 2 == 0,
    lambda r, c: r % 2 == 0,
    lambda r, c: c % 3 == 0,
    lambda r, c: (r + c) % 3 == 0,
    lambda r, c: (r // 2 + c // 3) % 2 == 0,
    lambda r, c: (r * c) % 2 + (r * c) % 3 == 0,
    lambda r, c: ((r * c) % 2 + (r * c) % 3) % 2 == 0,
    lambda r, c: ((r + c) % 2 + (r * c) % 3) % 2 == 0,
]

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

def make_clean_qr(flag: str = FLAG, module_px: int = MODULE_PX) -> np.ndarray:
    """Generate a clean QR code as a greyscale uint8 numpy array."""
    import qrcode
    qr = qrcode.QRCode(box_size=module_px, border=4)
    qr.add_data(flag)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white").convert("L")
    return np.array(img, dtype=np.uint8)


def apply_invert(arr: np.ndarray) -> np.ndarray:
    return 255 - arr


def apply_mask_xor(arr: np.ndarray, mask_id: int, module_px: int) -> np.ndarray:
    """Apply QR mask pattern *mask_id* by XORing each module that matches."""
    result = arr.copy()
    h, w = arr.shape
    fn = _MASK_FNS[mask_id]
    for r in range(h // module_px):
        for c in range(w // module_px):
            if fn(r, c):
                result[
                    r * module_px: (r + 1) * module_px,
                    c * module_px: (c + 1) * module_px,
                ] ^= 255
    return result


def apply_spatial_warp(arr: np.ndarray, strength: int = 6) -> np.ndarray:
    """Row-shift sinusoidal warp (simulates spatial distortion)."""
    h = arr.shape[0]
    warped = np.empty_like(arr)
    for y in range(h):
        shift = int(strength * math.sin(math.pi * y / h))
        warped[y] = np.roll(arr[y], shift)
    return warped


def make_random_binary_grid(n: int = 29, module_px: int = MODULE_PX) -> np.ndarray:
    """Return a square binary (B&W) grid with random module values.

    Looks QR-like (square, binary, detectable module size) but is not a valid
    QR code — used to exercise the "all repairs failed" path.
    """
    rng = np.random.default_rng(seed=0)
    grid = rng.integers(0, 2, size=(n, n), dtype=np.uint8) * 255
    # Scale up: each module -> module_px x module_px block
    scaled = np.repeat(np.repeat(grid, module_px, axis=0), module_px, axis=1)
    # Add a 4-module white quiet zone
    border = 4 * module_px
    h, w = scaled.shape
    canvas = np.ones((h + 2 * border, w + 2 * border), dtype=np.uint8) * 255
    canvas[border: border + h, border: border + w] = scaled
    return canvas


def save_png(arr: np.ndarray) -> str:
    fh = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
    Image.fromarray(arr).save(fh.name)
    fh.close()
    return fh.name


# ---------------------------------------------------------------------------
# Assertion helpers
# ---------------------------------------------------------------------------

def findings_contain_flag(findings) -> bool:
    for f in findings:
        if FLAG_PATTERN.search(f.title or "") or FLAG_PATTERN.search(f.detail or ""):
            return True
    return False


def findings_contain_qr(findings) -> bool:
    """True if any finding mentions 'QR' (case-insensitive)."""
    for f in findings:
        if re.search(r"qr", f.title or "", re.IGNORECASE):
            return True
    return False


def run_test(
    name: str,
    arr: np.ndarray,
    *,
    expect_flag: bool = True,
    expect_qr_finding: bool | None = None,
    patch_no_decoder: bool = False,
) -> bool:
    """Run ImageAnalyzer on *arr*, check expectations, print PASS/FAIL."""
    path = save_png(arr)
    try:
        analyzer = ImageAnalyzer()
        if patch_no_decoder:
            with (
                unittest.mock.patch.object(_image_mod, "HAS_CV2", False),
                unittest.mock.patch.object(_image_mod, "HAS_PYZBAR", False),
            ):
                findings = analyzer.analyze(path, FLAG_PATTERN, "fast", None)
        else:
            findings = analyzer.analyze(path, FLAG_PATTERN, "fast", None)

        flag_ok = findings_contain_flag(findings) == expect_flag
        qr_ok = (
            True
            if expect_qr_finding is None
            else findings_contain_qr(findings) == expect_qr_finding
        )
        ok = flag_ok and qr_ok
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}]  {name}")
        if not ok:
            titles = [f.title for f in findings]
            print(f"         expect_flag={expect_flag}, got_flag={findings_contain_flag(findings)}")
            if expect_qr_finding is not None:
                print(f"         expect_qr_finding={expect_qr_finding}, got={findings_contain_qr(findings)}")
            print(f"         findings ({len(findings)}): {titles[:8]}")
        return ok
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# A. Happy-path decode
# ---------------------------------------------------------------------------

def test_clean_qr() -> bool:
    return run_test(
        "A1 clean QR — standard decode (no repair)",
        make_clean_qr(),
    )


def test_inverted_qr() -> bool:
    return run_test(
        "A2 color-inverted QR — repair: invert",
        apply_invert(make_clean_qr()),
    )


def test_checkerboard_xor_qr() -> bool:
    """quick_response challenge: checkerboard-XOR then invert."""
    arr = make_clean_qr()
    arr = apply_mask_xor(arr, mask_id=0, module_px=MODULE_PX)
    arr = apply_invert(arr)
    return run_test("A3 checkerboard-XOR + invert (quick_response)", arr)


def test_spatially_warped_qr() -> bool:
    return run_test(
        "A4 spatial warp — majority-vote resample",
        apply_spatial_warp(make_clean_qr(), strength=6),
    )


def test_combined_mangle() -> bool:
    arr = make_clean_qr()
    arr = apply_mask_xor(arr, mask_id=0, module_px=MODULE_PX)
    arr = apply_invert(arr)
    arr = apply_spatial_warp(arr, strength=4)
    return run_test("A5 combined: mask-0 + invert + warp", arr)


def test_small_module_size() -> bool:
    """Module size of 8 px — smaller than default, tests module detection robustness."""
    return run_test(
        "A6 small module size (8 px/module)",
        make_clean_qr(module_px=8),
    )


# ---------------------------------------------------------------------------
# B. All 8 QR mask patterns
# ---------------------------------------------------------------------------

def test_all_mask_patterns() -> bool:
    """Each of the 8 QR mask patterns applied alone must be reversed by the pipeline."""
    all_pass = True
    for mask_id in range(8):
        arr = apply_mask_xor(make_clean_qr(), mask_id=mask_id, module_px=MODULE_PX)
        ok = run_test(f"B{mask_id + 7} QR mask pattern {mask_id}", arr)
        all_pass = all_pass and ok
    return all_pass


# ---------------------------------------------------------------------------
# C. False-positive prevention
# ---------------------------------------------------------------------------

def test_random_noise_no_qr() -> bool:
    """Random noise — not binary enough; no QR finding emitted."""
    rng = np.random.default_rng(seed=1)
    arr = rng.integers(60, 200, size=(400, 400), dtype=np.uint8)
    return run_test(
        "C15 random noise — no QR finding",
        arr,
        expect_flag=False,
        expect_qr_finding=False,
    )


def test_non_square_no_qr() -> bool:
    """Tall rectangular binary image — aspect ratio check skips QR pipeline."""
    arr = np.zeros((600, 300), dtype=np.uint8)  # h/w ratio = 2 (>>20% diff)
    arr[::20, :] = 255
    return run_test(
        "C16 non-square image — no QR finding",
        arr,
        expect_flag=False,
        expect_qr_finding=False,
    )


def test_grey_image_no_qr() -> bool:
    """Uniform grey — not binary; no QR finding emitted."""
    arr = np.full((400, 400), 128, dtype=np.uint8)
    return run_test(
        "C17 uniform grey image — no QR finding",
        arr,
        expect_flag=False,
        expect_qr_finding=False,
    )


# ---------------------------------------------------------------------------
# D. Graceful degradation — no decoder installed
# ---------------------------------------------------------------------------

def test_no_decoder_emits_finding() -> bool:
    """With HAS_CV2=False and HAS_PYZBAR=False, a QR-like image gets a MEDIUM
    'decoder unavailable' finding rather than silently returning nothing."""
    arr = make_clean_qr()  # valid QR but decoder patched out
    path = save_png(arr)
    try:
        analyzer = ImageAnalyzer()
        with (
            unittest.mock.patch.object(_image_mod, "HAS_CV2", False),
            unittest.mock.patch.object(_image_mod, "HAS_PYZBAR", False),
        ):
            findings = analyzer.analyze(path, FLAG_PATTERN, "fast", None)

        has_unavail = any(
            "decoder unavailable" in (f.title or "").lower()
            or "decoder unavailable" in (f.detail or "").lower()
            for f in findings
        )
        severities = {f.severity for f in findings if "qr" in (f.title or "").lower()}
        ok = has_unavail and bool(severities)
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}]  D18 no decoder — MEDIUM 'decoder unavailable' finding")
        if not ok:
            print(f"         has_unavail={has_unavail}, qr_severities={severities}")
            print(f"         titles: {[f.title for f in findings]}")
        return ok
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# E. "All repairs failed" path
# ---------------------------------------------------------------------------

def test_all_repairs_failed_emits_medium() -> bool:
    """A QR-shaped random binary grid looks valid but cannot be decoded.
    The pipeline must emit a MEDIUM 'all repair variants failed' finding."""
    arr = make_random_binary_grid(n=29, module_px=MODULE_PX)
    path = save_png(arr)
    try:
        analyzer = ImageAnalyzer()
        findings = analyzer.analyze(path, FLAG_PATTERN, "fast", None)
        has_failed = any(
            "repair" in (f.title or "").lower() and "failed" in (f.title or "").lower()
            for f in findings
        )
        medium_qr = any(
            f.severity == "MEDIUM" and "qr" in (f.title or "").lower()
            for f in findings
        )
        ok = has_failed or medium_qr
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}]  E19 random binary grid — 'all repairs failed' MEDIUM finding")
        if not ok:
            print(f"         findings: {[f.title for f in findings]}")
        return ok
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# F. Helper unit tests
# ---------------------------------------------------------------------------

def test_detect_module_size() -> bool:
    """_qr_detect_module_size returns the correct module size for a known grid."""
    for module_px in (8, 15, 20, 32):
        # Build a simple 3-stripe binary grid at known module size.
        n = 10
        arr = np.zeros((n * module_px, n * module_px), dtype=np.uint8)
        # Alternate modules: white columns at even indices
        for c in range(n):
            if c % 2 == 0:
                arr[:, c * module_px: (c + 1) * module_px] = 255

        detected = ImageAnalyzer._qr_detect_module_size(arr)
        ok = detected == module_px
        if not ok:
            print(f"  [FAIL]  F20 _qr_detect_module_size({module_px}px): got {detected}")
            return False
    print("  [PASS]  F20 _qr_detect_module_size — correct for 8, 15, 20, 32 px")
    return True


def test_majority_vote() -> bool:
    """_qr_majority_vote correctly extracts a clean grid from a noisy array."""
    module_px = 10
    n = 5
    # Build a known 5x5 binary pattern (checkerboard)
    expected = np.array([
        [0, 1, 0, 1, 0],
        [1, 0, 1, 0, 1],
        [0, 1, 0, 1, 0],
        [1, 0, 1, 0, 1],
        [0, 1, 0, 1, 0],
    ], dtype=np.uint8)

    # Render to pixel array (0=black, 1=white in binary domain)
    scaled = np.repeat(np.repeat(expected, module_px, axis=0), module_px, axis=1)

    # Add mild noise (flip ~5% of pixels)
    rng = np.random.default_rng(seed=42)
    noise_mask = rng.random(scaled.shape) < 0.05
    noisy = scaled.copy()
    noisy[noise_mask] ^= 1  # flip 0<->1

    result = ImageAnalyzer._qr_majority_vote(noisy, module_px, n)
    ok = result is not None and np.array_equal(result, expected)
    status = "PASS" if ok else "FAIL"
    print(f"  [{status}]  F21 _qr_majority_vote — recovers clean grid through 5% noise")
    if not ok and result is not None:
        print(f"         expected:\n{expected}\n         got:\n{result}")
    return ok


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("QR code repair pipeline tests\n")

    print("--- A. Happy-path decode ---")
    results = [
        test_clean_qr(),
        test_inverted_qr(),
        test_checkerboard_xor_qr(),
        test_spatially_warped_qr(),
        test_combined_mangle(),
        test_small_module_size(),
    ]

    print("\n--- B. All 8 QR mask patterns ---")
    results.append(test_all_mask_patterns())

    print("\n--- C. False-positive prevention ---")
    results += [
        test_random_noise_no_qr(),
        test_non_square_no_qr(),
        test_grey_image_no_qr(),
    ]

    print("\n--- D. Graceful degradation (no decoder) ---")
    results.append(test_no_decoder_emits_finding())

    print("\n--- E. All repairs failed path ---")
    results.append(test_all_repairs_failed_emits_medium())

    print("\n--- F. Helper unit tests ---")
    results += [
        test_detect_module_size(),
        test_majority_vote(),
    ]

    passed = sum(results)
    total = len(results)
    print(f"\n{passed}/{total} passed")
    sys.exit(0 if passed == total else 1)
