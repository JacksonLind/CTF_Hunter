# PyInstaller runtime hook for imageio_ffmpeg.
#
# When running as a frozen exe, PyInstaller extracts bundled data files into
# sys._MEIPASS. imageio_ffmpeg.get_ffmpeg_exe() locates the ffmpeg binary
# relative to its own __file__, which inside a frozen exe points into the
# compressed archive rather than the extracted temp directory.
#
# This hook patches get_ffmpeg_exe() at startup to search _MEIPASS first,
# falling back to the normal resolution if the binary isn't found there.
import os
import sys


def _patched_get_ffmpeg_exe():
    import glob
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        # imageio_ffmpeg stores the binary as imageio_ffmpeg/binaries/ffmpeg*
        pattern = os.path.join(meipass, "imageio_ffmpeg", "binaries", "ffmpeg*")
        matches = [
            p for p in glob.glob(pattern)
            if not p.endswith(".txt")  # exclude the licence/version txt file
        ]
        if matches:
            return matches[0]
    # Fallback: let imageio_ffmpeg resolve it the normal way
    import imageio_ffmpeg._utils as _u
    return _u._get_ffmpeg_exe_original()


try:
    import imageio_ffmpeg._utils as _utils
    # Preserve original so the fallback above can call it
    if not hasattr(_utils, "_get_ffmpeg_exe_original"):
        _utils._get_ffmpeg_exe_original = _utils.get_ffmpeg_exe
    _utils.get_ffmpeg_exe = _patched_get_ffmpeg_exe

    import imageio_ffmpeg
    imageio_ffmpeg.get_ffmpeg_exe = _patched_get_ffmpeg_exe
except Exception:
    pass  # If anything goes wrong, let the normal resolution proceed
