"""Browser detection and opening."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess


def check_browser_availability() -> bool:
    """Check whether a browser can be opened.

    Returns False in SSH sessions or environments without a display.
    """
    if os.environ.get("SSH_CONNECTION") or os.environ.get("SSH_TTY"):
        return False

    system = platform.system()
    if system == "Darwin":
        return True
    if system == "Linux":
        if not shutil.which("xdg-open"):
            return False
        return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
    return system == "Windows"


def open_browser(url: str) -> bool:
    """Open a URL in the default browser. Returns True on success."""
    system = platform.system()
    try:
        if system == "Darwin":
            subprocess.Popen(["open", url])
        elif system == "Linux":
            subprocess.Popen(["xdg-open", url])
        elif system == "Windows":
            subprocess.Popen(["rundll32", "url.dll,FileProtocolHandler", url])
        else:
            return False
        return True
    except OSError:
        return False
