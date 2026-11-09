"""Central path resolution.

Every path in the app — where the database lives, where QML assets
live, where the frozen face-detection cascade lives — resolves through
this module.

Why: the desktop build runs from the source tree today, but the same
service layer will eventually run behind a web backend. When that
happens, only this file needs a different implementation — every
service keeps calling `data_root()`, `resource_root()`, etc.

Two roots:
    resource_root()  — read-only, bundled with the app (QML, assets,
                       cascade files). In frozen mode this is the
                       PyInstaller temp extraction dir; in dev it's
                       the project directory.
    data_root()      — writable, user-specific. Contains the SQLite
                       database, uploaded photos, backups, caches.
                       In frozen mode this is under %APPDATA%; in dev
                       it's `<project>/data`.
"""
import os
import sys


def is_frozen() -> bool:
    """True when running from a PyInstaller bundle."""
    return getattr(sys, "frozen", False)


def resource_root() -> str:
    """Root of the read-only bundled resources.

    - Frozen (PyInstaller onefile): sys._MEIPASS (temp extraction dir).
    - Frozen (PyInstaller onedir): the folder containing the .exe.
    - Dev: the project root — the parent of the `backend` folder.
    """
    if is_frozen():
        # PyInstaller sets _MEIPASS for both onefile and onedir modes.
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            return meipass
        # Fallback: the directory containing the executable.
        return os.path.dirname(os.path.abspath(sys.executable))
    # Dev mode: `backend/paths.py` → project root.
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def data_root() -> str:
    """Root of the writable, per-user data directory.

    - Frozen: %APPDATA%/ServiceProviderLink (Windows).
              ~/.local/share/ServiceProviderLink (Linux/macOS).
    - Dev:    <project>/data.
    """
    if is_frozen():
        if os.name == "nt":
            base = os.environ.get("APPDATA") or os.path.expanduser("~")
        else:
            base = os.environ.get("XDG_DATA_HOME") \
                or os.path.join(os.path.expanduser("~"), ".local", "share")
        root = os.path.join(base, "ServiceProviderLink")
    else:
        root = os.path.join(resource_root(), "data")
    os.makedirs(root, exist_ok=True)
    return root


def qml_root() -> str:
    """Root of the QML source tree."""
    return os.path.join(resource_root(), "qml")


def icons_root() -> str:
    """Directory holding the SVG icons."""
    return os.path.join(qml_root(), "assets", "Icons")


def assets_root() -> str:
    """Root of the qml/assets folder (fonts, photos, reference)."""
    return os.path.join(qml_root(), "assets")


def cascade_path() -> str:
    """OpenCV Haar cascade used by the face screener."""
    return os.path.join(resource_root(), "backend", "data",
                        "haarcascade_frontalface_default.xml")


def db_path() -> str:
    return os.path.join(data_root(), "service_link.db")


def backup_dir() -> str:
    d = os.path.join(data_root(), "backups")
    os.makedirs(d, exist_ok=True)
    return d


def photo_dir() -> str:
    d = os.path.join(data_root(), "profile_photos")
    os.makedirs(d, exist_ok=True)
    return d


def evidence_dir() -> str:
    d = os.path.join(data_root(), "dispute_evidence")
    os.makedirs(d, exist_ok=True)
    return d


def portfolio_dir() -> str:
    d = os.path.join(data_root(), "portfolio")
    os.makedirs(d, exist_ok=True)
    return d


def icon_cache_dir() -> str:
    d = os.path.join(data_root(), "icon_cache")
    os.makedirs(d, exist_ok=True)
    return d