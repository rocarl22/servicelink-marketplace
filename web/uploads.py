"""Safe handling of uploaded files. Nothing here trusts the visitor.

- The file's real type is decided from its first bytes ("magic numbers"), never from its name or
  the browser's content-type. Allowed: JPEG, PNG, WebP (and PDF only when switched on).
- The visitor's filename is thrown away. The file is staged under a random name in a private folder
  and always deleted afterwards, whether the upload worked or not.
- Size is enforced while streaming, so an oversize file is never fully written to disk.
- Photos then go through backend/face_screen.py: pixel-count cap, EXIF/GPS removal and re-encoding to a
  fresh JPEG (so anything hidden in the original file is discarded).
"""
import os
import secrets
from contextlib import contextmanager
from types import SimpleNamespace

from backend import database as db

MAX_IMAGE_BYTES = 12 * 1024 * 1024          # matches backend/face_screen.py
MAX_EVIDENCE_BYTES = 8 * 1024 * 1024        # matches backend/services/admin.py
REQUEST_LIMIT_BYTES = 13 * 1024 * 1024      # whole multipart request incl. other form fields
CHUNK = 64 * 1024


def sniff(head: bytes):
    """Return 'jpg' | 'png' | 'webp' | 'pdf' from the first bytes, or None."""
    if head.startswith(b"\xff\xd8\xff"):
        return "jpg"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "webp"
    if head.startswith(b"%PDF-"):
        return "pdf"
    return None


def tmp_dir() -> str:
    path = os.path.join(db.DATA_DIR, "tmp_uploads")
    os.makedirs(path, exist_ok=True)
    if os.name != "nt":
        os.chmod(path, 0o700)
    return path


def _fail(message):
    return SimpleNamespace(ok=False, path="", kind="", error=message)


def stage(file_storage, max_bytes: int, allow_pdf: bool = False):
    """Copy an upload to a private temp file after checking it. Returns a result object."""
    if not file_storage or not getattr(file_storage, "filename", ""):
        return _fail("Choose a file first.")
    stream = file_storage.stream
    head = stream.read(16)
    kind = sniff(head)
    if kind is None or (kind == "pdf" and not allow_pdf):
        return _fail("That file type isn't allowed. Please choose a JPG, PNG or WebP photo"
                     + (" (or a PDF)." if allow_pdf else "."))
    path = os.path.join(tmp_dir(), f"{secrets.token_hex(16)}.{kind}")
    total = 0
    try:
        with open(path, "wb") as out:
            out.write(head)
            total = len(head)
            while True:
                chunk = stream.read(CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError("too large")
                out.write(chunk)
    except ValueError:
        _remove(path)
        return _fail(f"That file is too large. The limit is {max_bytes // (1024 * 1024)} MB.")
    except OSError:
        _remove(path)
        return _fail("The file could not be saved. Please try again.")
    if total <= 16:
        _remove(path)
        return _fail("That file looks empty or damaged.")
    return SimpleNamespace(ok=True, path=path, kind=kind, error="")


def _remove(path):
    try:
        os.remove(path)
    except OSError:
        pass


@contextmanager
def staged(file_storage, max_bytes: int, allow_pdf: bool = False):
    """`with staged(request.files.get("photo"), MAX) as up:` - the temp file is always deleted."""
    result = stage(file_storage, max_bytes, allow_pdf)
    try:
        yield result
    finally:
        if result.ok:
            _remove(result.path)
