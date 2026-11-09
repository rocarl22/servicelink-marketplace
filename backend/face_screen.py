"""Face screening + EXIF stripping for portfolio uploads.

When a provider uploads a photo, we:
    1. Check for human faces. If any are found, reject the upload.
    2. Strip EXIF metadata (GPS, camera info, orientation)
    3. Re-encode as JPEG at a reasonable size

If OpenCV or the bundled Haar cascade is unavailable, portfolio uploads are
rejected with a clear message rather than being treated as successfully screened.
EXIF stripping and re-encoding run when Pillow is installed.

The `prepare_profile_image` function (below `prepare_portfolio_image`)
runs the same pipeline WITHOUT the face check - a profile photo is
expected to contain the account owner's face.
"""
import logging
import os

from . import paths

log = logging.getLogger("servicelink.face_screen")


# Pillow is required for the image processing pipeline
try:
    from PIL import Image, ImageOps
    PILLOW_OK = True
except ImportError:
    PILLOW_OK = False
    log.warning("Pillow not installed - portfolio uploads will fail")


# OpenCV is required for portfolio screening. It is imported defensively so
# profile-photo processing can still explain its own dependency state, but
# portfolio uploads fail closed if the detector cannot be initialized.
# The Haar cascade is bundled under backend/data/.
try:
    import cv2
    _cascade_path = paths.cascade_path()
    if not os.path.isfile(_cascade_path):
        _detector = None
        CV2_OK = False
        log.warning("Haar cascade not found at %s - face screening disabled",
                    _cascade_path)
    else:
        _detector = cv2.CascadeClassifier(_cascade_path)
        CV2_OK = not _detector.empty()
        if not CV2_OK:
            log.warning("OpenCV could not load cascade - face screening disabled")
        else:
            log.info("Face screening enabled (cascade loaded)")
except Exception:
    cv2 = None
    _detector = None
    CV2_OK = False
    log.info("OpenCV unavailable - face screening disabled")


MAX_DIMENSION = 1280
JPEG_QUALITY = 85
MAX_INPUT_BYTES = 12 * 1024 * 1024
MAX_INPUT_PIXELS = 40_000_000


def contains_face(image_path: str) -> bool:
    """Return whether a detectable face exists; raise if screening cannot run."""
    if not CV2_OK or _detector is None:
        raise RuntimeError("Face screening is unavailable")

    try:
        if os.path.getsize(image_path) > MAX_INPUT_BYTES:
            raise ValueError("Image file exceeds the upload size limit")

        # Check dimensions from image metadata before OpenCV decodes the full
        # raster. This limits memory pressure from tiny files with huge pixel
        # dimensions and keeps the detector's input policy aligned with the
        # Pillow processing pipeline below.
        if not PILLOW_OK:
            raise RuntimeError("Image validation is unavailable")
        with Image.open(image_path) as source_image:
            width, height = source_image.size
            if width <= 0 or height <= 0 or width * height > MAX_INPUT_PIXELS:
                raise ValueError("Image dimensions are too large to screen safely")
            source_image.verify()

        img = cv2.imread(image_path)
        if img is None:
            raise ValueError("Image could not be decoded by the screening engine")
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        faces = _detector.detectMultiScale(
            gray,
            scaleFactor=1.1,
            minNeighbors=4,
            minSize=(40, 40),
        )
        return len(faces) > 0
    except Exception:
        log.exception("Face detection failed")
        raise


def _validate_input_file(src: str):
    try:
        size = os.path.getsize(src)
    except OSError:
        return False, "The selected file could not be accessed."
    if size <= 0:
        return False, "The selected image is empty."
    if size > MAX_INPUT_BYTES:
        return False, "Image must be 12 MB or smaller."
    return True, ""


def prepare_portfolio_image(src: str, dst: str):
    """Screen + process a portfolio image for storage.

    Returns (ok, message):
        ok=True  -> image saved to dst, message is a success note
        ok=False -> image rejected, message explains why
    """
    if not PILLOW_OK:
        return False, "Image processing is not available on this system."

    src = (src or "").strip()
    if not src:
        return False, "No image path provided."
    if not os.path.exists(src):
        return False, "The selected file could not be found."

    ok, msg = _validate_input_file(src)
    if not ok:
        return False, msg

    # Face screening is mandatory for portfolio images. Do not treat a broken
    # detector as a successful negative result.
    try:
        if contains_face(src):
            return False, (
                "This photo appears to contain a person's face. "
                "Please upload a photo of the work only, without people."
            )
    except Exception:
        return False, "Face screening is temporarily unavailable. Please try again later."

    try:
        os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)

        with Image.open(src) as im:
            if getattr(im, "width", 0) * getattr(im, "height", 0) > MAX_INPUT_PIXELS:
                return False, "Image dimensions are too large to process safely."
            # Apply EXIF orientation so the saved copy is upright,
            # then strip all EXIF by re-saving without it.
            im = ImageOps.exif_transpose(im)

            # Convert to RGB if it's in a mode JPEG doesn't support
            if im.mode in ("RGBA", "P", "LA"):
                im = im.convert("RGB")
            elif im.mode != "RGB":
                im = im.convert("RGB")

            # Thumbnail to keep the file small
            im.thumbnail((MAX_DIMENSION, MAX_DIMENSION), Image.LANCZOS)

            # Save as JPEG. This drops all EXIF metadata.
            im.save(dst, "JPEG", quality=JPEG_QUALITY, optimize=True)

        return True, "Photo added to your portfolio."

    except Exception as e:
        log.exception("prepare_portfolio_image failed")
        return False, "Could not process this image. Please choose another file."


def prepare_profile_image(src: str, dst: str):
    """Process a profile photo for storage.

    Same pipeline as prepare_portfolio_image but WITHOUT the face
    screening check - a profile photo is expected to contain the
    account owner's face. EXIF is still stripped and the image is
    re-encoded as JPEG.

    Returns (ok, message).
    """
    if not PILLOW_OK:
        return False, "Image processing is not available on this system."

    src = (src or "").strip()
    if not src:
        return False, "No image path provided."
    if not os.path.exists(src):
        return False, "The selected file could not be found."

    ok, msg = _validate_input_file(src)
    if not ok:
        return False, msg

    try:
        os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)

        with Image.open(src) as im:
            if getattr(im, "width", 0) * getattr(im, "height", 0) > MAX_INPUT_PIXELS:
                return False, "Image dimensions are too large to process safely."
            im = ImageOps.exif_transpose(im)

            if im.mode in ("RGBA", "P", "LA"):
                im = im.convert("RGB")
            elif im.mode != "RGB":
                im = im.convert("RGB")

            im.thumbnail((MAX_DIMENSION, MAX_DIMENSION), Image.LANCZOS)
            im.save(dst, "JPEG", quality=JPEG_QUALITY, optimize=True)

        return True, "Profile photo updated."
    except Exception as e:
        log.exception("prepare_profile_image failed")
        return False, "Could not process this image. Please choose another file."