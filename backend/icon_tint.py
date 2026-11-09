"""Pre-tint SVG icons and cache them as PNGs.

Qt's MultiEffect and SVG rendering are unreliable on some Windows builds.
Instead of tinting in QML, we render the SVG to a PNG with the tint
colour baked in. The QML side just loads the PNG.
"""
import hashlib
import os
import logging

log = logging.getLogger("servicelink.icon_tint")

_CACHE_DIR = None


def _cache_dir() -> str:
    global _CACHE_DIR
    if _CACHE_DIR is None:
        from . import database as db
        _CACHE_DIR = os.path.join(db.DATA_DIR, "icon_cache")
        os.makedirs(_CACHE_DIR, exist_ok=True)
    return _CACHE_DIR


def tint_icon(svg_path: str, tint_hex: str) -> str:
    """Return the path to a PNG version of svg_path tinted to tint_hex.

    Caches by (svg_path, tint_hex) hash. Returns "" on failure.
    """
    if not svg_path or not os.path.isfile(svg_path):
        return ""

    tint_hex = (tint_hex or "#8ea0c2").lstrip("#")
    if len(tint_hex) == 3:
        tint_hex = "".join(c * 2 for c in tint_hex)
    if len(tint_hex) != 6:
        tint_hex = "8ea0c2"

    key = hashlib.sha1(
        f"{svg_path}|{tint_hex}".encode("utf-8")
    ).hexdigest()[:20]
    out_path = os.path.join(_cache_dir(), key + ".png")

    if os.path.isfile(out_path):
        return out_path

    try:
        from PySide6.QtGui import QImage, QPainter, QColor
        from PySide6.QtSvg import QSvgRenderer
        from PySide6.QtCore import QByteArray, Qt, QSize

        renderer = QSvgRenderer(svg_path)
        if not renderer.isValid():
            log.warning("Invalid SVG: %s", svg_path)
            return ""

        size = QSize(64, 64)
        image = QImage(size, QImage.Format_ARGB32_Premultiplied)
        image.fill(Qt.transparent)

        painter = QPainter(image)
        painter.setRenderHint(QPainter.Antialiasing, True)
        renderer.render(painter)
        painter.end()

        tint = QColor("#" + tint_hex)
        for y in range(image.height()):
            for x in range(image.width()):
                pixel = image.pixelColor(x, y)
                if pixel.alpha() > 0:
                    pixel.setRed(tint.red())
                    pixel.setGreen(tint.green())
                    pixel.setBlue(tint.blue())
                    image.setPixelColor(x, y, pixel)

        image.save(out_path, "PNG")
        return out_path
    except Exception:
        log.exception("tint_icon failed for %s", svg_path)
        return ""