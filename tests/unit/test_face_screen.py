from PIL import Image

from backend import face_screen


def test_portfolio_upload_fails_closed_if_detector_unavailable(tmp_path, monkeypatch):
    src = tmp_path / "sample.png"
    dst = tmp_path / "output.jpg"
    Image.new("RGB", (100, 100), "white").save(src)
    monkeypatch.setattr(face_screen, "PILLOW_OK", True)
    monkeypatch.setattr(face_screen, "CV2_OK", False)
    monkeypatch.setattr(face_screen, "_detector", None)

    ok, message = face_screen.prepare_portfolio_image(str(src), str(dst))
    assert not ok
    assert "screening" in message.lower()
    assert not dst.exists()


def test_profile_photo_processing_still_works_without_face_detector(tmp_path, monkeypatch):
    src = tmp_path / "profile.png"
    dst = tmp_path / "profile.jpg"
    Image.new("RGBA", (80, 60), (10, 20, 30, 128)).save(src)
    monkeypatch.setattr(face_screen, "PILLOW_OK", True)

    ok, message = face_screen.prepare_profile_image(str(src), str(dst))
    assert ok, message
    with Image.open(dst) as image:
        assert image.format == "JPEG"
        assert image.mode == "RGB"
        assert image.size == (80, 60)


def test_oversized_image_is_rejected_before_processing(tmp_path, monkeypatch):
    src = tmp_path / "sample.png"
    dst = tmp_path / "output.jpg"
    Image.new("RGB", (10, 10), "white").save(src)
    monkeypatch.setattr(face_screen, "PILLOW_OK", True)
    monkeypatch.setattr(face_screen, "MAX_INPUT_BYTES", 1)

    ok, message = face_screen.prepare_profile_image(str(src), str(dst))
    assert not ok
    assert "12 mb" in message.lower() or "size" in message.lower()
    assert not dst.exists()


def test_face_screen_checks_pixel_dimensions_before_opencv_decode(tmp_path, monkeypatch):
    src = tmp_path / "large_dimensions.png"
    Image.new("RGB", (20, 20), "white").save(src)
    monkeypatch.setattr(face_screen, "PILLOW_OK", True)
    monkeypatch.setattr(face_screen, "CV2_OK", True)
    monkeypatch.setattr(face_screen, "_detector", object())
    monkeypatch.setattr(face_screen, "MAX_INPUT_PIXELS", 100)

    class Cv2MustNotDecode:
        @staticmethod
        def imread(_path):
            raise AssertionError("OpenCV should not decode oversized images")

    monkeypatch.setattr(face_screen, "cv2", Cv2MustNotDecode())
    try:
        face_screen.contains_face(str(src))
    except ValueError as exc:
        assert "dimensions" in str(exc).lower()
    else:
        raise AssertionError("Oversized image should have been rejected")
