"""Decode a QR code back into the raw pairing payload.

Two paths:
  - scan_webcam(): live webcam capture via OpenCV, decoded with pyzbar (needs a webcam).
  - scan_image_file(path): decode a saved QR image (PNG/JPG) -- the fallback demo path used
    when no webcam is available, and what the test suite exercises.

The scanned QR content is base64 text (see qr_generate.py for why), so every successful scan is
base64-decoded back into the original binary payload before being returned.
"""
import base64

import cv2
from pyzbar import pyzbar


def _decode_frame(frame) -> bytes | None:
    decoded = pyzbar.decode(frame)
    if not decoded:
        return None
    return base64.b64decode(decoded[0].data)


def scan_image_file(path: str) -> bytes:
    frame = cv2.imread(path)
    if frame is None:
        raise FileNotFoundError(f"could not read image: {path}")
    payload = _decode_frame(frame)
    if payload is None:
        raise ValueError(f"no QR code found in image: {path}")
    return payload


def scan_webcam(camera_index: int = 0, timeout_frames: int = 300) -> bytes:
    cap = cv2.VideoCapture(camera_index)
    if not cap.isOpened():
        raise RuntimeError("could not open webcam")
    try:
        for _ in range(timeout_frames):
            ok, frame = cap.read()
            if not ok:
                continue
            payload = _decode_frame(frame)
            if payload is not None:
                return payload
        raise TimeoutError("no QR code detected within timeout")
    finally:
        cap.release()


def demo():
    from pairing.qr_generate import build_payload, save_qr
    from pairing.qr_scan import scan_image_file
    import tempfile
    from pathlib import Path

    x25519_pub = bytes(range(32))
    mlkem_pub = bytes((i * 7) % 256 for i in range(1184))
    payload = build_payload("device-a", x25519_pub, mlkem_pub)

    with tempfile.TemporaryDirectory() as tmp:
        path = str(Path(tmp) / "qr.png")
        save_qr(payload, path)
        scanned = scan_image_file(path)
        assert scanned == payload, "scanned payload does not match original"

    print("qr_scan demo OK (round-tripped through a saved QR image)")


if __name__ == "__main__":
    demo()
