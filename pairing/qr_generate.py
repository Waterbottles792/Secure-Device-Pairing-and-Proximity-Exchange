"""Encode a device's long-term identity (device_id + X25519 + ML-KEM-768 public keys) into a QR code.

Capacity note: ML-KEM-768 public keys are 1184 bytes, X25519 public keys are 32 bytes. A raw
binary payload (device_id + both keys) comes out around ~1200-1300 bytes depending on device_id
length. QR byte-mode at error-correction level L tops out at 2953 bytes (version 40), so this
fits in a *single* QR code -- no multi-frame splitting needed.

Encoding gotcha found during testing: the raw binary payload is base64-encoded before going into
the QR code. This is *not* for capacity (raw bytes alone would fit) -- it's because the zbar
scanner library (used by qr_scan.py) normalizes byte-mode QR payloads through UTF-8 on decode,
silently corrupting any byte >= 0x80 (e.g. 0x80 comes back as the two bytes 0xC2 0x80). Base64
keeps the QR content to printable ASCII, which round-trips through zbar untouched. This costs
~33% size overhead (~1227 raw bytes -> ~1640 base64 chars) but still fits comfortably at
error-correction level L (version ~30 of 40).

Payload framing (all binary, big-endian lengths), base64-encoded before QR encoding:
  [1 byte device_id_len][device_id utf-8 bytes][32 bytes x25519_pub][2 bytes mlkem_len][mlkem_pub bytes]
"""
import base64
import struct

import qrcode


def build_payload(device_id: str, x25519_pub: bytes, mlkem_pub: bytes) -> bytes:
    device_id_bytes = device_id.encode("utf-8")
    if len(device_id_bytes) > 255:
        raise ValueError("device_id too long (max 255 bytes utf-8)")
    if len(x25519_pub) != 32:
        raise ValueError("x25519_pub must be 32 bytes")
    return (
        struct.pack("B", len(device_id_bytes))
        + device_id_bytes
        + x25519_pub
        + struct.pack(">H", len(mlkem_pub))
        + mlkem_pub
    )


def parse_payload(payload: bytes) -> dict:
    offset = 0
    device_id_len = payload[offset]
    offset += 1
    device_id = payload[offset:offset + device_id_len].decode("utf-8")
    offset += device_id_len
    x25519_pub = payload[offset:offset + 32]
    offset += 32
    mlkem_len = struct.unpack(">H", payload[offset:offset + 2])[0]
    offset += 2
    mlkem_pub = payload[offset:offset + mlkem_len]
    return {"device_id": device_id, "x25519_pub": x25519_pub, "mlkem_pub": mlkem_pub}


def make_qr_image(payload: bytes):
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L)
    qr.add_data(base64.b64encode(payload), optimize=0)
    qr.make(fit=True)
    return qr.make_image()


def save_qr(payload: bytes, path: str) -> str:
    img = make_qr_image(payload)
    img.save(path)
    return path


def demo():
    x25519_pub = bytes(range(32))
    mlkem_pub = bytes((i * 7) % 256 for i in range(1184))
    payload = build_payload("device-a", x25519_pub, mlkem_pub)
    print(f"payload size = {len(payload)} bytes")

    parsed = parse_payload(payload)
    assert parsed["device_id"] == "device-a"
    assert parsed["x25519_pub"] == x25519_pub
    assert parsed["mlkem_pub"] == mlkem_pub

    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L)
    qr.add_data(base64.b64encode(payload), optimize=0)
    qr.make(fit=True)
    print(f"fits in a single QR code: version {qr.version} (max version is 40)")
    print("qr_generate demo OK")


if __name__ == "__main__":
    demo()
