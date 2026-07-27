import tempfile
from pathlib import Path

from pairing.qr_generate import build_payload, parse_payload, save_qr
from pairing.qr_scan import scan_image_file


def _sample_keys():
    return bytes(range(32)), bytes((i * 7) % 256 for i in range(1184))


def test_build_and_parse_payload_round_trip():
    x25519_pub, mlkem_pub = _sample_keys()
    payload = build_payload("device-a", x25519_pub, mlkem_pub)
    parsed = parse_payload(payload)
    assert parsed["device_id"] == "device-a"
    assert parsed["x25519_pub"] == x25519_pub
    assert parsed["mlkem_pub"] == mlkem_pub


def test_payload_fits_single_qr_code():
    import qrcode
    import base64

    x25519_pub, mlkem_pub = _sample_keys()
    payload = build_payload("device-a", x25519_pub, mlkem_pub)
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L)
    qr.add_data(base64.b64encode(payload), optimize=0)
    qr.make(fit=True)
    assert qr.version <= 40


def test_qr_image_scan_round_trip():
    x25519_pub, mlkem_pub = _sample_keys()
    payload = build_payload("device-b", x25519_pub, mlkem_pub)
    with tempfile.TemporaryDirectory() as tmp:
        path = str(Path(tmp) / "qr.png")
        save_qr(payload, path)
        scanned = scan_image_file(path)
        assert scanned == payload
        assert parse_payload(scanned)["device_id"] == "device-b"
