"""BLE transport tests. No real Bluetooth hardware is used or required: BleakScanner is mocked
for discovery, and the chunk-reassembly logic is exercised directly. This is the "mocked
adapter" test path noted in plan.md -- see proximity/transport_ble.py for why a live two-radio
test isn't run in this environment.
"""
from unittest.mock import AsyncMock, patch

import pytest

from proximity.transport_ble import BleTransport, CHUNK_SIZE, _build_frame, _parse_frame


def test_frame_round_trip():
    frame = _build_frame("device-a", b"hello proximity token")
    sender_id, body = _parse_frame(frame[4:])
    assert sender_id == "device-a"
    assert body == b"hello proximity token"


def test_reassembles_chunked_writes_into_inbox():
    transport = BleTransport()
    transport.my_id = "device-b"
    payload = _build_frame("device-a", b"x" * (CHUNK_SIZE * 3))  # forces multiple chunks

    for i in range(0, len(payload), CHUNK_SIZE):
        transport._on_write(None, payload[i:i + CHUNK_SIZE])

    sender_id, body = transport._inbox.get(timeout=1)
    assert sender_id == "device-a"
    assert body == b"x" * (CHUNK_SIZE * 3)


def test_discover_uses_bleak_scanner():
    transport = BleTransport()
    transport.my_id = "device-a"

    fake_device = type("FakeDevice", (), {"name": "device-b", "address": "AA:BB:CC:DD:EE:FF"})()

    import asyncio
    transport._loop = asyncio.new_event_loop()
    import threading
    threading.Thread(target=transport._loop.run_forever, daemon=True).start()

    try:
        with patch("proximity.transport_ble.BleakScanner.discover", new=AsyncMock(return_value=[fake_device])):
            found = transport.discover(timeout=0.1)
        assert found == ["device-b"]
        assert transport._peers["device-b"] == "AA:BB:CC:DD:EE:FF"
    finally:
        transport._loop.call_soon_threadsafe(transport._loop.stop)
