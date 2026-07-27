"""Live WiFi transport test: two real WifiTransport instances on localhost using real mDNS
(zeroconf) discovery and real TCP sockets. No mocking -- this is the transport verified live.
"""
import pytest

from proximity.transport_wifi import WifiTransport


@pytest.fixture
def devices():
    a = WifiTransport()
    b = WifiTransport()
    a.start("test-device-a")
    b.start("test-device-b")
    yield a, b
    a.stop()
    b.stop()


def test_discover_finds_peer(devices):
    a, b = devices
    peers = a.discover(timeout=3.0)
    assert "test-device-b" in peers


def test_send_receive_round_trip(devices):
    a, b = devices
    a.discover(timeout=3.0)
    a.send("test-device-b", b"hello from A")
    sender, body = b.receive(timeout=5.0)
    assert sender == "test-device-a"
    assert body == b"hello from A"


def test_send_to_unknown_peer_raises(devices):
    a, _b = devices
    with pytest.raises(ValueError):
        a.send("nonexistent-peer", b"data")


def test_receive_times_out_with_no_message(devices):
    a, _b = devices
    with pytest.raises(TimeoutError):
        a.receive(timeout=0.5)
