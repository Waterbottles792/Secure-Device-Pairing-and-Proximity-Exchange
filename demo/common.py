"""Shared helpers for demo/device_a.py and demo/device_b.py: per-device state paths and the
tiny length-framed socket helpers used only during --pair (proximity uses transport_wifi.py /
transport_ble.py instead, which have their own framing)."""
import socket
import struct
import time
from pathlib import Path

from proximity.transport_ble import BleTransport
from proximity.transport_wifi import WifiTransport

STATE_ROOT = Path(__file__).resolve().parent / "state"


def device_state_dir(device_id: str) -> Path:
    d = STATE_ROOT / device_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def log(device_id: str, message: str):
    print(f"[{time.strftime('%H:%M:%S')}] [{device_id}] {message}", flush=True)


def send_framed(conn: socket.socket, data: bytes):
    conn.sendall(struct.pack(">I", len(data)) + data)


def recv_framed(conn: socket.socket) -> bytes:
    length = struct.unpack(">I", _recv_exact(conn, 4))[0]
    return _recv_exact(conn, length)


def _recv_exact(conn: socket.socket, n: int) -> bytes:
    chunks = []
    remaining = n
    while remaining > 0:
        chunk = conn.recv(remaining)
        if not chunk:
            raise ConnectionError("connection closed before full message received")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def make_transport(name: str):
    if name == "wifi":
        return WifiTransport()
    if name == "ble":
        return BleTransport()
    raise ValueError(f"unknown transport: {name}")
