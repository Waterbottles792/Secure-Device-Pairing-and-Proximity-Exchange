"""BLE transport: bleak (central: scan + GATT client) + bless (peripheral: advertise + GATT server).

Every device runs both roles simultaneously so discover()/send()/receive() stay symmetric with
the WiFi transport: start() advertises a GATT peripheral (for incoming messages) while also
being ready to scan-and-connect-out as a central (for outgoing messages).

bleak/bless are asyncio-only; this module runs its own event loop in a background thread and
bridges every call through asyncio.run_coroutine_threadsafe() so the public interface can stay
synchronous like transport_wifi.py.

BLE ATT writes are MTU-limited (~180 usable bytes is a safe default across platforms), so
messages are length-prefixed and chunked; the peripheral reassembles chunks before delivering
a full message to its inbox. The same self-describing frame format as transport_wifi.py is used
(sender id + body), then wrapped in an outer 4-byte total-length prefix for reassembly.

# ponytail: the peripheral's write handler accumulates chunks into a single shared buffer, so
# only one BLE central can be mid-send to a given peripheral at a time. Fine for a two-device
# demo; if concurrent multi-peer BLE writes are ever needed, key the buffer by client address
# once bless exposes the connecting client's identity to write_request_func.

Environment note: this was developed and unit-tested (with BleakScanner/BlessServer mocked) on
a machine whose only Bluetooth adapter was powered off / rfkill-blocked, so it has not been
exercised against real BLE hardware end-to-end. See docs/SECURITY_ANALYSIS.md and README.md.
"""
import asyncio
import queue
import struct
import threading

from bleak import BleakClient, BleakScanner
from bless import BlessGATTCharacteristic, BlessServer, GATTAttributePermissions, GATTCharacteristicProperties

from proximity.transport_base import Transport

SERVICE_UUID = "3ba0b0f0-8b1a-4b8e-9c6a-0f6f2e6a3b10"
CHAR_UUID = "3ba0b0f1-8b1a-4b8e-9c6a-0f6f2e6a3b10"
CHUNK_SIZE = 180


def _build_frame(sender_id: str, body: bytes) -> bytes:
    sender_bytes = sender_id.encode("utf-8")
    frame = struct.pack("B", len(sender_bytes)) + sender_bytes + struct.pack(">I", len(body)) + body
    return struct.pack(">I", len(frame)) + frame


def _parse_frame(frame: bytes) -> tuple[str, bytes]:
    id_len = frame[0]
    sender_id = frame[1:1 + id_len].decode("utf-8")
    offset = 1 + id_len
    body_len = struct.unpack(">I", frame[offset:offset + 4])[0]
    offset += 4
    return sender_id, frame[offset:offset + body_len]


class BleTransport(Transport):
    def __init__(self):
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._server: BlessServer | None = None
        self._peers: dict[str, str] = {}  # peer_id -> BLE address
        self._inbox: queue.Queue = queue.Queue()
        self._recv_total_len: int | None = None
        self._recv_buffer = bytearray()
        self.my_id: str | None = None

    def start(self, my_id: str):
        self.my_id = my_id
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)
        self._thread.start()
        asyncio.run_coroutine_threadsafe(self._start_server(my_id), self._loop).result(timeout=15)

    async def _start_server(self, my_id: str):
        server = BlessServer(name=my_id, loop=self._loop)
        server.write_request_func = self._on_write
        await server.add_new_service(SERVICE_UUID)
        properties = (
            GATTCharacteristicProperties.write
            | GATTCharacteristicProperties.write_without_response
        )
        permissions = GATTAttributePermissions.writeable
        await server.add_new_characteristic(SERVICE_UUID, CHAR_UUID, properties, None, permissions)
        await server.start()
        self._server = server

    def _on_write(self, characteristic: "BlessGATTCharacteristic", value):
        data = bytes(value)
        if self._recv_total_len is None:
            self._recv_total_len = struct.unpack(">I", data[:4])[0]
            self._recv_buffer = bytearray(data[4:])
        else:
            self._recv_buffer.extend(data)
        if len(self._recv_buffer) >= self._recv_total_len:
            frame = bytes(self._recv_buffer[: self._recv_total_len])
            self._recv_total_len = None
            self._recv_buffer = bytearray()
            sender_id, body = _parse_frame(frame)
            self._inbox.put((sender_id, body))

    def discover(self, timeout: float = 5.0) -> list[str]:
        return asyncio.run_coroutine_threadsafe(self._discover(timeout), self._loop).result(timeout=timeout + 10)

    async def _discover(self, timeout: float) -> list[str]:
        devices = await BleakScanner.discover(timeout=timeout)
        found = []
        for device in devices:
            if device.name and device.name != self.my_id:
                self._peers[device.name] = device.address
                found.append(device.name)
        return found

    def send(self, peer_id: str, data: bytes):
        if peer_id not in self._peers:
            raise ValueError(f"unknown peer_id (not discovered): {peer_id}")
        asyncio.run_coroutine_threadsafe(self._send(peer_id, data), self._loop).result(timeout=20)

    async def _send(self, peer_id: str, data: bytes):
        address = self._peers[peer_id]
        payload = _build_frame(self.my_id, data)
        async with BleakClient(address) as client:
            for i in range(0, len(payload), CHUNK_SIZE):
                chunk = payload[i:i + CHUNK_SIZE]
                await client.write_gatt_char(CHAR_UUID, chunk, response=True)

    def receive(self, timeout: float | None = None) -> tuple[str, bytes]:
        try:
            return self._inbox.get(timeout=timeout)
        except queue.Empty:
            raise TimeoutError("no message received within timeout")

    def stop(self):
        if self._server is not None:
            asyncio.run_coroutine_threadsafe(self._server.stop(), self._loop).result(timeout=10)
        if self._loop is not None:
            self._loop.call_soon_threadsafe(self._loop.stop)


def demo():
    """Live two-radio BLE demo -- requires a powered Bluetooth adapter and a nearby BLE peer
    advertising the same service. Not runnable standalone in a single-adapter sandbox; see
    tests/test_transport_ble.py for the mocked interface-contract test that *does* run here."""
    print("transport_ble.demo() requires two live BLE radios; see tests/test_transport_ble.py "
          "for a hardware-free check of the chunking/framing logic.")


if __name__ == "__main__":
    demo()
