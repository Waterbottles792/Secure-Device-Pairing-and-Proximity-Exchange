"""WiFi transport: mDNS discovery (zeroconf) + TCP sockets for data exchange.

Each message is length-framed and self-describes its sender so receive() doesn't need to
correlate connections by IP address:
    [1 byte sender_id_len][sender_id utf-8][4 bytes body_len big-endian][body]
"""
import queue
import socket
import struct
import threading
import time

from zeroconf import ServiceBrowser, ServiceInfo, Zeroconf

from proximity.transport_base import Transport

SERVICE_TYPE = "_secprox._tcp.local."


class _Listener:
    def __init__(self, zeroconf: Zeroconf, my_service_name: str, peers: dict, discovered_event_names: set):
        self._zeroconf = zeroconf
        self._my_service_name = my_service_name
        self._peers = peers
        self._discovered_event_names = discovered_event_names

    def add_service(self, zc, service_type, name):
        if name == self._my_service_name:
            return
        info = zc.get_service_info(service_type, name)
        if info is None or not info.addresses:
            return
        peer_id = name[: -len("." + SERVICE_TYPE)]
        host = socket.inet_ntoa(info.addresses[0])
        self._peers[peer_id] = (host, info.port)
        self._discovered_event_names.add(peer_id)

    def update_service(self, zc, service_type, name):
        self.add_service(zc, service_type, name)

    def remove_service(self, zc, service_type, name):
        pass


class WifiTransport(Transport):
    def __init__(self):
        self._zeroconf: Zeroconf | None = None
        self._service_info: ServiceInfo | None = None
        self._browser: ServiceBrowser | None = None
        self._server_socket: socket.socket | None = None
        self._accept_thread: threading.Thread | None = None
        self._running = False
        self._peers: dict[str, tuple[str, int]] = {}
        self._inbox: queue.Queue = queue.Queue()
        self.my_id: str | None = None

    def start(self, my_id: str):
        self.my_id = my_id
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind(("0.0.0.0", 0))
        self._server_socket.listen(5)
        port = self._server_socket.getsockname()[1]

        self._running = True
        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._accept_thread.start()

        local_ip = _local_ip()
        self._zeroconf = Zeroconf()
        service_name = f"{my_id}.{SERVICE_TYPE}"
        self._service_info = ServiceInfo(
            SERVICE_TYPE,
            service_name,
            addresses=[socket.inet_aton(local_ip)],
            port=port,
            properties={},
        )
        self._zeroconf.register_service(self._service_info)

        self._discovered_names: set = set()
        listener = _Listener(self._zeroconf, service_name, self._peers, self._discovered_names)
        self._browser = ServiceBrowser(self._zeroconf, SERVICE_TYPE, listener)

    def discover(self, timeout: float = 5.0) -> list[str]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            time.sleep(0.1)
        return [p for p in self._peers if p != self.my_id]

    def send(self, peer_id: str, data: bytes):
        if peer_id not in self._peers:
            raise ValueError(f"unknown peer_id (not discovered): {peer_id}")
        host, port = self._peers[peer_id]
        with socket.create_connection((host, port), timeout=5) as sock:
            sock.sendall(_frame(self.my_id, data))

    def receive(self, timeout: float | None = None) -> tuple[str, bytes]:
        try:
            return self._inbox.get(timeout=timeout)
        except queue.Empty:
            raise TimeoutError("no message received within timeout")

    def stop(self):
        self._running = False
        if self._server_socket:
            self._server_socket.close()
        if self._zeroconf and self._service_info:
            self._zeroconf.unregister_service(self._service_info)
        if self._zeroconf:
            self._zeroconf.close()

    def _accept_loop(self):
        while self._running:
            try:
                conn, _addr = self._server_socket.accept()
            except OSError:
                break
            threading.Thread(target=self._handle_connection, args=(conn,), daemon=True).start()

    def _handle_connection(self, conn: socket.socket):
        try:
            sender_id, body = _read_frame(conn)
            self._inbox.put((sender_id, body))
        except (ConnectionError, struct.error):
            pass
        finally:
            conn.close()


def _frame(sender_id: str, body: bytes) -> bytes:
    sender_bytes = sender_id.encode("utf-8")
    return struct.pack("B", len(sender_bytes)) + sender_bytes + struct.pack(">I", len(body)) + body


def _recv_exact(conn: socket.socket, n: int) -> bytes:
    chunks = []
    remaining = n
    while remaining > 0:
        chunk = conn.recv(remaining)
        if not chunk:
            raise ConnectionError("connection closed before full frame received")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_frame(conn: socket.socket) -> tuple[str, bytes]:
    id_len = _recv_exact(conn, 1)[0]
    sender_id = _recv_exact(conn, id_len).decode("utf-8")
    body_len = struct.unpack(">I", _recv_exact(conn, 4))[0]
    body = _recv_exact(conn, body_len)
    return sender_id, body


def _local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def demo():
    a = WifiTransport()
    b = WifiTransport()
    a.start("device-a")
    b.start("device-b")
    try:
        peers_seen_by_a = a.discover(timeout=3.0)
        print(f"device-a discovered: {peers_seen_by_a}")
        assert "device-b" in peers_seen_by_a

        a.send("device-b", b"hello from A")
        sender, body = b.receive(timeout=5.0)
        assert sender == "device-a"
        assert body == b"hello from A"
        print("transport_wifi demo OK")
    finally:
        a.stop()
        b.stop()


if __name__ == "__main__":
    demo()
