"""Abstract transport interface shared by BLE and WiFi.

The proximity protocol (proximity_protocol.py) only talks to this interface -- it doesn't know
or care whether messages travel over BLE or WiFi. Implementations own their own discovery
mechanism (mDNS for WiFi, BLE advertising/scanning for BLE) but must expose peers as plain
string peer_ids.
"""
from abc import ABC, abstractmethod


class Transport(ABC):
    @abstractmethod
    def start(self, my_id: str):
        """Begin advertising this device and listening for incoming messages."""

    @abstractmethod
    def discover(self, timeout: float = 5.0) -> list[str]:
        """Return peer_ids of nearby devices found within timeout seconds."""

    @abstractmethod
    def send(self, peer_id: str, data: bytes):
        """Send data to a previously-discovered peer."""

    @abstractmethod
    def receive(self, timeout: float | None = None) -> tuple[str, bytes]:
        """Block until a message arrives (or timeout elapses -> TimeoutError). Returns (peer_id, data)."""

    @abstractmethod
    def stop(self):
        """Stop advertising/listening and release resources."""
