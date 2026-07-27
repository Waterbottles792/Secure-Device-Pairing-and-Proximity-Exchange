import queue

import pytest

from core.classical_kex import generate_keypair as generate_x25519_keypair
from core.pq_kex import generate_keypair as generate_pq_keypair
from pairing.pairing_protocol import generate_identity
from pairing.trust_store import TrustStore
from proximity.proximity_protocol import (
    AuthenticationFailedError,
    UnpairedPeerError,
    build_initiate_message,
    initiate_encounter,
    respond_to_encounter,
)


class LoopbackTransport:
    """In-process stand-in for a real Transport: same send/receive shape as
    transport_wifi.WifiTransport / transport_ble.BleTransport, backed by queues instead of a
    network. Keeps these tests fast and hardware-free while exercising the exact same protocol
    code the real transports carry."""

    def __init__(self, my_id, inbox, peer_inbox):
        self.my_id = my_id
        self._inbox = inbox
        self._peer_inbox = peer_inbox

    def send(self, peer_id, data):
        self._peer_inbox.put((self.my_id, data))

    def receive(self, timeout=None):
        try:
            return self._inbox.get(timeout=timeout)
        except queue.Empty:
            raise TimeoutError("no message received within timeout")


@pytest.fixture
def paired_devices(tmp_path):
    alice = generate_identity("device-a")
    bob = generate_identity("device-b")

    alice_store = TrustStore(tmp_path / "alice.json")
    bob_store = TrustStore(tmp_path / "bob.json")
    alice_store.save_peer("device-b", bob.x25519_pub, bob.mlkem_pub, "fp")
    bob_store.save_peer("device-a", alice.x25519_pub, alice.mlkem_pub, "fp")

    q_alice, q_bob = queue.Queue(), queue.Queue()
    alice_transport = LoopbackTransport("device-a", q_alice, q_bob)
    bob_transport = LoopbackTransport("device-b", q_bob, q_alice)

    return {
        "alice": (alice, alice_store, alice_transport),
        "bob": (bob, bob_store, bob_transport),
    }


def _run_responder_in_background(bob, bob_store, bob_transport, token, out):
    import threading

    def run():
        try:
            out["result"] = respond_to_encounter(bob_transport, bob, bob_store, token)
        except Exception as e:  # noqa: BLE001 - captured for the test thread to inspect
            out["error"] = e

    t = threading.Thread(target=run)
    t.start()
    return t


def test_authenticated_handshake_and_token_exchange(paired_devices):
    alice, alice_store, alice_transport = paired_devices["alice"]
    bob, bob_store, bob_transport = paired_devices["bob"]

    out = {}
    t = _run_responder_in_background(bob, bob_store, bob_transport, b"token-from-bob", out)
    alice_received = initiate_encounter(alice_transport, alice, alice_store, "device-b", b"token-from-alice")
    t.join(timeout=5)

    assert alice_received == b"token-from-bob"
    assert out["result"] == ("device-a", b"token-from-alice")


def test_initiator_refuses_unpaired_peer(paired_devices, tmp_path):
    alice, _alice_store, alice_transport = paired_devices["alice"]
    empty_store = TrustStore(tmp_path / "empty.json")

    with pytest.raises(UnpairedPeerError):
        initiate_encounter(alice_transport, alice, empty_store, "device-b", b"token")


def test_responder_refuses_unknown_claimed_device_id(paired_devices):
    """A device claiming an id bob has never paired with at all -- rejected without bob ever
    replying, regardless of what's in the message (bob's trust store has no record to check
    the MAC against in the first place)."""
    bob, bob_store, bob_transport = paired_devices["bob"]

    stranger = generate_identity("stranger")
    ephemeral_x_priv, ephemeral_x_pub = generate_x25519_keypair()
    ephemeral_pq = generate_pq_keypair()
    forged = build_initiate_message(stranger, ephemeral_x_pub, ephemeral_pq.public_key, b"\x00" * 32)
    bob_transport._inbox.put(("stranger", forged))

    with pytest.raises(UnpairedPeerError):
        respond_to_encounter(bob_transport, bob, bob_store, b"token")


def test_responder_rejects_impersonator_with_wrong_long_term_key(paired_devices):
    """Mallory claims device_id "device-a" (a real paired peer of bob's) but signs with a MAC
    key she can't actually derive, since she doesn't hold device-a's real long-term private key.
    This is the core proximity threat the MAC over the long-term-derived key defends against."""
    bob, bob_store, bob_transport = paired_devices["bob"]

    wrong_long_term_key = b"\x00" * 32  # mallory cannot compute the real one
    ephemeral_x_priv, ephemeral_x_pub = generate_x25519_keypair()
    ephemeral_pq = generate_pq_keypair()

    class FakeIdentity:
        device_id = "device-a"

    forged = build_initiate_message(FakeIdentity(), ephemeral_x_pub, ephemeral_pq.public_key, wrong_long_term_key)
    bob_transport._inbox.put(("mallory", forged))

    with pytest.raises(AuthenticationFailedError):
        respond_to_encounter(bob_transport, bob, bob_store, b"token")
