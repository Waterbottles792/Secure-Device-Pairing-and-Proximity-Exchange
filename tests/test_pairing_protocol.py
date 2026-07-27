import pytest

from pairing.pairing_protocol import (
    generate_identity, save_identity, load_identity, load_or_create_identity,
    make_qr_payload, respond_to_qr, complete_pairing, compute_fingerprint,
)


def test_full_pairing_handshake_matching_fingerprints(tmp_path):
    alice = generate_identity("device-a")
    bob = generate_identity("device-b")

    qr_payload = make_qr_payload(alice)
    response, bob_fingerprint, alice_seen_by_bob = respond_to_qr(bob, qr_payload)
    alice_fingerprint, bob_seen_by_alice = complete_pairing(alice, response)

    assert alice_fingerprint == bob_fingerprint
    assert alice_seen_by_bob["device_id"] == "device-a"
    assert alice_seen_by_bob["x25519_pub"] == alice.x25519_pub
    assert bob_seen_by_alice["device_id"] == "device-b"
    assert bob_seen_by_alice["x25519_pub"] == bob.x25519_pub


def test_fingerprint_order_independent():
    alice = generate_identity("device-a")
    bob = generate_identity("device-b")
    fp1 = compute_fingerprint("device-a", alice.x25519_pub, alice.mlkem_pub,
                               "device-b", bob.x25519_pub, bob.mlkem_pub)
    fp2 = compute_fingerprint("device-b", bob.x25519_pub, bob.mlkem_pub,
                               "device-a", alice.x25519_pub, alice.mlkem_pub)
    assert fp1 == fp2


def test_wrong_identity_cannot_complete_pairing():
    alice = generate_identity("device-a")
    mallory = generate_identity("mallory")  # attacker, doesn't have alice's private key
    bob = generate_identity("device-b")

    qr_payload = make_qr_payload(alice)
    response, _, _ = respond_to_qr(bob, qr_payload)

    with pytest.raises(ValueError):
        complete_pairing(mallory, response)


def test_identity_persists_across_reload(tmp_path):
    path = tmp_path / "identity.json"
    identity = generate_identity("device-a")
    save_identity(identity, path)

    reloaded = load_identity(path)
    assert reloaded.device_id == "device-a"
    assert reloaded.x25519_pub == identity.x25519_pub
    assert reloaded.mlkem_pub == identity.mlkem_pub

    # reloaded private key must actually work in the protocol, not just match public bytes
    bob = generate_identity("device-b")
    response, _, _ = respond_to_qr(bob, make_qr_payload(identity))
    complete_pairing(reloaded, response)


def test_load_or_create_identity_is_stable(tmp_path):
    path = tmp_path / "identity.json"
    first = load_or_create_identity("device-a", path)
    second = load_or_create_identity("device-a", path)
    assert first.x25519_pub == second.x25519_pub
    assert first.mlkem_pub == second.mlkem_pub
