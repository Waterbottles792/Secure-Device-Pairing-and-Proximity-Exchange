from core.pq_kex import generate_keypair, load_keypair, encapsulate, ALGORITHM


def test_shared_secret_matches():
    alice = generate_keypair()
    ciphertext, bob_secret = encapsulate(alice.public_key)
    alice_secret = alice.decapsulate(ciphertext)
    assert alice_secret == bob_secret


def test_algorithm_is_mlkem768():
    assert ALGORITHM == "ML-KEM-768"


def test_different_keypairs_different_ciphertexts():
    alice = generate_keypair()
    ct1, secret1 = encapsulate(alice.public_key)
    ct2, secret2 = encapsulate(alice.public_key)
    # fresh randomness each encapsulation
    assert ct1 != ct2
    assert secret1 != secret2


def test_reload_persisted_keypair():
    alice = generate_keypair()
    secret_key = alice.export_secret_key()
    ciphertext, expected_secret = encapsulate(alice.public_key)

    reloaded = load_keypair(secret_key, alice.public_key)
    assert reloaded.decapsulate(ciphertext) == expected_secret
