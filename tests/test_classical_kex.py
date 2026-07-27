from core.classical_kex import generate_keypair, derive_shared_secret


def test_shared_secret_matches():
    alice_priv, alice_pub = generate_keypair()
    bob_priv, bob_pub = generate_keypair()

    alice_secret = derive_shared_secret(alice_priv, bob_pub)
    bob_secret = derive_shared_secret(bob_priv, alice_pub)

    assert alice_secret == bob_secret
    assert len(alice_secret) == 32


def test_different_peers_different_secrets():
    alice_priv, alice_pub = generate_keypair()
    _, bob_pub = generate_keypair()
    _, carol_pub = generate_keypair()

    assert derive_shared_secret(alice_priv, bob_pub) != derive_shared_secret(alice_priv, carol_pub)
