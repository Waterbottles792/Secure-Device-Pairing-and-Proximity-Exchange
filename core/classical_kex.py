"""X25519 classical Diffie-Hellman key exchange wrapper."""
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization


def generate_keypair() -> tuple[X25519PrivateKey, bytes]:
    """Returns (private_key, raw_public_key_bytes)."""
    private_key = X25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_key, public_bytes


def derive_shared_secret(private_key: X25519PrivateKey, peer_public_bytes: bytes) -> bytes:
    peer_public_key = X25519PublicKey.from_public_bytes(peer_public_bytes)
    return private_key.exchange(peer_public_key)


def demo():
    alice_priv, alice_pub = generate_keypair()
    bob_priv, bob_pub = generate_keypair()

    alice_secret = derive_shared_secret(alice_priv, bob_pub)
    bob_secret = derive_shared_secret(bob_priv, alice_pub)

    assert alice_secret == bob_secret
    print(f"classical_kex demo OK, shared secret = {alice_secret.hex()[:16]}...")


if __name__ == "__main__":
    demo()
