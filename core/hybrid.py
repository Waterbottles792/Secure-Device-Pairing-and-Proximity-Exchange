"""Combine classical (X25519) and post-quantum (ML-KEM-768) shared secrets into one session key.

Concatenate-then-HKDF, the standard hybrid-KEX construction (cf. Signal's PQXDH, TLS hybrid
key-exchange drafts): as long as at least one of the two component secrets is uncompromised,
the derived session key is secure.
"""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SESSION_KEY_LEN = 16  # bytes, matches ASCON-128a key size


def combine_secrets(classical_secret: bytes, pq_secret: bytes, info: bytes = b"hybrid-session-key") -> bytes:
    ikm = classical_secret + pq_secret
    return HKDF(
        algorithm=hashes.SHA256(),
        length=SESSION_KEY_LEN,
        salt=None,
        info=info,
    ).derive(ikm)


def demo():
    classical_secret = b"\x01" * 32
    pq_secret = b"\x02" * 32

    alice_key = combine_secrets(classical_secret, pq_secret)
    bob_key = combine_secrets(classical_secret, pq_secret)

    assert alice_key == bob_key
    assert len(alice_key) == SESSION_KEY_LEN
    print(f"hybrid demo OK, session key = {alice_key.hex()}")


if __name__ == "__main__":
    demo()
