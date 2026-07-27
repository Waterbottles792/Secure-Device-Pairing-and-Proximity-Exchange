"""ML-KEM-768 post-quantum key encapsulation wrapper (NIST FIPS 203), via liboqs-python."""
import oqs

ALGORITHM = "ML-KEM-768"


class PQKeypair:
    """Holds a liboqs KeyEncapsulation object alive for the lifetime of the private key.

    liboqs-python keeps the private key inside the KeyEncapsulation object itself, so
    the object must stay alive until decapsulate() is called.
    """

    def __init__(self, secret_key: bytes | None = None, public_key: bytes | None = None):
        if secret_key is None:
            self._kem = oqs.KeyEncapsulation(ALGORITHM)
            self.public_key = self._kem.generate_keypair()
        else:
            # Reloading a persisted identity: liboqs has no "derive public key from
            # secret key" call, so the public key must be persisted alongside it.
            if public_key is None:
                raise ValueError("public_key is required when reloading from secret_key")
            self._kem = oqs.KeyEncapsulation(ALGORITHM, secret_key=secret_key)
            self.public_key = public_key

    def decapsulate(self, ciphertext: bytes) -> bytes:
        return self._kem.decap_secret(ciphertext)

    def export_secret_key(self) -> bytes:
        return self._kem.export_secret_key()


def generate_keypair() -> PQKeypair:
    return PQKeypair()


def load_keypair(secret_key: bytes, public_key: bytes) -> PQKeypair:
    return PQKeypair(secret_key=secret_key, public_key=public_key)


def encapsulate(peer_public_key: bytes) -> tuple[bytes, bytes]:
    """Encapsulate against a peer's public key. Returns (ciphertext, shared_secret)."""
    with oqs.KeyEncapsulation(ALGORITHM) as kem:
        ciphertext, shared_secret = kem.encap_secret(peer_public_key)
    return ciphertext, shared_secret


def demo():
    alice = generate_keypair()
    ciphertext, bob_secret = encapsulate(alice.public_key)
    alice_secret = alice.decapsulate(ciphertext)

    assert alice_secret == bob_secret
    print(f"pq_kex ({ALGORITHM}) demo OK, shared secret = {alice_secret.hex()[:16]}...")


if __name__ == "__main__":
    demo()
