"""ASCON AEAD wrapper.

Uses the `ascon` PyPI package (reference implementation of the Ascon
candidate as submitted to/standardized by NIST SP 800-232). At the time
of writing, `ascon==0.0.9` exposes the pre-finalization variant names
("Ascon-128", "Ascon-128a", "Ascon-80pq") rather than the finalized
"Ascon-AEAD128" name — the underlying permutation and security properties
are the same lightweight-crypto design NIST standardized. We use
Ascon-128a (16-byte key, 16-byte nonce, higher throughput than Ascon-128).
See docs/SECURITY_ANALYSIS.md for the full note.
"""
import os

import ascon

VARIANT = "Ascon-128a"
KEY_SIZE = 16
NONCE_SIZE = 16


def encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> tuple[bytes, bytes]:
    """Encrypt with a fresh random nonce. Returns (nonce, ciphertext)."""
    if len(key) != KEY_SIZE:
        raise ValueError(f"ASCON key must be {KEY_SIZE} bytes, got {len(key)}")
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = ascon.encrypt(key, nonce, associated_data, plaintext, variant=VARIANT)
    return nonce, ciphertext


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes = b"") -> bytes:
    """Decrypt and verify. Raises ValueError on tamper/auth failure."""
    if len(key) != KEY_SIZE:
        raise ValueError(f"ASCON key must be {KEY_SIZE} bytes, got {len(key)}")
    plaintext = ascon.decrypt(key, nonce, associated_data, ciphertext, variant=VARIANT)
    if plaintext is None:
        raise ValueError("ASCON authentication failed: ciphertext or nonce was tampered with")
    return plaintext


def demo():
    key = os.urandom(KEY_SIZE)
    nonce, ct = encrypt(key, b"hello proximity", b"ctx")
    pt = decrypt(key, nonce, ct, b"ctx")
    assert pt == b"hello proximity"

    tampered = bytes([ct[0] ^ 0x01]) + ct[1:]
    try:
        decrypt(key, nonce, tampered, b"ctx")
        raise AssertionError("tampered ciphertext should not decrypt")
    except ValueError:
        pass

    bad_nonce = bytes([nonce[0] ^ 0x01]) + nonce[1:]
    try:
        decrypt(key, bad_nonce, ct, b"ctx")
        raise AssertionError("tampered nonce should not decrypt")
    except ValueError:
        pass

    print("ascon_aead demo OK")


if __name__ == "__main__":
    demo()
