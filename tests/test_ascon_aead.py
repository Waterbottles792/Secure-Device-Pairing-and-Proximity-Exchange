import os
import pytest

from core.ascon_aead import encrypt, decrypt, KEY_SIZE


def test_round_trip():
    key = os.urandom(KEY_SIZE)
    nonce, ct = encrypt(key, b"secret message", b"aad")
    pt = decrypt(key, nonce, ct, b"aad")
    assert pt == b"secret message"


def test_empty_plaintext():
    key = os.urandom(KEY_SIZE)
    nonce, ct = encrypt(key, b"")
    assert decrypt(key, nonce, ct) == b""


def test_tampered_ciphertext_rejected():
    key = os.urandom(KEY_SIZE)
    nonce, ct = encrypt(key, b"secret message")
    tampered = bytes([ct[0] ^ 0x01]) + ct[1:]
    with pytest.raises(ValueError):
        decrypt(key, nonce, tampered)


def test_tampered_nonce_rejected():
    key = os.urandom(KEY_SIZE)
    nonce, ct = encrypt(key, b"secret message")
    bad_nonce = bytes([nonce[0] ^ 0x01]) + nonce[1:]
    with pytest.raises(ValueError):
        decrypt(key, bad_nonce, ct)


def test_wrong_associated_data_rejected():
    key = os.urandom(KEY_SIZE)
    nonce, ct = encrypt(key, b"secret message", b"context-a")
    with pytest.raises(ValueError):
        decrypt(key, nonce, ct, b"context-b")


def test_nonces_are_unique_per_call():
    key = os.urandom(KEY_SIZE)
    nonce1, _ = encrypt(key, b"msg")
    nonce2, _ = encrypt(key, b"msg")
    assert nonce1 != nonce2
