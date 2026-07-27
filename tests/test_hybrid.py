from core.hybrid import combine_secrets, SESSION_KEY_LEN


def test_same_inputs_same_key():
    key1 = combine_secrets(b"\x01" * 32, b"\x02" * 32)
    key2 = combine_secrets(b"\x01" * 32, b"\x02" * 32)
    assert key1 == key2
    assert len(key1) == SESSION_KEY_LEN


def test_different_inputs_different_keys():
    key1 = combine_secrets(b"\x01" * 32, b"\x02" * 32)
    key2 = combine_secrets(b"\x01" * 32, b"\x03" * 32)
    assert key1 != key2


def test_pq_break_still_needs_classical_secret():
    # if pq secret alone is known (attacker breaks PQ), key still depends on classical secret
    key_known_pq = combine_secrets(b"\x01" * 32, b"\x02" * 32)
    key_wrong_classical = combine_secrets(b"\xff" * 32, b"\x02" * 32)
    assert key_known_pq != key_wrong_classical
