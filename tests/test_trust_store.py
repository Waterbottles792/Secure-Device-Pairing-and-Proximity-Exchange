from pathlib import Path

from pairing.trust_store import TrustStore


def test_save_and_get_peer(tmp_path):
    store = TrustStore(tmp_path / "store.json")
    store.save_peer("device-b", b"\x01" * 32, b"\x02" * 1184, "AB12-CD34")

    record = store.get_peer("device-b")
    assert record["x25519_pub"] == b"\x01" * 32
    assert record["mlkem_pub"] == b"\x02" * 1184
    assert record["fingerprint"] == "AB12-CD34"


def test_unknown_peer_returns_none(tmp_path):
    store = TrustStore(tmp_path / "store.json")
    assert store.get_peer("nope") is None
    assert not store.is_paired("nope")


def test_list_peers(tmp_path):
    store = TrustStore(tmp_path / "store.json")
    store.save_peer("a", b"\x01" * 32, b"\x02" * 1184, "fp-a")
    store.save_peer("b", b"\x03" * 32, b"\x04" * 1184, "fp-b")
    assert set(store.list_peers()) == {"a", "b"}


def test_persists_across_instances(tmp_path):
    path = tmp_path / "store.json"
    TrustStore(path).save_peer("a", b"\x01" * 32, b"\x02" * 1184, "fp-a")
    reopened = TrustStore(path)
    assert reopened.is_paired("a")
