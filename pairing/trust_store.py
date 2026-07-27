"""Persistence for paired-peer long-term trust records.

Backed by a local JSON file. One record per peer_id:
{peer_id: {x25519_pub, mlkem_pub, fingerprint, paired_at}}
"""
import json
import os
import time
from pathlib import Path

DEFAULT_STORE_PATH = Path(__file__).resolve().parent.parent / "trust_store.json"


class TrustStore:
    def __init__(self, path: Path | str = DEFAULT_STORE_PATH):
        self.path = Path(path)
        if not self.path.exists():
            self._write({})

    def _read(self) -> dict:
        with open(self.path) as f:
            return json.load(f)

    def _write(self, data: dict):
        tmp = self.path.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, self.path)

    def save_peer(self, peer_id: str, x25519_pub: bytes, mlkem_pub: bytes, fingerprint: str):
        data = self._read()
        data[peer_id] = {
            "x25519_pub": x25519_pub.hex(),
            "mlkem_pub": mlkem_pub.hex(),
            "fingerprint": fingerprint,
            "paired_at": time.time(),
        }
        self._write(data)

    def get_peer(self, peer_id: str) -> dict | None:
        data = self._read()
        record = data.get(peer_id)
        if record is None:
            return None
        return {
            "x25519_pub": bytes.fromhex(record["x25519_pub"]),
            "mlkem_pub": bytes.fromhex(record["mlkem_pub"]),
            "fingerprint": record["fingerprint"],
            "paired_at": record["paired_at"],
        }

    def list_peers(self) -> list[str]:
        return list(self._read().keys())

    def is_paired(self, peer_id: str) -> bool:
        return self.get_peer(peer_id) is not None


def demo():
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        store = TrustStore(Path(tmp) / "test_store.json")
        assert store.list_peers() == []
        store.save_peer("device-b", b"\x01" * 32, b"\x02" * 1184, "AB12-CD34")
        assert store.is_paired("device-b")
        assert not store.is_paired("device-c")
        record = store.get_peer("device-b")
        assert record["x25519_pub"] == b"\x01" * 32
        assert record["fingerprint"] == "AB12-CD34"
        print("trust_store demo OK")


if __name__ == "__main__":
    demo()
