"""Benchmark: proximity handshake cost over WiFi vs BLE.

For each transport, runs N full proximity encounters (discover once, then N x
[authenticated ephemeral handshake + token exchange]) between two in-process devices and
records wall-clock latency per encounter. Also reports bytes-on-the-wire per encounter, which
is protocol-fixed (X25519/ML-KEM-768/ASCON field sizes never vary) so it's computed directly
rather than measured.

BLE requires two live, powered BLE radios to actually run (see proximity/transport_ble.py) --
if the local adapter isn't available/powered, this script catches that, marks BLE as skipped
with the reason, and still produces WiFi results and the chart/CSV for whatever did run. This
mirrors the documented environment constraint rather than papering over it with fake numbers.
"""
import csv
import queue
import threading
import time
from pathlib import Path

from pairing.pairing_protocol import generate_identity
from pairing.trust_store import TrustStore
from proximity.proximity_protocol import initiate_encounter, respond_to_encounter
from proximity.transport_ble import BleTransport
from proximity.transport_wifi import WifiTransport

RESULTS_DIR = Path(__file__).resolve().parent / "results"
TOKEN = b"presence-token"

# Protocol-fixed message sizes (id length assumed 8 chars, e.g. "device-a"/"device-b").
INITIATE_BYTES = 1 + 8 + 32 + 1184 + 32
RESPONSE_BYTES = 1 + 8 + 32 + 1088 + 32
TOKEN_BYTES = 16 + len(TOKEN) + 16
BLE_OUTER_PREFIX = 4  # transport_ble.py wraps each message in a 4-byte total-length prefix
WIFI_FRAME_OVERHEAD = 1 + 8 + 4  # transport_wifi.py: [1B id_len][id][4B body_len]


def bytes_on_wire(transport_name: str) -> int:
    per_message_overhead = BLE_OUTER_PREFIX if transport_name == "ble" else WIFI_FRAME_OVERHEAD
    total = INITIATE_BYTES + RESPONSE_BYTES + 2 * TOKEN_BYTES
    return total + 4 * per_message_overhead


def _setup_paired_devices(tmp_dir: Path):
    alice = generate_identity("device-a")
    bob = generate_identity("device-b")
    alice_store = TrustStore(tmp_dir / "alice.json")
    bob_store = TrustStore(tmp_dir / "bob.json")
    alice_store.save_peer("device-b", bob.x25519_pub, bob.mlkem_pub, "fp")
    bob_store.save_peer("device-a", alice.x25519_pub, alice.mlkem_pub, "fp")
    return alice, alice_store, bob, bob_store


def run_transport_benchmark(transport_name: str, num_runs: int, tmp_dir: Path) -> list[float]:
    alice, alice_store, bob, bob_store = _setup_paired_devices(tmp_dir)

    make = {"wifi": WifiTransport, "ble": BleTransport}[transport_name]
    alice_transport, bob_transport = make(), make()
    alice_transport.start("device-a")
    bob_transport.start("device-b")
    try:
        alice_transport.discover(timeout=5.0 if transport_name == "wifi" else 8.0)

        latencies = []
        for _ in range(num_runs):
            out = {}

            def responder():
                out["result"] = respond_to_encounter(bob_transport, bob, bob_store, TOKEN, timeout=15)

            t = threading.Thread(target=responder)
            t.start()
            start = time.perf_counter()
            initiate_encounter(alice_transport, alice, alice_store, "device-b", TOKEN, timeout=15)
            elapsed = time.perf_counter() - start
            t.join(timeout=15)
            if "result" not in out:
                raise RuntimeError("responder did not complete")
            latencies.append(elapsed)
        return latencies
    finally:
        alice_transport.stop()
        bob_transport.stop()


def main(num_runs: int = 20):
    import tempfile

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    results: dict[str, list[float]] = {}
    skipped: dict[str, str] = {}

    for transport_name in ("wifi", "ble"):
        print(f"benchmarking {transport_name}...")
        with tempfile.TemporaryDirectory() as tmp:
            try:
                results[transport_name] = run_transport_benchmark(transport_name, num_runs, Path(tmp))
                avg_ms = 1000 * sum(results[transport_name]) / len(results[transport_name])
                print(f"  {transport_name}: {len(results[transport_name])} runs, avg {avg_ms:.1f} ms")
            except Exception as e:
                skipped[transport_name] = str(e)
                print(f"  {transport_name}: SKIPPED ({e})")

    csv_path = RESULTS_DIR / "latency_raw.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["transport", "run_index", "latency_seconds"])
        for transport_name, latencies in results.items():
            for i, latency in enumerate(latencies):
                writer.writerow([transport_name, i, latency])
        for transport_name, reason in skipped.items():
            writer.writerow([transport_name, "SKIPPED", reason])
    print(f"raw latencies written to {csv_path}")

    for transport_name in ("wifi", "ble"):
        if transport_name in results or transport_name in skipped:
            print(f"{transport_name} bytes-on-wire per encounter: {bytes_on_wire(transport_name)}")

    if results:
        _plot(results)
    return results, skipped


def _plot(results: dict[str, list[float]]):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    names = list(results.keys())
    avgs_ms = [1000 * sum(v) / len(v) for v in results.values()]

    fig, ax = plt.subplots(figsize=(5, 4))
    ax.bar(names, avgs_ms, color=["#4C72B0", "#DD8452"][: len(names)])
    ax.set_ylabel("avg proximity handshake latency (ms)")
    ax.set_title("Proximity handshake cost: BLE vs WiFi")
    for i, v in enumerate(avgs_ms):
        ax.text(i, v, f"{v:.1f}", ha="center", va="bottom")
    fig.tight_layout()

    out_path = RESULTS_DIR / "latency_comparison.png"
    fig.savefig(out_path)
    print(f"chart written to {out_path}")


if __name__ == "__main__":
    main()
