## Secure Device Pairing and Proximity Exchange

Two devices pair once via QR code (out-of-band, MITM-resistant) to establish long-term trust,
then automatically recognize and securely reconnect with each other whenever they're near again
(over BLE or WiFi) using fresh ephemeral keys authenticated against that trust.

Crypto core: hybrid **X25519 + ML-KEM-768** key exchange (NIST FIPS 203) combined via HKDF, and
**ASCON-128a** AEAD (NIST SP 800-232 lightweight crypto) for encryption. See
`docs/SECURITY_ANALYSIS.md` for the full threat model and citations, and `plan.md` for the
phase-by-phase build spec (see git history for how each phase landed).



## Setup

Requires Python 3.11+ and a C toolchain (cmake, gcc/clang) -- `liboqs-python` builds the
`liboqs` C library from source on first install, which takes several minutes.

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
pytest tests/ -q                # ~35s, 38 tests
```

BLE (`bleak` + `bless`) needs a powered Bluetooth adapter and, on Linux, BlueZ over D-Bus
(`bluetoothctl power on` if it shows `PowerState: off-blocked`). WiFi (`zeroconf` + TCP sockets)
needs no special permissions and works out of the box; it's the transport this project verified
live end-to-end (see "What was not live-verified" in `docs/SECURITY_ANALYSIS.md` -- the dev
sandbox this was built in had no powered BLE radio, so BLE is implemented and unit-tested with a
mocked adapter but not live-demoed against two real radios).

## Running the demo

All commands run from the repo root with `venv` activated. Two terminals, both processes on the
same machine for this demo (loopback WiFi/localhost) -- see `demo/device_a.py` /
`demo/device_b.py` docstrings for why device_a is always the initiator and device_b the
responder here.

**1. Pair the two devices (QR code, one-time):**

```bash
# terminal 1
python -m demo.device_a --pair
# prints a port number and saves demo/state/device-a/qr.png

# terminal 2 (after terminal 1 prints its port)
python -m demo.device_b --pair --qr-image demo/state/device-a/qr.png --peer-port <printed-port>
```

Both terminals print a **safety number** (fingerprint) -- confirm they match, the same way you'd
check Signal safety numbers. If you have a real webcam, drop `--qr-image` from device_b's command
to scan the QR live instead of from the saved PNG.

**2. Proximity reconnect (after pairing, can be run repeatedly / after restarting both processes):**

```bash
# terminal 1
python -m demo.device_b --proximity --transport wifi --duration 30

# terminal 2
python -m demo.device_a --proximity --transport wifi
```

You'll see both sides log `ACCEPTED ...: authenticated handshake complete, received token ...`.
Swap `--transport wifi` for `--transport ble` if you have two real BLE-capable machines nearby.

**3. Demonstrate rejection of an unpaired device:**

```bash
python -m demo.device_a --proximity --transport wifi --as-stranger
```

Uses a fresh, never-paired identity; device_b's terminal will *not* show an ACCEPTED line for it
(the stranger's own trust store is empty, so it skips before even contacting device_b -- see
`tests/test_proximity_protocol.py` for the automated test of the responder-side rejection path,
i.e. an attacker who *does* attempt contact and gets turned away for a bad MAC).

## Benchmark

```bash
python -m benchmarks.run_benchmark
```

Runs 20 full proximity handshakes over WiFi and (if a BLE adapter is available) BLE, writes raw
latencies to `benchmarks/results/latency_raw.csv` and a comparison chart to
`benchmarks/results/latency_comparison.png`. On the dev machine this was built on: WiFi averaged
~6 ms/handshake over localhost; BLE was skipped (no powered adapter) rather than faked.

## Repository layout

```
core/        X25519, ML-KEM-768, hybrid HKDF combiner, ASCON AEAD
pairing/     QR generation/scanning, trust store, pairing handshake
proximity/   BLE/WiFi transport abstraction, proximity handshake protocol
demo/        device_a.py / device_b.py CLIs
benchmarks/  BLE vs WiFi latency benchmark
docs/        SECURITY_ANALYSIS.md
tests/       pytest suite (38 tests)
```

## Tests

```bash
pytest tests/ -q
```

WiFi and proximity-over-loopback tests are live (real sockets/mDNS, no mocking). BLE tests mock
`BleakScanner`/`BlessServer` since no adapter was available in the dev sandbox -- see
`tests/test_transport_ble.py` and `docs/SECURITY_ANALYSIS.md`.


