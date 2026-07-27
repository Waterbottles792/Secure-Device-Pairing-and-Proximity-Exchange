# Secure Device Pairing & Proximity Exchange — Implementation Plan

## What this project is

A two-part secure system:

1. **QR-based pairing** — two devices establish long-term mutual trust for the first time, using
   a QR code as an out-of-band channel to prevent man-in-the-middle attacks during the initial
   handshake.
2. **Proximity token exchange** — previously-paired devices automatically recognize and securely
   reconnect with each other whenever they're near again, over either **BLE or WiFi** (pluggable
   transport), using fresh ephemeral keys authenticated against the trust established in step 1.

Both parts share one cryptographic core:
- **Hybrid key exchange:** X25519 (classical elliptic-curve Diffie-Hellman) + ML-KEM-768
  (post-quantum, NIST FIPS 203, finalized Aug 2024), combined via HKDF into a single session key.
- **Data encryption:** **ASCON** (NIST's 2023 Lightweight Cryptography standard, SP 800-232) —
  used instead of AES/DES, chosen specifically because it's designed for constrained/low-power
  devices, which matches the BLE/IoT-flavored proximity use case.

Note: `Secure_Pairing_Proximity_Project_Explained.pdf` was referenced as background reading but
was not present in this project folder when implementation started; this plan.md (plus the
NIST/RFC citations in `docs/SECURITY_ANALYSIS.md`) was used as the spec of record instead.

**End goal:** a working demo where (a) two devices pair by scanning a QR code and establish a
stored trust record, and (b) those same two devices, run again later, automatically detect each
other over BLE or WiFi, complete a fresh authenticated handshake, and exchange encrypted tokens —
plus a benchmark comparing BLE vs WiFi proximity handshake cost, and a security write-up.

---

## Tech stack

- **Language:** Python 3.11+
- **Classical KEX:** `cryptography` library — `X25519PrivateKey` / `X25519PublicKey`
- **Post-quantum KEX:** `liboqs-python`, algorithm `ML-KEM-768`
- **KDF:** `cryptography.hazmat.primitives.kdf.hkdf.HKDF`
- **Data encryption:** `ascon` (PyPI reference implementation of NIST SP 800-232 Ascon-AEAD128)
- **QR generation:** `qrcode`
- **QR scanning:** `opencv-python` + `pyzbar` (webcam-based scan), or manual paste of decoded
  payload as a fallback demo path
- **BLE transport:** `bleak` (cross-platform BLE advertise/scan/GATT)
- **WiFi transport:** `zeroconf` (mDNS discovery) + raw UDP/TCP sockets
- **Trust store:** local JSON file or `sqlite3`
- **Benchmarking:** Python `time` + `matplotlib`
- **Testing:** `pytest`

---

## Repository structure

```
secure-pairing-proximity/
├── plan.md
├── requirements.txt
├── core/
│   ├── classical_kex.py       # X25519 wrapper
│   ├── pq_kex.py               # ML-KEM wrapper
│   ├── hybrid.py               # combine secrets via HKDF
│   └── ascon_aead.py           # ASCON encrypt/decrypt helpers
├── pairing/
│   ├── qr_generate.py          # encode identity pubkeys into a QR code
│   ├── qr_scan.py               # decode a scanned QR code
│   ├── pairing_protocol.py     # full pairing handshake logic
│   └── trust_store.py           # persist paired-peer records
├── proximity/
│   ├── transport_base.py        # abstract transport interface (discover/send/receive)
│   ├── transport_ble.py         # BLE implementation via bleak
│   ├── transport_wifi.py        # WiFi/mDNS + socket implementation
│   └── proximity_protocol.py    # discovery + authenticated ephemeral handshake + token exchange
├── demo/
│   ├── device_a.py               # CLI entry point simulating "Device A"
│   └── device_b.py               # CLI entry point simulating "Device B"
├── benchmarks/
│   ├── run_benchmark.py          # compare BLE vs WiFi proximity handshake cost
│   └── results/
├── tests/
│   ├── test_classical_kex.py
│   ├── test_pq_kex.py
│   ├── test_hybrid.py
│   ├── test_ascon_aead.py
│   ├── test_pairing_protocol.py
│   └── test_proximity_protocol.py
└── docs/
    └── SECURITY_ANALYSIS.md
```

(See git history / commit messages for the phase-by-phase build order: crypto core, then QR
pairing, then transports, then the proximity protocol, then demo/benchmark/docs.)

## Definition of done

- [x] All Phase 1 crypto-core unit tests pass (`pytest`)
- [x] Two devices can complete QR-based pairing and store matching trust records with matching
      fingerprints
- [x] QR payload size handling is implemented and documented (single high-density code, multi-frame,
      or compression — whichever was chosen)
- [x] Both BLE and WiFi transports independently support discovery and data exchange
- [x] Previously-paired devices auto-detect each other and complete an authenticated ephemeral
      handshake + encrypted token exchange over both transports
- [x] An unpaired/unknown device is correctly rejected at the proximity stage (demonstrated, not
      just assumed)
- [x] Benchmark comparing BLE vs WiFi proximity handshake cost is generated
- [x] `docs/SECURITY_ANALYSIS.md` is complete with an honest threat model and citations
- [x] Project runs end-to-end from a clean clone following the run instructions (see README.md)

Note on BLE: real BLE hardware / OS-level BLE stack access was not available in the development
sandbox used to build this. `transport_ble.py` is implemented against the same abstract
interface as WiFi and is exercised by unit tests with a mocked adapter, but it has not been
run against real BLE radios. WiFi is the transport verified live end-to-end. See README.md and
docs/SECURITY_ANALYSIS.md for details.
