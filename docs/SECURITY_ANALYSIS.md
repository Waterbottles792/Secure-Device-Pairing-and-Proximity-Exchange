# Security Analysis

## System summary

Two protocols share one crypto core (hybrid X25519 + ML-KEM-768 key exchange combined via HKDF,
ASCON-128a AEAD for encryption):

1. **Pairing** (`pairing/pairing_protocol.py`) -- a QR code carries device A's long-term
   identity public keys out-of-band to device B. B replies over the network with its own
   long-term public keys, encrypted under a key only A can derive. Both sides display a
   human-comparable fingerprint.
2. **Proximity** (`proximity/proximity_protocol.py`) -- previously-paired devices, on
   rediscovering each other (BLE or WiFi), run a fresh ephemeral X25519 + ML-KEM handshake
   authenticated by an HMAC keyed off the *long-term* shared secret from pairing, then exchange
   an ASCON-encrypted token.

## What this protects against

**Network MITM during pairing.** Device A's long-term public keys travel only via the QR code
(a channel a remote network attacker cannot observe). Deriving the pairing session key requires
either A's private X25519 key (for the DH half) or A's private ML-KEM key (to decapsulate the
KEM ciphertext) -- an attacker who never saw the QR has neither, and cannot compute the session
key even though the KEM ciphertext and B's ephemeral-for-pairing X25519 public key travel over
the network in the clear (see `pairing_protocol.py` module docstring for the full argument).
The post-pairing fingerprint comparison (`compute_fingerprint`, mirroring Signal's safety
numbers) is the human-verifiable backstop: if an attacker did have visual/physical access to the
QR (see limits below), the two devices would still show *different* keys underneath a forged
fingerprint only if the attacker also controls what's displayed on both screens -- comparing the
fingerprint out loud on a call, for instance, still catches it.

**Impersonation at the proximity stage.** `proximity_protocol.py`'s HMAC over each ephemeral
handshake is keyed by `HKDF(DH(my_long_term_priv, stored_peer_long_term_pub))` -- a value
reproducible only by whoever holds the paired peer's actual long-term private key. An attacker
who was never paired (`UnpairedPeerError`) or who claims a real paired peer's `device_id` without
holding that peer's private key (`AuthenticationFailedError`, see
`tests/test_proximity_protocol.py::test_responder_rejects_impersonator_with_wrong_long_term_key`)
cannot produce a valid MAC and is rejected before any token is exchanged.

**Harvest-now-decrypt-later.** Every session key (pairing and proximity) is derived from *both*
an X25519 DH and an ML-KEM-768 encapsulation, concatenated before HKDF. Breaking the session key
requires breaking both primitives -- a future quantum computer breaking X25519 alone still
leaves ML-KEM-768 (NIST FIPS 203, targeting NIST security level 3) protecting the key.

**Forward secrecy per proximity encounter.** The proximity handshake's session key comes from
*fresh* ephemeral X25519 + ML-KEM keypairs generated per encounter and discarded afterward
(never written to disk). Compromising a device's long-term identity keys later does not let an
attacker decrypt a previously-recorded encounter's token, since the ephemeral private keys used
to derive that specific session key no longer exist anywhere. (Pairing itself is a one-time
event and is not forward-secret in this sense -- it establishes the long-term trust that
proximity then uses.)

**Tampering / message forgery.** ASCON-128a is an AEAD: every ciphertext carries an integrity
tag over both the ciphertext and any associated data. `core/ascon_aead.py` verifies this on
every decrypt and raises rather than returning corrupted plaintext (see
`tests/test_ascon_aead.py::test_tampered_ciphertext_rejected` /
`test_tampered_nonce_rejected`).

## What this does NOT protect against

- **Physical device compromise.** If an attacker extracts a device's long-term private keys
  (from `demo/state/<id>/identity.json` in this demo, or wherever a real deployment persists
  them), they can impersonate that device to any of its paired peers indefinitely, and decrypt
  any *future* proximity encounter with peers who still trust it (though not past ones, per
  forward secrecy above). At-rest key encryption / secure enclave storage is out of scope here;
  `identity.json` is plaintext JSON.
- **Physical QR substitution / shoulder-surfing.** The security argument above assumes B scans
  the QR that A actually displays. An attacker physically present who swaps in their own QR (or
  photographs A's QR and relays it before the real B scans) is a classic "evil maid" /
  QR-substitution attack this system does not detect on its own -- the fingerprint comparison
  step exists specifically to let a human catch this, but only if the human actually checks it.
- **Traffic analysis / metadata.** BLE advertisements and mDNS service announcements broadcast
  a device's `device_id` and, for WiFi, its raw IP address in the clear during discovery (see
  `proximity/transport_wifi.py`'s `_local_ip()` / `ServiceInfo`). An observer can tell that a
  paired encounter *occurred* between two identifiable devices and roughly when, even though
  they can't read the token content. No traffic-analysis resistance (e.g. random rotating
  identifiers per broadcast) is implemented.
- **Denial of service.** Nothing rate-limits proximity handshake attempts; a nearby attacker who
  knows a valid `device_id` string (even without being able to complete the MAC check) can still
  cause a responder to spend CPU on an ML-KEM encapsulation per bogus attempt.
- **Malicious but genuinely-paired peers.** Trust is binary and long-term once established --
  there's no revocation flow in this demo (deleting a peer from `trust_store.json` is the only
  "unpair" mechanism), and a paired device is fully trusted for every future encounter.

## Why ASCON instead of AES/DES

ASCON was selected by NIST in Feb 2023 as the winner of the Lightweight Cryptography competition
and standardized as SP 800-232 (Ascon-AEAD128) in 2023. It's a sponge-based (not
substitution-permutation-network) design specifically targeted at constrained devices: smaller
RAM/code footprint and no dependency on hardware AES acceleration, which matters for the
BLE/IoT-flavored proximity use case here where the "device" may be a microcontroller rather than
a full computer. AES remains secure and is the right choice for most general-purpose systems;
ASCON is the deliberate choice here because it's the standard built for exactly this constrained
setting, not because AES has any known weakness. DES/3DES were never seriously considered --
56/112-bit effective key sizes are inadequate by modern standards regardless of the device class.

**Implementation note:** the `ascon` PyPI package (`ascon==0.0.9`) used here implements the
pre-finalization variant names ("Ascon-128", "Ascon-128a", "Ascon-80pq") rather than the
finalized SP 800-232 "Ascon-AEAD128" name -- same underlying permutation and design lineage, but
not yet updated to the exact finalized parameter set/API. `core/ascon_aead.py` uses
"Ascon-128a" (128-bit key, higher throughput than "Ascon-128"). See that module's docstring.

## What was not live-verified

BLE (`proximity/transport_ble.py`, via `bleak` for the central/scanning role and `bless` for the
peripheral/GATT-server role) was implemented and unit-tested with the adapter mocked
(`tests/test_transport_ble.py`), but the only Bluetooth radio available in the development
sandbox was powered off / rfkill-blocked (`hciconfig -a` showed `DOWN`, `bluetoothctl show`
showed `PowerState: off-blocked`), and a live BLE demo needs two separate radios in any case.
`benchmarks/run_benchmark.py` attempts it live and gracefully records "SKIPPED (Failed to
register advertisement)" rather than fabricating numbers. WiFi (`transport_wifi.py`, mDNS via
`zeroconf` + TCP) was verified live end-to-end, including in the benchmark (~6 ms average
proximity handshake latency on localhost over 20 runs).

## Citations

- NIST FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard* (ML-KEM), Aug 2024.
- NIST SP 800-232, *Ascon-Based Lightweight Cryptography Standards for Constrained Devices*, 2023.
- Dobraunig, Eichlseder, Mendel, Schläffer, *Ascon v1.2: Lightweight Authenticated Encryption
  and Hashing*, Journal of Cryptology, 2021 (the original Ascon design/NIST LWC submission).
- Bernstein, *Curve25519: New Diffie-Hellman Speed Records*, PKC 2006 (the X25519 curve).
- Signal, *PQXDH Key Agreement Protocol* specification, 2023 (hybrid classical+PQ handshake
  design this project's `core/hybrid.py` concatenate-then-HKDF construction follows).
- Apple, *iMessage with PQ3: The new state of the art in quantum-secure messaging at scale*,
  2024 (production precedent for hybrid classical+PQ messaging).
- Google/Apple, *Exposure Notification Cryptography Specification*, 2020 (design precedent for
  BLE proximity protocols using rotating ephemeral identifiers -- relevant contrast, since this
  project's `device_id` is *not* rotated, per the metadata/traffic-analysis limitation above).
