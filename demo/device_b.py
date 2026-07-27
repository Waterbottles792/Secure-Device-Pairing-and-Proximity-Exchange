#!/usr/bin/env python3
"""Device B demo CLI.

  python -m demo.device_b --pair --qr-image demo/state/device-a/qr.png --peer-port <printed by device_a>
      Scans the QR code device-a displayed (from a saved image -- see qr_scan.py for the
      webcam-based path if you have one) and completes pairing back over the network.

  python -m demo.device_b --proximity --transport wifi
      Loads device-b's identity + trust store and waits, responding to any authenticated
      proximity encounter from a paired peer (and rejecting anyone else) until --duration
      seconds pass.

See demo/device_a.py for why device_a is always the initiator and device_b the responder here.
"""
import argparse
import socket
import time

from demo.common import device_state_dir, log, make_transport, send_framed
from pairing.pairing_protocol import load_or_create_identity, respond_to_qr
from pairing.qr_scan import scan_image_file, scan_webcam
from pairing.trust_store import TrustStore
from proximity.proximity_protocol import AuthenticationFailedError, UnpairedPeerError, respond_to_encounter

DEVICE_ID = "device-b"


def cmd_pair(qr_image: str | None, peer_host: str, peer_port: int):
    state = device_state_dir(DEVICE_ID)
    identity = load_or_create_identity(DEVICE_ID, state / "identity.json")

    if qr_image:
        log(DEVICE_ID, f"scanning QR from {qr_image}")
        payload = scan_image_file(qr_image)
    else:
        log(DEVICE_ID, "scanning QR from webcam...")
        payload = scan_webcam()

    response, fingerprint, peer = respond_to_qr(identity, payload)
    log(DEVICE_ID, f"scanned {peer['device_id']}'s public keys, connecting to {peer_host}:{peer_port}")

    with socket.create_connection((peer_host, peer_port), timeout=10) as conn:
        send_framed(conn, response)

    trust_store = TrustStore(state / "trust_store.json")
    trust_store.save_peer(peer["device_id"], peer["x25519_pub"], peer["mlkem_pub"], fingerprint)

    log(DEVICE_ID, f"paired with {peer['device_id']}")
    log(DEVICE_ID, f"SAFETY NUMBER (compare with device-a): {fingerprint}")


def cmd_proximity(transport_name: str, duration: float):
    state = device_state_dir(DEVICE_ID)
    identity = load_or_create_identity(DEVICE_ID, state / "identity.json")
    trust_store = TrustStore(state / "trust_store.json")

    transport = make_transport(transport_name)
    transport.start(DEVICE_ID)
    log(DEVICE_ID, f"advertising over {transport_name}, waiting up to {duration}s for encounters...")
    try:
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            try:
                token = f"presence-token-from-{DEVICE_ID}".encode()
                peer_id, received = respond_to_encounter(transport, identity, trust_store, token, timeout=remaining)
                log(DEVICE_ID, f"ACCEPTED {peer_id}: authenticated handshake complete, received token {received!r}")
            except UnpairedPeerError as e:
                log(DEVICE_ID, f"REJECTED an unpaired peer: {e}")
            except AuthenticationFailedError as e:
                log(DEVICE_ID, f"REJECTED an impersonation attempt: {e}")
            except TimeoutError:
                break
    finally:
        transport.stop()
    log(DEVICE_ID, "done")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pair", action="store_true")
    parser.add_argument("--qr-image", default=None, help="path to a saved QR image (omit to use the webcam)")
    parser.add_argument("--peer-host", default="127.0.0.1")
    parser.add_argument("--peer-port", type=int, default=None)
    parser.add_argument("--proximity", action="store_true")
    parser.add_argument("--transport", choices=["wifi", "ble"], default="wifi")
    parser.add_argument("--duration", type=float, default=30.0, help="seconds to wait for proximity encounters")
    args = parser.parse_args()

    if args.pair:
        if args.peer_port is None:
            parser.error("--pair requires --peer-port (printed by device_a --pair)")
        cmd_pair(args.qr_image, args.peer_host, args.peer_port)
    elif args.proximity:
        cmd_proximity(args.transport, args.duration)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
