#!/usr/bin/env python3
"""Device A demo CLI.

  python -m demo.device_a --pair
      Generates (or loads) device-a's long-term identity, saves a QR code, and waits for
      device-b to scan it and pair back over the network.

  python -m demo.device_a --proximity --transport wifi
      Loads device-a's identity + trust store, discovers nearby devices, and initiates an
      authenticated ephemeral handshake + token exchange with each one that's already paired.

  python -m demo.device_a --proximity --transport wifi --as-stranger
      Same as above but using a fresh, never-paired throwaway identity -- demonstrates that
      the proximity protocol correctly rejects a device it has no trust record for.

In this demo, device_a always plays the pairing/proximity *initiator* role and device_b always
plays the *responder* -- a fixed choice made only to keep the two CLI scripts simple and avoid
both sides trying to initiate at once; the underlying protocol (pairing_protocol.py,
proximity_protocol.py) is symmetric and doesn't care which side calls which function.
"""
import argparse
import socket
import uuid

from demo.common import device_state_dir, log, make_transport, recv_framed
from pairing.pairing_protocol import complete_pairing, load_or_create_identity, make_qr_payload
from pairing.qr_generate import save_qr
from pairing.trust_store import TrustStore
from proximity.proximity_protocol import AuthenticationFailedError, UnpairedPeerError, initiate_encounter

DEVICE_ID = "device-a"


def cmd_pair(port: int):
    state = device_state_dir(DEVICE_ID)
    identity = load_or_create_identity(DEVICE_ID, state / "identity.json")
    qr_path = state / "qr.png"
    save_qr(make_qr_payload(identity), str(qr_path))
    log(DEVICE_ID, f"identity ready, QR code saved to {qr_path}")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(1)
    bound_port = server.getsockname()[1]
    log(DEVICE_ID, f"listening on port {bound_port} for device-b's pairing response")
    log(DEVICE_ID, f"run: python -m demo.device_b --pair --qr-image {qr_path} --peer-port {bound_port}")

    conn, addr = server.accept()
    log(DEVICE_ID, f"connection from {addr}, completing handshake")
    with conn:
        response = recv_framed(conn)
    server.close()

    fingerprint, peer = complete_pairing(identity, response)
    trust_store = TrustStore(state / "trust_store.json")
    trust_store.save_peer(peer["device_id"], peer["x25519_pub"], peer["mlkem_pub"], fingerprint)

    log(DEVICE_ID, f"paired with {peer['device_id']}")
    log(DEVICE_ID, f"SAFETY NUMBER (compare with device-b): {fingerprint}")


def cmd_proximity(transport_name: str, as_stranger: bool, discover_timeout: float):
    if as_stranger:
        stranger_id = f"stranger-{uuid.uuid4().hex[:8]}"
        state = device_state_dir(stranger_id)
        identity = load_or_create_identity(stranger_id, state / "identity.json")
        trust_store = TrustStore(state / "trust_store.json")  # deliberately empty: never paired
        my_id = stranger_id
    else:
        state = device_state_dir(DEVICE_ID)
        identity = load_or_create_identity(DEVICE_ID, state / "identity.json")
        trust_store = TrustStore(state / "trust_store.json")
        my_id = DEVICE_ID

    transport = make_transport(transport_name)
    transport.start(my_id)
    log(my_id, f"advertising over {transport_name}, discovering nearby devices...")
    try:
        peers = transport.discover(timeout=discover_timeout)
        log(my_id, f"discovered: {peers}")
        if not peers:
            log(my_id, "no peers found -- is device-b running --proximity too?")

        for peer_id in peers:
            token = f"presence-token-from-{my_id}".encode()
            try:
                received = initiate_encounter(transport, identity, trust_store, peer_id, token)
                log(my_id, f"ACCEPTED by {peer_id}: authenticated handshake complete, received token {received!r}")
            except UnpairedPeerError as e:
                log(my_id, f"SKIPPED {peer_id}: {e}")
            except AuthenticationFailedError as e:
                log(my_id, f"REJECTED by {peer_id}: {e}")
            except TimeoutError as e:
                log(my_id, f"TIMEOUT talking to {peer_id}: {e}")
    finally:
        transport.stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pair", action="store_true", help="run the QR pairing flow")
    parser.add_argument("--port", type=int, default=0, help="port to listen on during --pair (0 = pick automatically)")
    parser.add_argument("--proximity", action="store_true", help="run the proximity discovery + handshake flow")
    parser.add_argument("--transport", choices=["wifi", "ble"], default="wifi")
    parser.add_argument("--as-stranger", action="store_true", help="use a fresh unpaired identity (demonstrates rejection)")
    parser.add_argument("--discover-timeout", type=float, default=5.0)
    args = parser.parse_args()

    if args.pair:
        cmd_pair(args.port)
    elif args.proximity:
        cmd_proximity(args.transport, args.as_stranger, args.discover_timeout)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
