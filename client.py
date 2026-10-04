"""
client.py
---------
Sender: signs a file or text and sends the package to the server over TCP.

Usage:
    python client.py --key keys/alice_private.pem --file samples/message.txt
    python client.py --key keys/alice_private.pem --text "Pay Bob 100"
    python client.py --key keys/alice_private.pem --text "Pay Bob 100" --tamper
    python client.py --key keys/alice_private.pem --text "Pay Bob 100" --replay
    python client.py --key keys/alice_private.pem --text "hello" --tls
"""

import argparse
import base64
import getpass
import os
import socket
import ssl
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))

from crypto_core import load_private_key, sign_message
from netproto import send_json, recv_json

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5050

_last_package = None   # stored for --replay simulation


def main():
    global _last_package

    parser = argparse.ArgumentParser(description="DSVS Sender Client")

    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--file", help="File to sign and send.")
    source.add_argument("--text", help="Inline text message to sign and send.")

    parser.add_argument("--key", required=True, help="Sender's PEM private key.")
    parser.add_argument("--password", action="store_true", help="Prompt for key password.")
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"Server host (default {DEFAULT_HOST}).")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Server port (default {DEFAULT_PORT}).")
    parser.add_argument("--tls", action="store_true", help="Use TLS.")
    parser.add_argument("--tamper", action="store_true", help="Tamper with the message before sending (simulation).")
    parser.add_argument("--replay", action="store_true", help="Resend the previous package (replay simulation).")
    args = parser.parse_args()

    # ── Load private key ──────────────────────────────────────────────
    password: bytes | None = None
    if args.password:
        pw = getpass.getpass("Private key password: ")
        password = pw.encode()

    try:
        with open(args.key, "rb") as f:
            private_key = load_private_key(f.read(), password)
    except FileNotFoundError:
        print(f"ERROR: Key not found: {args.key}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"ERROR loading key: {exc}", file=sys.stderr)
        sys.exit(1)

    # ── Read message ──────────────────────────────────────────────────
    if args.file:
        with open(args.file, "rb") as f:
            message = f.read()
        filename = os.path.basename(args.file)
    else:
        message = args.text.encode("utf-8")
        filename = ""

    # ── Sign ──────────────────────────────────────────────────────────
    if args.replay and _last_package is not None:
        package = _last_package
        print("[SIMULATION] Replaying previous package …")
    else:
        package = sign_message(message, private_key, filename=filename)
        _last_package = package

    # ── Tamper simulation ─────────────────────────────────────────────
    if args.tamper:
        original_b64 = package["message_b64"]
        tampered_msg = base64.b64decode(original_b64).replace(b"1", b"9").replace(b"B", b"A")
        if tampered_msg == base64.b64decode(original_b64):
            tampered_msg += b" [TAMPERED]"
        package["message_b64"] = base64.b64encode(tampered_msg).decode("ascii")
        print("[SIMULATION] Message tampered — signature should be INVALID.")

    # ── Connect and send ──────────────────────────────────────────────
    print(f"Connecting to {args.host}:{args.port} …", end=" ", flush=True)
    try:
        raw_sock = socket.create_connection((args.host, args.port), timeout=10)
        if args.tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # demo mode; use CERT_REQUIRED in production
            sock = ctx.wrap_socket(raw_sock, server_hostname=args.host)
        else:
            sock = raw_sock
        print("connected.")
    except Exception as exc:
        print(f"FAILED\nERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        send_json(sock, package)
        response = recv_json(sock)
    except Exception as exc:
        print(f"ERROR during communication: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        sock.close()

    status = response.get("status", "UNKNOWN")
    reason = response.get("reason", "")
    icon = "✔" if status == "VALID" else "✘"
    print(f"{icon}  Server response: {status}" + (f" — {reason}" if reason else ""))
    sys.exit(0 if status == "VALID" else 1)


if __name__ == "__main__":
    main()
