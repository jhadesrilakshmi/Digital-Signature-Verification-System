"""
server.py
---------
Receiver: listens on TCP, verifies incoming signature packages.

Usage:
    python server.py --pub keys/alice_public.pem --port 5050
    python server.py --pub keys/alice_public.pem --tls-cert certs/server.crt --tls-key certs/server.key
"""

import argparse
import base64
import json
import os
import socket
import ssl
import sys
import threading

sys.path.insert(0, os.path.dirname(__file__))

import config as cfg
import audit_log
from crypto_core import load_public_key, verify_package
from netproto import recv_json, send_json

DEFAULT_PORT = cfg.SERVER_PORT
RECEIVED_DIR = cfg.RECEIVED_DIR



def handle_client(conn: socket.socket, addr: tuple, trusted_pub, check_replay: bool):
    peer = f"{addr[0]}:{addr[1]}"
    print(f"[+] Connection from {peer}")
    try:
        package = recv_json(conn)
        if not package:
            print(f"[{peer}] Empty message received.")
            send_json(conn, {"status": "INVALID", "reason": "Empty package."})
            audit_log.log_verify(status="INVALID", reason="Empty package.", source="server", peer=peer)
            return

        result = verify_package(package, trusted_public_key=trusted_pub, check_replay=check_replay)

        response = {"status": result.status, "reason": result.reason}
        send_json(conn, response)

        audit_log.log_verify(
            status=result.status,
            reason=result.reason,
            source="server",
            peer=peer,
            filename=package.get("filename", ""),
            sha256=package.get("message_sha256", ""),
            nonce=package.get("nonce", ""),
            algorithm=package.get("algorithm", ""),
        )

        if result.ok:
            _save_received(package)
            print(f"[{peer}] [VALID]  -- {package.get('filename') or '(text message)'}")
        else:
            print(f"[{peer}] [ERROR]  {result.status} -- {result.reason}")


    except ConnectionError as exc:
        print(f"[{peer}] Connection error: {exc}")
        audit_log.log_error("server", f"connection error from {peer}: {exc}")
    except Exception as exc:
        print(f"[{peer}] Unexpected error: {exc}")
        audit_log.log_error("server", f"error from {peer}: {exc}")
        try:
            send_json(conn, {"status": "INVALID", "reason": str(exc)})
        except Exception:
            pass
    finally:
        conn.close()



def _save_received(package: dict) -> None:
    """Save accepted message/file to the received/ directory."""
    os.makedirs(RECEIVED_DIR, exist_ok=True)
    try:
        message_bytes = base64.b64decode(package.get("message_b64", ""))
        filename = package.get("filename") or f"message_{package['nonce']}.txt"
        # Sanitize filename
        filename = os.path.basename(filename)
        out_path = os.path.join(RECEIVED_DIR, filename)
        with open(out_path, "wb") as f:
            f.write(message_bytes)
        # Also save the full package
        meta_path = out_path + ".meta.json"
        meta = {k: v for k, v in package.items() if k != "message_b64"}
        with open(meta_path, "w") as f:
            json.dump(meta, f, indent=2)
    except Exception as exc:
        print(f"  [warn] Could not save received file: {exc}")


def main():
    parser = argparse.ArgumentParser(description="DSVS Receiver Server")
    parser.add_argument("--pub", required=True, help="Trusted sender public key (PEM).")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Listen port (default {DEFAULT_PORT}).")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (default 0.0.0.0).")
    parser.add_argument("--no-replay", action="store_true", help="Disable replay protection.")
    parser.add_argument("--tls-cert", help="TLS certificate file (PEM).")
    parser.add_argument("--tls-key", help="TLS private key file (PEM).")
    args = parser.parse_args()

    # Load trusted public key
    try:
        with open(args.pub, "rb") as f:
            trusted_pub = load_public_key(f.read())
        print(f"Trusted public key loaded from: {args.pub}")
    except Exception as exc:
        print(f"ERROR loading public key: {exc}", file=sys.stderr)
        sys.exit(1)

    check_replay = not args.no_replay

    # Create listening socket
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((args.host, args.port))
    server_sock.listen(16)

    # Optional TLS wrap
    if args.tls_cert and args.tls_key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(args.tls_cert, args.tls_key)
        server_sock = ctx.wrap_socket(server_sock, server_side=True)
        print(f"TLS enabled (cert: {args.tls_cert})")

    mode = "TLS" if (args.tls_cert and args.tls_key) else "TCP"
    replay_str = "enabled" if check_replay else "disabled"
    print(f"DSVS Server listening on {args.host}:{args.port} ({mode}) — replay protection {replay_str}")
    print("Press Ctrl+C to stop.\n")

    try:
        while True:
            conn, addr = server_sock.accept()
            t = threading.Thread(
                target=handle_client,
                args=(conn, addr, trusted_pub, check_replay),
                daemon=True,
            )
            t.start()
    except KeyboardInterrupt:
        print("\nServer stopped.")
    finally:
        server_sock.close()


if __name__ == "__main__":
    main()
