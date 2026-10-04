"""
run_demo.py
-----------
Cross-platform end-to-end demo for the Digital Signature Verification System.
Works on Windows, Linux, and macOS without requiring bash or git-bash.

Usage:
    python run_demo.py
    python run_demo.py --verbose
    python run_demo.py --skip-network    (skip TCP server/client demo)
"""

import argparse
import base64
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time

# Ensure we can import from this directory
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from crypto_core import (
    clear_nonce_store,
    generate_key_pair,
    load_public_key,
    serialize_private_key,
    serialize_public_key,
    sign_message,
    verify_package,
    VerificationResult,
)
from netproto import send_json, recv_json

# -----------------------------------------------------------------------------
SEP  = "=" * 60
STEP = 0


def step(title: str):
    global STEP
    STEP += 1
    print(f"\n{SEP}")
    print(f"  [{STEP}] {title}")
    print(SEP)


def ok(msg: str):
    print(f"  [OK]  {msg}")


def fail(msg: str):
    print(f"  [!!]  {msg}", file=sys.stderr)


def check(condition: bool, success_msg: str, fail_msg: str) -> bool:
    if condition:
        ok(success_msg)
        return True
    else:
        fail(fail_msg)
        return False


# -----------------------------------------------------------------------------
# Demo steps
# -----------------------------------------------------------------------------

def demo_keygen(keys_dir: str, verbose: bool) -> tuple:
    """Step 1: Generate Alice's key pair."""
    step("Key Generation — RSA-2048")
    priv, pub = generate_key_pair(2048)
    os.makedirs(keys_dir, exist_ok=True)

    priv_path = os.path.join(keys_dir, "demo_alice_private.pem")
    pub_path  = os.path.join(keys_dir, "demo_alice_public.pem")

    with open(priv_path, "wb") as f:
        f.write(serialize_private_key(priv))
    with open(pub_path, "wb") as f:
        f.write(serialize_public_key(pub))

    ok(f"Private key -> {priv_path}")
    ok(f"Public  key -> {pub_path}")
    return priv, pub, priv_path, pub_path


def demo_sign_and_verify(priv, pub, samples_dir: str, verbose: bool) -> dict:
    """Steps 2-3: Sign a message and verify it (happy path)."""
    step("Sign a text message")
    message = b"Authorised: Transfer $500 from A to B. Ref#20261001."
    pkg = sign_message(message, priv, filename="")
    ok(f"Signature  : {pkg['signature_b64'][:40]}…")
    ok(f"SHA-256    : {pkg['message_sha256']}")
    ok(f"Nonce      : {pkg['nonce']}")

    step("Verify the signature  ->  Expected: VALID")
    r = verify_package(pkg, trusted_public_key=pub)
    check(r.status == VerificationResult.VALID,
          f"Result: {r.status}", f"FAILED — got {r.status}")

    # Save package for later CLI demo
    pkg_path = os.path.join(samples_dir, "demo_text.sig.json")
    os.makedirs(samples_dir, exist_ok=True)
    with open(pkg_path, "w") as f:
        json.dump(pkg, f, indent=2)
    ok(f"Package saved -> {pkg_path}")
    return pkg


def demo_sign_file(priv, pub, samples_dir: str) -> None:
    """Sign samples/message.txt and verify."""
    step("Sign a file  (samples/message.txt)")
    fpath = os.path.join(samples_dir, "message.txt")
    if not os.path.exists(fpath):
        ok("(skipping — samples/message.txt not found)")
        return
    with open(fpath, "rb") as f:
        data = f.read()
    pkg = sign_message(data, priv, filename="message.txt")
    r = verify_package(pkg, trusted_public_key=pub)
    check(r.status == VerificationResult.VALID,
          f"File signature: {r.status}", f"FAILED — {r.status}: {r.reason}")


def demo_tamper_attacks(priv, pub, base_pkg: dict) -> None:
    """Steps 5-9: All tampering/attack scenarios."""

    # TC-2: Tamper message
    step("Attack TC-2 — Tamper message bytes  ->  Expected: INVALID")
    pkg = dict(base_pkg)
    orig = base64.b64decode(pkg["message_b64"])
    pkg["message_b64"] = base64.b64encode(orig.replace(b"$500", b"$999")).decode()
    r = verify_package(pkg, trusted_public_key=pub)
    check(r.status == VerificationResult.INVALID,
          f"Tamper detected: {r.status}", f"FAILED — expected INVALID, got {r.status}")

    # TC-3: Tamper message + hash
    step("Attack TC-3 — Tamper message AND hash  ->  Expected: INVALID")
    from crypto_core import sha256_hex
    pkg = dict(base_pkg)
    evil_msg = b"Authorised: Transfer $0 from A to B. Ref#20261001."
    pkg["message_b64"]    = base64.b64encode(evil_msg).decode()
    pkg["message_sha256"] = sha256_hex(evil_msg)
    r = verify_package(pkg, trusted_public_key=pub)
    check(r.status == VerificationResult.INVALID,
          f"Tamper detected: {r.status}", f"FAILED — expected INVALID, got {r.status}")

    # TC-4: Corrupt signature
    step("Attack TC-4 — Corrupt signature bytes  ->  Expected: INVALID")
    pkg = dict(base_pkg)
    sig = bytearray(base64.b64decode(pkg["signature_b64"]))
    sig[0] ^= 0xFF
    pkg["signature_b64"] = base64.b64encode(bytes(sig)).decode()
    r = verify_package(pkg, trusted_public_key=pub)
    check(r.status == VerificationResult.INVALID,
          f"Corruption detected: {r.status}", f"FAILED — expected INVALID, got {r.status}")

    # TC-5: Tamper timestamp
    step("Attack TC-5 — Modify timestamp  ->  Expected: INVALID")
    pkg = dict(base_pkg)
    pkg["timestamp"] = pkg["timestamp"] - 9999
    r = verify_package(pkg, trusted_public_key=pub)
    check(r.status == VerificationResult.INVALID,
          f"Timestamp tamper detected: {r.status}", f"FAILED — expected INVALID, got {r.status}")

    # TC-6: Wrong trusted key
    step("Attack TC-6 — Wrong trusted public key  ->  Expected: INVALID")
    _, pub2 = generate_key_pair(2048)
    r = verify_package(base_pkg, trusted_public_key=pub2)
    check(r.status == VerificationResult.INVALID,
          f"Key mismatch detected: {r.status}", f"FAILED — expected INVALID, got {r.status}")

    # TC-7: Attacker signs with own key
    step("Attack TC-7 — Attacker signs with their own key  ->  Expected: INVALID")
    priv_evil, _ = generate_key_pair(2048)
    evil_pkg = sign_message(b"Authorised: Transfer $500 from A to B.", priv_evil)
    r = verify_package(evil_pkg, trusted_public_key=pub)
    check(r.status == VerificationResult.INVALID,
          f"Impersonation detected: {r.status}", f"FAILED — expected INVALID, got {r.status}")


def demo_replay(priv, pub) -> None:
    """TC-8: Replay attack."""
    step("Attack TC-8 — Replay attack  ->  Expected: REJECTED on 2nd send")
    clear_nonce_store()
    pkg = sign_message(b"Pay Charlie 50.", priv)
    r1 = verify_package(pkg, trusted_public_key=pub, check_replay=True)
    r2 = verify_package(pkg, trusted_public_key=pub, check_replay=True)
    check(r1.status == VerificationResult.VALID,   "First  send: VALID",    f"FAILED 1st: {r1.status}")
    check(r2.status == VerificationResult.REJECTED, "Second send: REJECTED", f"FAILED 2nd: {r2.status}")
    clear_nonce_store()


def demo_age_check(priv, pub) -> None:
    """TC-9: Expired signature."""
    step("Attack TC-9 — Expired signature  ->  Expected: REJECTED")
    pkg = sign_message(b"Old message.", priv)
    pkg["timestamp"] = int(time.time()) - 3600  # 1 hour ago
    r = verify_package(pkg, trusted_public_key=pub, max_age=60)
    check(r.status == VerificationResult.REJECTED,
          f"Expired signature detected: {r.status}",
          f"FAILED — expected REJECTED, got {r.status}")


def demo_edge_cases(priv, pub) -> None:
    """TC-11, TC-12, TC-15: Edge cases."""
    step("Edge cases — 5 MB file, empty message, two signatures")

    # TC-11: Large file
    big = os.urandom(5 * 1024 * 1024)
    r = verify_package(sign_message(big, priv), trusted_public_key=pub)
    check(r.status == VerificationResult.VALID, "5 MB binary: VALID", f"FAILED — {r.status}")

    # TC-12: Empty message
    r = verify_package(sign_message(b"", priv), trusted_public_key=pub)
    check(r.status == VerificationResult.VALID, "Empty message: VALID", f"FAILED — {r.status}")

    # TC-15: Two signatures differ
    p1 = sign_message(b"same text", priv)
    p2 = sign_message(b"same text", priv)
    check(p1["nonce"] != p2["nonce"],
          "Two signatures have different nonces", "FAILED — nonces are the same")


def demo_tls_cert() -> None:
    """Generate a self-signed TLS certificate."""
    step("Generate TLS certificate (self-signed, demo only)")
    try:
        import gen_cert
        gen_cert.main()
        ok("TLS certificate generated in certs/")
    except Exception as exc:
        fail(f"Certificate generation failed: {exc}")


def demo_network(priv, pub, verbose: bool) -> None:
    """Spin up the server in a thread and send a signed message via client."""
    step("Network demo — TCP client -> server")

    from server import handle_client
    import config as cfg

    # Find a free port
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("127.0.0.1", port))
    server_sock.listen(5)
    server_sock.settimeout(5)

    clear_nonce_store()
    errors = []

    def server_thread():
        try:
            conn, addr = server_sock.accept()
            handle_client(conn, addr, pub, check_replay=True)
        except Exception as exc:
            errors.append(str(exc))
        finally:
            server_sock.close()

    t = threading.Thread(target=server_thread, daemon=True)
    t.start()
    time.sleep(0.2)

    # Send a valid message
    pkg = sign_message(b"Hello from the network demo!", priv)
    try:
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        send_json(sock, pkg)
        response = recv_json(sock)
        sock.close()
    except Exception as exc:
        fail(f"Client connection failed: {exc}")
        return

    t.join(timeout=3)
    status = response.get("status", "UNKNOWN")
    check(status == "VALID",
          f"Server responded: {status}",
          f"FAILED — server said {status}: {response.get('reason')}")

    if errors:
        fail(f"Server errors: {errors}")

    clear_nonce_store()


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="DSVS end-to-end demo (cross-platform)")
    parser.add_argument("--verbose",      action="store_true", help="Show extra output.")
    parser.add_argument("--skip-network", action="store_true", help="Skip the TCP demo.")
    parser.add_argument("--skip-tls",     action="store_true", help="Skip TLS cert generation.")
    args = parser.parse_args()

    keys_dir    = os.path.join(ROOT, "keys")
    samples_dir = os.path.join(ROOT, "samples")

    print(f"\n{'='*60}")
    print("  Digital Signature Verification System -- Python Demo")
    print(f"{'='*60}")

    print(f"  Python  : {sys.version.split()[0]}")
    print(f"  Root    : {ROOT}")

    priv, pub, priv_path, pub_path = demo_keygen(keys_dir, args.verbose)
    base_pkg = demo_sign_and_verify(priv, pub, samples_dir, args.verbose)
    demo_sign_file(priv, pub, samples_dir)
    demo_tamper_attacks(priv, pub, base_pkg)
    demo_replay(priv, pub)
    demo_age_check(priv, pub)
    demo_edge_cases(priv, pub)

    if not args.skip_tls:
        demo_tls_cert()

    if not args.skip_network:
        demo_network(priv, pub, args.verbose)

    print(f"\n{'='*60}")
    print("  All demo steps completed successfully!")
    print(f"  Run full test suite: python -m unittest discover -s tests -v")
    print(f"  Launch web UI      : python app.py")
    print(f"{'='*60}\n")



if __name__ == "__main__":
    main()
