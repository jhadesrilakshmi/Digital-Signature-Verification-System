"""
keygen.py
---------
CLI tool: generate an RSA key pair and save to the keys/ directory.

Usage:
    python keygen.py --name alice
    python keygen.py --name alice --bits 4096 --password
"""

import argparse
import getpass
import os
import sys

# Allow running from the project root
sys.path.insert(0, os.path.dirname(__file__))

from crypto_core import generate_key_pair, serialize_private_key, serialize_public_key


def main():
    parser = argparse.ArgumentParser(
        description="Generate an RSA key pair for the Digital Signature Verification System."
    )
    parser.add_argument(
        "--name", required=True,
        help="Name used as the key filename prefix (e.g. 'alice' → keys/alice_private.pem).",
    )
    parser.add_argument(
        "--bits", type=int, default=2048,
        help="RSA key size in bits (default: 2048, minimum: 2048).",
    )
    parser.add_argument(
        "--password", action="store_true",
        help="Prompt for a password to protect the private key.",
    )
    parser.add_argument(
        "--keys-dir", default="keys",
        help="Directory where keys are stored (default: keys/).",
    )
    args = parser.parse_args()

    # ── Resolve directories ───────────────────────────────────────────
    base_dir = os.path.dirname(os.path.abspath(__file__))
    keys_dir = os.path.join(base_dir, args.keys_dir)
    os.makedirs(keys_dir, exist_ok=True)

    priv_path = os.path.join(keys_dir, f"{args.name}_private.pem")
    pub_path  = os.path.join(keys_dir, f"{args.name}_public.pem")

    # ── Optional password ─────────────────────────────────────────────
    password: bytes | None = None
    if args.password:
        pw1 = getpass.getpass("Enter key password: ")
        pw2 = getpass.getpass("Confirm key password: ")
        if pw1 != pw2:
            print("ERROR: Passwords do not match.", file=sys.stderr)
            sys.exit(1)
        if not pw1:
            print("ERROR: Password cannot be empty when --password is specified.", file=sys.stderr)
            sys.exit(1)
        password = pw1.encode()

    # ── Generate ──────────────────────────────────────────────────────
    print(f"Generating {args.bits}-bit RSA key pair for '{args.name}' …", flush=True)
    try:
        private_key, public_key = generate_key_pair(args.bits)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    # ── Serialize and write ───────────────────────────────────────────
    priv_pem = serialize_private_key(private_key, password)
    pub_pem  = serialize_public_key(public_key)

    with open(priv_path, "wb") as f:
        f.write(priv_pem)
    # Restrict private key permissions on POSIX systems
    try:
        os.chmod(priv_path, 0o600)
    except AttributeError:
        pass  # Windows – no chmod

    with open(pub_path, "wb") as f:
        f.write(pub_pem)

    print(f"  Private key → {priv_path}")
    print(f"  Public key  → {pub_path}")
    if password:
        print("  Private key is password-protected.")
    print("Done.")


if __name__ == "__main__":
    main()
