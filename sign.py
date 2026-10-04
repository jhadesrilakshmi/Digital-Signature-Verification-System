"""
sign.py
-------
CLI tool: sign a file or a text message and write a JSON signature package.

Usage:
    python sign.py --key keys/alice_private.pem --file samples/message.txt
    python sign.py --key keys/alice_private.pem --text "Pay Bob 100"
    python sign.py --key keys/alice_private.pem --file samples/message.txt --password
"""

import argparse
import getpass
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from crypto_core import load_private_key, sign_message


def main():
    parser = argparse.ArgumentParser(
        description="Sign a message or file using the Digital Signature Verification System."
    )

    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--file", help="Path to a file to sign.")
    source.add_argument("--text", help="Inline text message to sign.")

    parser.add_argument(
        "--key", required=True,
        help="Path to the PEM private key file.",
    )
    parser.add_argument(
        "--password", action="store_true",
        help="Prompt for the private key password.",
    )
    parser.add_argument(
        "--out",
        help="Output path for the signature package. "
             "Default: <input_file>.sig.json or <cwd>/signed_message.sig.json.",
    )
    args = parser.parse_args()

    # ── Load private key ──────────────────────────────────────────────
    password: bytes | None = None
    if args.password:
        pw = getpass.getpass("Private key password: ")
        password = pw.encode()

    try:
        with open(args.key, "rb") as f:
            priv_pem = f.read()
        private_key = load_private_key(priv_pem, password)
    except FileNotFoundError:
        print(f"ERROR: Key file not found: {args.key}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"ERROR loading key: {exc}", file=sys.stderr)
        sys.exit(1)

    # ── Read message ──────────────────────────────────────────────────
    if args.file:
        try:
            with open(args.file, "rb") as f:
                message = f.read()
        except FileNotFoundError:
            print(f"ERROR: File not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        filename = os.path.basename(args.file)
        default_out = args.file + ".sig.json"
    else:
        message = args.text.encode("utf-8")
        filename = ""
        default_out = os.path.join(os.getcwd(), "signed_message.sig.json")

    # ── Sign ──────────────────────────────────────────────────────────
    print("Signing … ", end="", flush=True)
    package = sign_message(message, private_key, filename=filename)
    print("OK")

    # ── Write package ─────────────────────────────────────────────────
    out_path = args.out or default_out
    with open(out_path, "w") as f:
        json.dump(package, f, indent=2)

    print(f"Signature package written to: {out_path}")
    print(f"  SHA-256 : {package['message_sha256']}")
    print(f"  Nonce   : {package['nonce']}")
    print(f"  Time    : {package['timestamp']}")


if __name__ == "__main__":
    main()
