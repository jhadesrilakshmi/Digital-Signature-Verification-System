"""
verify.py
---------
CLI tool: verify a JSON signature package.

Usage:
    python verify.py --package samples/message.txt.sig.json --pub keys/alice_public.pem
    python verify.py --package samples/message.txt.sig.json  # no trusted key (less secure)
    python verify.py --package samples/message.txt.sig.json --pub keys/alice_public.pem --check-age 300
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from crypto_core import load_public_key, verify_package


def main():
    parser = argparse.ArgumentParser(
        description="Verify a JSON signature package from the Digital Signature Verification System."
    )
    parser.add_argument("--package", required=True, help="Path to the .sig.json package file.")
    parser.add_argument("--pub", help="Path to the trusted sender public key PEM file.")
    parser.add_argument(
        "--check-age", type=int, metavar="SECONDS",
        help="Reject signatures older than SECONDS seconds.",
    )
    args = parser.parse_args()

    # ── Load package ──────────────────────────────────────────────────
    try:
        with open(args.package) as f:
            package = json.load(f)
    except FileNotFoundError:
        print(f"ERROR: Package file not found: {args.package}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as exc:
        print(f"ERROR: Invalid JSON in package: {exc}", file=sys.stderr)
        sys.exit(1)

    # ── Load trusted public key (optional) ────────────────────────────
    trusted_pub = None
    if args.pub:
        try:
            with open(args.pub, "rb") as f:
                trusted_pub = load_public_key(f.read())
        except FileNotFoundError:
            print(f"ERROR: Public key file not found: {args.pub}", file=sys.stderr)
            sys.exit(1)
        except Exception as exc:
            print(f"ERROR loading public key: {exc}", file=sys.stderr)
            sys.exit(1)

    # ── Verify ────────────────────────────────────────────────────────
    result = verify_package(
        package,
        trusted_public_key=trusted_pub,
        max_age=args.check_age,
    )

    # ── Print result ──────────────────────────────────────────────────
    print("─" * 50)
    print(f"Package   : {args.package}")
    if package.get("filename"):
        print(f"File      : {package['filename']}")
    print(f"Algorithm : {package.get('algorithm', 'unknown')}")
    print(f"Timestamp : {package.get('timestamp', '?')}")
    print(f"SHA-256   : {package.get('message_sha256', '?')}")
    print("─" * 50)
    print(f"Result    : {result}")
    print("─" * 50)

    sys.exit(0 if result.ok else 1)


if __name__ == "__main__":
    main()
