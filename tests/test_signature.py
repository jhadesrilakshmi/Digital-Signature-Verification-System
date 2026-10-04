"""
tests/test_signature.py
-----------------------
Unit tests for the core cryptographic operations.
All 15 cryptographic test cases from the project specification.
"""

import base64
import json
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from crypto_core import (
    clear_nonce_store,
    generate_key_pair,
    load_private_key,
    load_public_key,
    serialize_private_key,
    serialize_public_key,
    sha256_hex,
    sign_message,
    verify_package,
    VerificationResult,
)


class TestKeyGeneration(unittest.TestCase):
    """Key generation tests."""

    def test_generate_2048(self):
        """TC-13a: generate 2048-bit key pair."""
        priv, pub = generate_key_pair(2048)
        self.assertEqual(priv.key_size, 2048)

    def test_generate_4096(self):
        """TC-13b: generate 4096-bit key pair."""
        priv, pub = generate_key_pair(4096)
        self.assertEqual(priv.key_size, 4096)

    def test_key_too_small_rejected(self):
        """TC-14: key smaller than 2048 bits must be rejected."""
        with self.assertRaises(ValueError):
            generate_key_pair(1024)

    def test_load_key_too_small_rejected(self):
        """TC-14b: loading a key smaller than 2048 bits must raise ValueError."""
        # Build a 1024-bit key via the low-level API
        from cryptography.hazmat.primitives.asymmetric import rsa
        small_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        from cryptography.hazmat.primitives import serialization
        pem = small_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with self.assertRaises(ValueError):
            load_private_key(pem)

    def test_password_protected_key(self):
        """TC-13c: private key with password round-trips correctly."""
        priv, _ = generate_key_pair(2048)
        pem = serialize_private_key(priv, password=b"s3cr3t!")
        loaded = load_private_key(pem, password=b"s3cr3t!")
        self.assertEqual(priv.key_size, loaded.key_size)

    def test_wrong_password_fails(self):
        """TC-13d: wrong password raises an exception."""
        priv, _ = generate_key_pair(2048)
        pem = serialize_private_key(priv, password=b"correct")
        with self.assertRaises(Exception):
            load_private_key(pem, password=b"wrong")


class TestSignAndVerify(unittest.TestCase):
    """Core sign / verify tests."""

    @classmethod
    def setUpClass(cls):
        cls.priv, cls.pub = generate_key_pair(2048)
        cls.priv2, cls.pub2 = generate_key_pair(2048)
        cls.message = b"Pay Bob 100 dollars."

    def setUp(self):
        clear_nonce_store()

    def _signed(self, msg=None):
        return sign_message(msg if msg is not None else self.message, self.priv)

    # ── TC-1: Valid package ───────────────────────────────────────────
    def test_tc1_valid(self):
        """TC-1: Original message with correct signature → VALID."""
        pkg = self._signed()
        r = verify_package(pkg, trusted_public_key=self.pub)
        self.assertEqual(r.status, VerificationResult.VALID)

    # ── TC-2: Message modified after signing ──────────────────────────
    def test_tc2_tampered_message(self):
        """TC-2: Message modified after signing → INVALID."""
        pkg = self._signed()
        pkg["message_b64"] = base64.b64encode(b"Pay Bob 999 dollars.").decode()
        r = verify_package(pkg, trusted_public_key=self.pub)
        self.assertEqual(r.status, VerificationResult.INVALID)

    # ── TC-3: Message AND hash both modified ──────────────────────────
    def test_tc3_tampered_message_and_hash(self):
        """TC-3: Attacker changes message AND its hash → INVALID (signature mismatch)."""
        pkg = self._signed()
        tampered = b"Pay Bob 999 dollars."
        pkg["message_b64"]   = base64.b64encode(tampered).decode()
        pkg["message_sha256"] = sha256_hex(tampered)
        r = verify_package(pkg, trusted_public_key=self.pub)
        self.assertEqual(r.status, VerificationResult.INVALID)

    # ── TC-4: Signature bytes modified ───────────────────────────────
    def test_tc4_corrupted_signature(self):
        """TC-4: Signature bytes modified → INVALID."""
        pkg = self._signed()
        sig_bytes = bytearray(base64.b64decode(pkg["signature_b64"]))
        sig_bytes[10] ^= 0xFF
        pkg["signature_b64"] = base64.b64encode(bytes(sig_bytes)).decode()
        r = verify_package(pkg, trusted_public_key=self.pub)
        self.assertEqual(r.status, VerificationResult.INVALID)

    # ── TC-5: Timestamp modified ──────────────────────────────────────
    def test_tc5_tampered_timestamp(self):
        """TC-5: Timestamp modified → INVALID (signed content changes)."""
        pkg = self._signed()
        pkg["timestamp"] = pkg["timestamp"] - 1000
        r = verify_package(pkg, trusted_public_key=self.pub)
        self.assertEqual(r.status, VerificationResult.INVALID)

    # ── TC-6: Wrong public key ────────────────────────────────────────
    def test_tc6_wrong_public_key(self):
        """TC-6: Verified with the wrong public key → INVALID."""
        pkg = self._signed()
        r = verify_package(pkg, trusted_public_key=self.pub2)
        self.assertEqual(r.status, VerificationResult.INVALID)

    # ── TC-7: Attacker signs with own key ────────────────────────────
    def test_tc7_attacker_key(self):
        """TC-7: Attacker signs with own key; receiver trusts real sender → INVALID."""
        pkg = sign_message(self.message, self.priv2)  # signed with priv2
        r = verify_package(pkg, trusted_public_key=self.pub)  # trusted is pub1
        self.assertEqual(r.status, VerificationResult.INVALID)

    # ── TC-8: Replay attack ───────────────────────────────────────────
    def test_tc8_replay(self):
        """TC-8: Same package sent twice → REJECTED on second attempt."""
        pkg = self._signed()
        r1 = verify_package(pkg, trusted_public_key=self.pub, check_replay=True)
        self.assertEqual(r1.status, VerificationResult.VALID)
        r2 = verify_package(pkg, trusted_public_key=self.pub, check_replay=True)
        self.assertEqual(r2.status, VerificationResult.REJECTED)

    # ── TC-9: Signature too old ───────────────────────────────────────
    def test_tc9_too_old(self):
        """TC-9: Signature older than allowed age → REJECTED."""
        pkg = self._signed()
        pkg["timestamp"] = int(time.time()) - 3600  # 1 hour old
        r = verify_package(pkg, trusted_public_key=self.pub, max_age=60)
        self.assertEqual(r.status, VerificationResult.REJECTED)

    # ── TC-10: Malformed package ──────────────────────────────────────
    def test_tc10_malformed(self):
        """TC-10: Malformed package → INVALID."""
        r = verify_package({"bad": "data"}, trusted_public_key=self.pub)
        self.assertEqual(r.status, VerificationResult.INVALID)

    # ── TC-11: 5 MB binary file ───────────────────────────────────────
    def test_tc11_large_file(self):
        """TC-11: 5 MB binary message → VALID."""
        import os as _os
        big_message = _os.urandom(5 * 1024 * 1024)
        pkg = sign_message(big_message, self.priv)
        r = verify_package(pkg, trusted_public_key=self.pub)
        self.assertEqual(r.status, VerificationResult.VALID)

    # ── TC-12: Empty message ──────────────────────────────────────────
    def test_tc12_empty_message(self):
        """TC-12: Empty message → VALID."""
        pkg = sign_message(b"", self.priv)
        r = verify_package(pkg, trusted_public_key=self.pub)
        self.assertEqual(r.status, VerificationResult.VALID)

    # ── TC-15: Two signatures of the same message ─────────────────────
    def test_tc15_different_signatures(self):
        """TC-15: Two signatures of same message → different nonces and signatures."""
        pkg1 = self._signed()
        pkg2 = self._signed()
        self.assertNotEqual(pkg1["nonce"], pkg2["nonce"])
        self.assertNotEqual(pkg1["signature_b64"], pkg2["signature_b64"])
        # Both must still verify
        r1 = verify_package(pkg1, trusted_public_key=self.pub)
        r2 = verify_package(pkg2, trusted_public_key=self.pub)
        self.assertEqual(r1.status, VerificationResult.VALID)
        self.assertEqual(r2.status, VerificationResult.VALID)


class TestHashIntegrity(unittest.TestCase):
    """SHA-256 hashing tests."""

    def test_sha256_deterministic(self):
        self.assertEqual(sha256_hex(b"hello"), sha256_hex(b"hello"))

    def test_sha256_different_input(self):
        self.assertNotEqual(sha256_hex(b"hello"), sha256_hex(b"world"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
