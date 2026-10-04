"""
tests/test_web_and_network.py
-----------------------------
Integration tests for the Flask web API and the TCP network protocol.
"""

import base64
import json
import os
import socket
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Flask test client
import app as flask_app_module
from app import app

from crypto_core import (
    clear_nonce_store,
    generate_key_pair,
    serialize_private_key,
    serialize_public_key,
    sign_message,
    verify_package,
    VerificationResult,
)
from netproto import recv_json, send_json


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def _gen_pem_pair():
    priv, pub = generate_key_pair(2048)
    return (
        serialize_private_key(priv).decode("ascii"),
        serialize_public_key(pub).decode("ascii"),
        priv, pub,
    )


# ──────────────────────────────────────────────
# Flask API Tests
# ──────────────────────────────────────────────

class TestFlaskAPI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = app.test_client()
        cls.priv_pem, cls.pub_pem, cls.priv, cls.pub = _gen_pem_pair()

    def setUp(self):
        clear_nonce_store()

    # ── /api/keygen ───────────────────────────────────────────────────
    def test_keygen_2048(self):
        r = self.client.post("/api/keygen", json={"bits": 2048})
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertIn("private_key_pem", data)
        self.assertIn("public_key_pem", data)
        self.assertIn("BEGIN", data["private_key_pem"])

    def test_keygen_invalid_size(self):
        r = self.client.post("/api/keygen", json={"bits": 512})
        self.assertEqual(r.status_code, 400)
        self.assertIn("error", r.get_json())

    # ── /api/sign ─────────────────────────────────────────────────────
    def test_sign_text_message(self):
        r = self.client.post("/api/sign", json={
            "private_key_pem": self.priv_pem,
            "message": "Hello, World!",
        })
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        pkg = data["package"]
        self.assertEqual(pkg["algorithm"], "RSA-PSS-SHA256")
        self.assertIn("signature_b64", pkg)

    def test_sign_does_not_auto_verify(self):
        """Signing must return only the package — no 'status' or verification result."""
        r = self.client.post("/api/sign", json={
            "private_key_pem": self.priv_pem,
            "message": "Test no auto-verify",
        })
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        # Must have 'package' key
        self.assertIn("package", data)
        # Must NOT contain a verification status in the top-level response
        self.assertNotIn("status", data)
        self.assertNotIn("valid", data)
        self.assertNotIn("verified", data)

    def test_sign_returns_key_bits(self):
        """Sign response includes key_bits so the UI can display key size."""
        r = self.client.post("/api/sign", json={
            "private_key_pem": self.priv_pem,
            "message": "key bits test",
        })
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertIn("key_bits", data)
        self.assertEqual(data["key_bits"], 2048)

    def test_sign_missing_key(self):
        r = self.client.post("/api/sign", json={"message": "test"})
        self.assertEqual(r.status_code, 400)

    def test_sign_missing_message(self):
        r = self.client.post("/api/sign", json={"private_key_pem": self.priv_pem})
        self.assertEqual(r.status_code, 400)

    def test_sign_bad_key(self):
        r = self.client.post("/api/sign", json={
            "private_key_pem": "NOT A REAL KEY",
            "message": "test",
        })
        self.assertEqual(r.status_code, 400)

    # ── /api/verify ───────────────────────────────────────────────────
    def test_verify_valid(self):
        pkg = sign_message(b"test message", self.priv)
        r = self.client.post("/api/verify", json={
            "package": pkg,
            "trusted_public_key_pem": self.pub_pem,
        })
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["status"], "VALID")

    def test_verify_returns_checks(self):
        """Verify response must include per-check breakdown for UI display."""
        pkg = sign_message(b"test message", self.priv)
        r = self.client.post("/api/verify", json={
            "package": pkg,
            "trusted_public_key_pem": self.pub_pem,
        })
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertIn("checks", data)
        checks = data["checks"]
        self.assertIn("structure", checks)
        self.assertIn("hash", checks)
        self.assertIn("signature", checks)

    def test_verify_tampered(self):
        pkg = sign_message(b"original", self.priv)
        pkg["message_b64"] = base64.b64encode(b"tampered").decode()
        r = self.client.post("/api/verify", json={"package": pkg})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["status"], "INVALID")

    def test_verify_old_signature(self):
        pkg = sign_message(b"test", self.priv)
        pkg["timestamp"] = int(time.time()) - 3600
        r = self.client.post("/api/verify", json={
            "package": pkg,
            "trusted_public_key_pem": self.pub_pem,
            "check_age": 60,
        })
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["status"], "REJECTED")

    def test_verify_wrong_trusted_key(self):
        _, pub2_pem, _, _ = _gen_pem_pair()
        pkg = sign_message(b"test", self.priv)
        r = self.client.post("/api/verify", json={
            "package": pkg,
            "trusted_public_key_pem": pub2_pem,
        })
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["status"], "INVALID")

    def test_verify_replay_rejected(self):
        """Same package submitted twice with check_replay=true: 2nd must be REJECTED."""
        pkg = sign_message(b"replay test", self.priv)
        r1 = self.client.post("/api/verify", json={
            "package": pkg,
            "trusted_public_key_pem": self.pub_pem,
            "check_replay": True,
        })
        self.assertEqual(r1.get_json()["status"], "VALID")
        r2 = self.client.post("/api/verify", json={
            "package": pkg,
            "trusted_public_key_pem": self.pub_pem,
            "check_replay": True,
        })
        self.assertEqual(r2.get_json()["status"], "REJECTED")

    def test_verify_malformed_package(self):
        r = self.client.post("/api/verify", json={"package": {"junk": True}})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["status"], "INVALID")

    def test_verify_no_body(self):
        r = self.client.post("/api/verify", data="not json",
                             content_type="application/json")
        self.assertEqual(r.status_code, 400)

    # ── /api/stats ────────────────────────────────────────────────────
    def test_stats_endpoint_exists(self):
        """GET /api/stats must return a valid stats dict."""
        r = self.client.get("/api/stats")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertIn("signatures_created", data)
        self.assertIn("verifications", data)
        self.assertIn("valid", data["verifications"])
        self.assertIn("invalid", data["verifications"])
        self.assertIn("rejected", data["verifications"])

    # ── /api/transfer ─────────────────────────────────────────────────
    def test_transfer_saves_package(self):
        """POST /api/transfer must save package to inbox and return success."""
        pkg = sign_message(b"transfer test", self.priv)
        r = self.client.post("/api/transfer", json={"package": pkg})
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data.get("success"))
        self.assertIn("filename", data)

    def test_transfer_missing_package(self):
        r = self.client.post("/api/transfer", json={})
        self.assertEqual(r.status_code, 400)

    # ── /api/inbox ────────────────────────────────────────────────────
    def test_inbox_endpoint_exists(self):
        """GET /api/inbox must return an inbox list."""
        r = self.client.get("/api/inbox")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertIn("inbox", data)
        self.assertIsInstance(data["inbox"], list)

    def test_inbox_contains_transferred_package(self):
        """After transfer, the package appears in the inbox."""
        pkg = sign_message(b"inbox test", self.priv)
        self.client.post("/api/transfer", json={"package": pkg})
        r = self.client.get("/api/inbox")
        self.assertEqual(r.status_code, 200)
        inbox = r.get_json()["inbox"]
        # At least one entry should exist
        self.assertGreater(len(inbox), 0)

    # ── /api/fingerprint ──────────────────────────────────────────────
    def test_fingerprint_valid_key(self):
        """POST /api/fingerprint returns colon-separated SHA-256 fingerprint."""
        r = self.client.post("/api/fingerprint", json={"public_key_pem": self.pub_pem})
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertIn("fingerprint", data)
        self.assertEqual(data.get("algorithm"), "SHA-256")
        # SHA-256 has 32 bytes -> 32 pairs separated by 31 colons = 95 chars
        self.assertEqual(len(data["fingerprint"]), 95)
        self.assertIn(":", data["fingerprint"])

    def test_fingerprint_missing_key(self):
        r = self.client.post("/api/fingerprint", json={})
        self.assertEqual(r.status_code, 400)

    # ── /api/log_attack ───────────────────────────────────────────────
    def test_log_attack_records_event(self):
        """POST /api/log_attack adds an attack event to the audit log."""
        r = self.client.post("/api/log_attack", json={
            "attack_name": "Message Tampering",
            "status": "DETECTED",
            "reason": "SHA-256 digest mismatch",
            "nonce": "testnonce123",
            "sha256": "testhash456",
        })
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data.get("logged"))
        self.assertEqual(data.get("status"), "DETECTED")

        # Verify stats reflect attack
        stats_r = self.client.get("/api/stats")
        self.assertEqual(stats_r.status_code, 200)
        stats = stats_r.get_json()
        self.assertIn("attack_tests_run", stats)
        self.assertGreaterEqual(stats["attack_tests_run"], 1)


# ──────────────────────────────────────────────
# Network (netproto) Tests
# ──────────────────────────────────────────────

class TestNetProto(unittest.TestCase):
    """Test the length-prefixed JSON protocol with a loopback socket pair."""

    def _loopback_pair(self):
        """Create a connected pair of sockets."""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind(("127.0.0.1", 0))
        server_sock.listen(1)
        port = server_sock.getsockname()[1]

        client_sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        conn, _ = server_sock.accept()
        server_sock.close()
        return client_sock, conn

    def test_send_recv_simple(self):
        c, s = self._loopback_pair()
        send_json(c, {"hello": "world", "num": 42})
        data = recv_json(s)
        self.assertEqual(data["hello"], "world")
        self.assertEqual(data["num"], 42)
        c.close(); s.close()

    def test_send_recv_large_payload(self):
        c, s = self._loopback_pair()
        payload = {"data": "x" * 100_000}
        send_json(c, payload)
        received = recv_json(s)
        self.assertEqual(len(received["data"]), 100_000)
        c.close(); s.close()

    def test_signature_package_round_trip(self):
        c, s = self._loopback_pair()
        priv, pub = generate_key_pair(2048)
        pkg = sign_message(b"network test message", priv)
        send_json(c, pkg)
        received_pkg = recv_json(s)
        result = verify_package(received_pkg, trusted_public_key=pub)
        self.assertEqual(result.status, VerificationResult.VALID)
        c.close(); s.close()

    def test_recv_on_closed_raises(self):
        c, s = self._loopback_pair()
        c.close()
        with self.assertRaises(ConnectionError):
            recv_json(s)
        s.close()


# ──────────────────────────────────────────────
# Index Route
# ──────────────────────────────────────────────

class TestIndexRoute(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = app.test_client()

    def test_index_returns_html(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Digital Signature", r.data)


if __name__ == "__main__":
    unittest.main(verbosity=2)
