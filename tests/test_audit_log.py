"""
tests/test_audit_log.py
-----------------------
Tests for the audit logging module.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import config as cfg

# Redirect log to a temp file during tests
_orig_log_file = cfg.AUDIT_LOG_FILE
_orig_enabled  = cfg.AUDIT_LOG_ENABLED


class TestAuditLog(unittest.TestCase):

    def setUp(self):
        # Use a fresh temp file for every test
        self._tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False
        )
        self._tmp.close()
        cfg.AUDIT_LOG_FILE    = self._tmp.name
        cfg.AUDIT_LOG_ENABLED = True

        import audit_log  # re-import to pick up new config
        self._mod = audit_log

    def tearDown(self):
        cfg.AUDIT_LOG_FILE    = _orig_log_file
        cfg.AUDIT_LOG_ENABLED = _orig_enabled
        try:
            os.unlink(self._tmp.name)
        except OSError:
            pass

    def _read_entries(self):
        return self._mod.read_log(last_n=100)

    def test_log_verify_written(self):
        self._mod.log_verify(status="VALID", reason="", source="test", nonce="abc123")
        entries = self._read_entries()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["event"],  "VERIFY")
        self.assertEqual(entries[0]["status"], "VALID")
        self.assertEqual(entries[0]["source"], "test")

    def test_log_sign_written(self):
        self._mod.log_sign(source="cli", filename="foo.txt", sha256="dead", nonce="1234")
        entries = self._read_entries()
        self.assertEqual(entries[0]["event"],    "SIGN")
        self.assertEqual(entries[0]["filename"], "foo.txt")

    def test_log_keygen_written(self):
        self._mod.log_keygen(source="web", key_size=4096)
        entries = self._read_entries()
        self.assertEqual(entries[0]["event"],  "KEYGEN")
        self.assertIn("4096", entries[0]["reason"])

    def test_log_error_written(self):
        self._mod.log_error(source="server", reason="bad packet")
        entries = self._read_entries()
        self.assertEqual(entries[0]["event"],  "ERROR")
        self.assertIn("bad packet", entries[0]["reason"])

    def test_multiple_entries_appended(self):
        self._mod.log_verify(status="VALID",   source="test")
        self._mod.log_verify(status="INVALID", source="test")
        self._mod.log_verify(status="REJECTED",source="test")
        entries = self._read_entries()
        self.assertEqual(len(entries), 3)
        statuses = [e["status"] for e in entries]
        self.assertIn("VALID",    statuses)
        self.assertIn("INVALID",  statuses)
        self.assertIn("REJECTED", statuses)

    def test_disabled_produces_no_log(self):
        cfg.AUDIT_LOG_ENABLED = False
        self._mod.log_verify(status="VALID", source="test")
        entries = self._read_entries()
        self.assertEqual(len(entries), 0)
        cfg.AUDIT_LOG_ENABLED = True

    def test_read_log_last_n(self):
        for i in range(10):
            self._mod.log_verify(status="VALID", nonce=str(i))
        entries = self._mod.read_log(last_n=5)
        self.assertEqual(len(entries), 5)
        self.assertEqual(entries[-1]["nonce"], "9")

    def test_timestamp_utc_present(self):
        self._mod.log_sign(source="test")
        entries = self._read_entries()
        self.assertIn("timestamp_utc", entries[0])
        self.assertTrue(entries[0]["timestamp_utc"].endswith("+00:00")
                        or entries[0]["timestamp_utc"].endswith("Z")
                        or "T" in entries[0]["timestamp_utc"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
