"""Interoperability vectors for binary v7 and the joint FIDO emergency slot."""

from __future__ import annotations

import base64
import importlib.util
import sys
import unittest
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("tagcrypt_v7_recovery", ROOT / "tools" / "tagcrypt_v7_decrypt.py")
recovery = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = recovery
SPEC.loader.exec_module(recovery)

PASSPHRASE = "VECTOR_ONLY_passphrase_2026"
EXPECTED_JSON = b'{"secret":"VECTOR_ONLY"}'

# Deterministic Argon2id/ChaCha20-Poly1305 records. The second direct vector
# uses a 71-byte padded plaintext to cover capacity-dependent NFC padding.
DIRECT_BUCKET_VECTOR = (
    "p51C8QABAgMEBQYHCAkKCwwNDg8AAQIDBAUGBwgJCgt+Z8qAzi8ITvpYbCFlQPfVZ6WLOWQ2N+9fLuzF4jqhXVoYPIiJOypkntkT3WJrJSfc"
)
DIRECT_CAPACITY_VECTOR = (
    "p51C8QABAgMEBQYHCAkKCwwNDg8AAQIDBAUGBwgJCgt+Z8qAzi8ITvpYbCFlQPfVZ6WLOWQ2N+9fLuzF4jqhXVrJQTxLZDzTeV8YIJmdXP48a9ffC9jotKK0E516W8AkB7m4fI1+yYi1bBFCbY9eI9Iqk3sMEeA="
)
JOINT_FIDO_EMERGENCY_VECTOR = (
    "WtN+kRAREhMUFRYXGBkaGxwdHh8AAAA9DA0ODxAREhMUFRYXCBAPll8EHi2d+pMIyjiDe8kaCMK6KyXwvJOHijbfqUjMZZF53xb+nIUkiEbgp+7AAwIBABkCAAAAAgQAAAAgISIjJCUmJygpKissLS4vADwYGRobHB0eHyAhIiPo7zmYq8dyPfaM9IrUjuRuxTjcglqhPLziUA8PbqPIfDbu3dUu/Pf4dceHmEb0sboDADIBS0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ubwA8JCUmJygpKissLS4vpDVrXaHSX+87bnh/GrWxqoy3OWeqqHLhyxBnJZGXklzxQbIXURdFPVB51ANpea7t"
)


class TagcryptV7RecoveryTests(unittest.TestCase):
    def test_raw_page_memory_file_is_loaded_as_binary_record(self):
        with tempfile.TemporaryDirectory() as directory:
            raw_file = Path(directory) / "ntag216-memory.bin"
            raw_file.write_bytes(bytes.fromhex("a79d42f1") + bytes(range(32)))
            self.assertEqual(recovery.read_record(raw_file=raw_file), raw_file.read_bytes())

    def test_passphrase_only_bucket_vector(self) -> None:
        record = base64.b64decode(DIRECT_BUCKET_VECTOR, validate=True)
        self.assertEqual(len(record), 81)
        self.assertEqual(recovery.decrypt(record, PASSPHRASE), EXPECTED_JSON)

    def test_passphrase_only_capacity_padding_vector(self) -> None:
        record = base64.b64decode(DIRECT_CAPACITY_VECTOR, validate=True)
        self.assertEqual(len(record), 119)
        self.assertEqual(recovery.decrypt(record, PASSPHRASE), EXPECTED_JSON)

    def test_joint_fido_emergency_passphrase_vector(self) -> None:
        record = base64.b64decode(JOINT_FIDO_EMERGENCY_VECTOR, validate=True)
        self.assertEqual(len(record), 291)
        self.assertEqual(recovery.decrypt(record, PASSPHRASE), EXPECTED_JSON)

    def test_wrong_passphrase_and_tampered_payload_fail(self) -> None:
        record = base64.b64decode(DIRECT_CAPACITY_VECTOR, validate=True)
        with self.assertRaises(Exception):
            recovery.decrypt(record, "wrong phrase")
        damaged = bytearray(record)
        damaged[-1] ^= 1
        with self.assertRaises(Exception):
            recovery.decrypt(bytes(damaged), PASSPHRASE)


if __name__ == "__main__":
    unittest.main()
