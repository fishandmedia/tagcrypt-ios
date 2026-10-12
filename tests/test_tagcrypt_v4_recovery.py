"""Interoperability checks for the documented v4 passphrase recovery slot."""

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("tagcrypt_recovery", ROOT / "tools" / "tagcrypt_v2_decrypt.py")
recovery = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = recovery
SPEC.loader.exec_module(recovery)


def _make_slot(slot_type: int, metadata: bytes, wrapped: bytes) -> bytes:
    return bytes([slot_type]) + len(metadata).to_bytes(2, "big") + metadata + len(wrapped).to_bytes(2, "big") + wrapped


def make_v4_fixture(passphrase: str) -> bytes:
    magic = b"TVLT\x04"
    vault = {
        "secret": "",
        "slots": [
            {"id": "00000000-0000-4000-8000-000000000001", "secret": "SAMPLE_ONLY_alpha", "title": "Email · sample"},
            {"id": "00000000-0000-4000-8000-000000000002", "secret": "SAMPLE_ONLY_beta", "title": "Wi-Fi · sample"},
        ],
    }
    plaintext = json.dumps(vault, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    dek = bytes(range(32))
    payload_nonce = bytes(range(12))
    payload = payload_nonce + ChaCha20Poly1305(dek).encrypt(payload_nonce, plaintext, magic)
    salt = bytes(range(16, 32))
    metadata = b"\x01" + (600_000).to_bytes(4, "big") + salt
    passphrase_key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000).derive(passphrase.strip().encode())
    pass_aad = magic + payload + b"\x01" + metadata
    pass_nonce = bytes(range(32, 44))
    wrapped_dek = pass_nonce + ChaCha20Poly1305(passphrase_key).encrypt(pass_nonce, dek, pass_aad)

    credential_id = bytes(range(64))
    prf_input = bytes(range(64, 96))
    hkdf_salt = bytes(range(96, 112))
    fido_metadata = bytes([len(credential_id)]) + credential_id + prf_input + hkdf_salt
    fido_prf = bytes(range(128, 160))
    fido_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=hkdf_salt, info=b"Tagcrypt v4 FIDO key-wrap").derive(fido_prf)
    fido_aad = magic + payload + b"\x02" + fido_metadata
    fido_nonce = bytes(range(112, 124))
    fido_wrapped = fido_nonce + ChaCha20Poly1305(fido_key).encrypt(fido_nonce, dek, fido_aad)

    return magic + len(payload).to_bytes(4, "big") + payload + b"\x02" + _make_slot(1, metadata, wrapped_dek) + _make_slot(2, fido_metadata, fido_wrapped)


def make_v5_fixture(passphrase: str) -> bytes:
    """Build a two-key v5 record using one shared record PRF input."""
    magic = b"TVLT\x05"
    vault = {"secret": "", "slots": [
        {"id": "00000000-0000-4000-8000-000000000001", "secret": "SAMPLE_ONLY_v5", "title": "Sample"}
    ]}
    plaintext = json.dumps(vault, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    dek = bytes(range(32))
    payload_nonce = bytes(range(12))
    payload = payload_nonce + ChaCha20Poly1305(dek).encrypt(payload_nonce, plaintext, magic)
    salt = bytes(range(16, 32))
    pass_metadata = b"\x01" + (600_000).to_bytes(4, "big") + salt
    pass_key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000).derive(passphrase.strip().encode())
    pass_nonce = bytes(range(32, 44))
    pass_aad = magic + payload + b"\x01" + pass_metadata
    pass_wrapped = pass_nonce + ChaCha20Poly1305(pass_key).encrypt(pass_nonce, dek, pass_aad)
    prf_input = bytes(range(64, 96))
    slots = [_make_slot(1, pass_metadata, pass_wrapped)]
    for index in range(2):
        credential_id = bytes(range(1 + index, 65 + index))
        hkdf_salt = bytes(range(96 + index * 16, 112 + index * 16))
        metadata = bytes([len(credential_id)]) + credential_id + prf_input + hkdf_salt
        prf_output = bytes((value + index) % 256 for value in range(128, 160))
        wrapping_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=hkdf_salt,
                            info=b"Tagcrypt v5 FIDO key-wrap").derive(prf_output)
        nonce = bytes((value + index) % 256 for value in range(112, 124))
        aad = magic + payload + b"\x02" + metadata
        wrapped = nonce + ChaCha20Poly1305(wrapping_key).encrypt(nonce, dek, aad)
        slots.append(_make_slot(2, metadata, wrapped))
    return magic + len(payload).to_bytes(4, "big") + payload + bytes([len(slots)]) + b"".join(slots)


class TagcryptV4RecoveryTests(unittest.TestCase):
    def test_v4_passphrase_recovery_reads_multi_slot_vault(self) -> None:
        envelope = make_v4_fixture("DEMO_ONLY_RECOVERY_PHRASE_0001")
        self.assertEqual(
            recovery.decrypt_envelope(envelope, "DEMO_ONLY_RECOVERY_PHRASE_0001"),
            "[1] Email · sample\nSAMPLE_ONLY_alpha\n\n[2] Wi-Fi · sample\nSAMPLE_ONLY_beta",
        )

    def test_v4_wrong_passphrase_fails_without_plaintext(self) -> None:
        with self.assertRaises(recovery.RecoveryError):
            recovery.decrypt_envelope(make_v4_fixture("DEMO_ONLY_RECOVERY_PHRASE_0001"), "wrong phrase")

    def test_v4_tampered_wrapped_key_fails_authentication(self) -> None:
        envelope = bytearray(make_v4_fixture("DEMO_ONLY_RECOVERY_PHRASE_0001"))
        envelope[-1] ^= 1
        # Tampering the last (FIDO) slot still parses; the passphrase slot should recover
        # the unchanged payload, since FIDO and passphrase wrapping slots are independent.
        self.assertIn("SAMPLE_ONLY_alpha", recovery.decrypt_envelope(bytes(envelope), "DEMO_ONLY_RECOVERY_PHRASE_0001"))

    def test_qr_prefix_is_accepted(self) -> None:
        import base64

        envelope = make_v4_fixture("DEMO_ONLY_RECOVERY_PHRASE_0001")
        self.assertEqual(
            recovery.decode_text_record_value(b"TAGCRYPT1:" + base64.b64encode(envelope)),
            envelope,
        )

    def test_v5_passphrase_slot_recovers_record_with_two_fido_slots(self) -> None:
        self.assertEqual(
            recovery.decrypt_envelope(make_v5_fixture("DEMO_ONLY_RECOVERY_PHRASE_0001"), "DEMO_ONLY_RECOVERY_PHRASE_0001"),
            "[1] Sample\nSAMPLE_ONLY_v5",
        )


if __name__ == "__main__":
    unittest.main()
