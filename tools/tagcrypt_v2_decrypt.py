#!/usr/bin/env python3
"""Offline passphrase recovery helper for Tagcrypt v2 through v6 records."""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import sys
import unicodedata
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

MAGIC_V2 = b"TVLT\x02"
MAGIC_V3 = b"TVLT\x03"
MAGIC_V4 = b"TVLT\x04"
MAGIC_V5 = b"TVLT\x05"
MAGIC_V6 = b"TVLT\x06"
KDF_ID_PBKDF2_SHA256 = 1
ITERATIONS = 600_000
SALT_BYTES = 16
HEADER_BYTES = 5 + 1 + 4 + SALT_BYTES
NONCE_BYTES = 12
TAG_BYTES = 16
MAX_RECORD_BYTES = 4096


class RecoveryError(Exception):
    """Input is malformed, unsupported, or cannot be authenticated."""


def decode_text_record_value(encoded: bytes) -> bytes:
    """Decode Base64 copied from the NDEF Text value, allowing line wrapping."""
    try:
        compact = b"".join(encoded.split())
        if compact.startswith(b"TAGCRYPT1:"):
            compact = compact[len(b"TAGCRYPT1:"):]
        envelope = base64.b64decode(compact, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise RecoveryError("Input is not valid Base64 Tagcrypt text.") from exc
    if len(envelope) > MAX_RECORD_BYTES:
        raise RecoveryError("Record is larger than this helper accepts.")
    return envelope


def decrypt_envelope(envelope: bytes, passphrase: str) -> str:
    if envelope.startswith((MAGIC_V4, MAGIC_V5, MAGIC_V6)):
        return decrypt_envelope_passphrase_slot(envelope, passphrase)
    if len(envelope) < HEADER_BYTES + NONCE_BYTES + TAG_BYTES + 1:
        raise RecoveryError("Record is too short to be a valid Tagcrypt v2/v3 record.")
    if envelope[: len(MAGIC_V2)] not in (MAGIC_V2, MAGIC_V3):
        raise RecoveryError("This is not a supported Tagcrypt v2/v3 record.")
    if envelope[5] != KDF_ID_PBKDF2_SHA256:
        raise RecoveryError("This record uses an unsupported key-derivation method.")

    rounds = int.from_bytes(envelope[6:10], "big", signed=False)
    if rounds != ITERATIONS:
        raise RecoveryError("This record uses unsupported KDF parameters.")

    header = envelope[:HEADER_BYTES]
    salt = envelope[10:HEADER_BYTES]
    combined = envelope[HEADER_BYTES:]
    if len(combined) < NONCE_BYTES + TAG_BYTES + 1:
        raise RecoveryError("Record is missing encrypted data.")

    nonce = combined[:NONCE_BYTES]
    ciphertext_and_tag = combined[NONCE_BYTES:]
    canonical = unicodedata.normalize("NFC", passphrase.strip())
    candidates = [canonical]
    if canonical != passphrase:
        candidates.append(passphrase)
    plaintext = None
    for candidate in candidates:
        key = hashlib.pbkdf2_hmac(
            "sha256", candidate.encode("utf-8"), salt, ITERATIONS, dklen=32
        )
        try:
            plaintext = ChaCha20Poly1305(key).decrypt(nonce, ciphertext_and_tag, header)
            break
        except (InvalidTag, ValueError):
            continue
    if plaintext is None:
        raise RecoveryError("Passphrase is incorrect or the record is damaged.")

    try:
        vault = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RecoveryError("Decrypted data is not valid Tagcrypt JSON.") from exc
    return format_vault(vault)


def decrypt_envelope_passphrase_slot(envelope: bytes, passphrase: str) -> str:
    """Open the passphrase recovery slot in a TVLT v4/v5/v6 envelope."""
    magic = envelope[:5]
    version = {MAGIC_V4: 4, MAGIC_V5: 5, MAGIC_V6: 6}.get(magic)
    if len(envelope) < 5 + 4 + NONCE_BYTES + TAG_BYTES + 1 or version is None:
        raise RecoveryError("Record is too short to be a valid Tagcrypt v4/v5/v6 record.")
    payload_length = int.from_bytes(envelope[5:9], "big")
    cursor = 9
    if payload_length < NONCE_BYTES + TAG_BYTES + 1 or payload_length > MAX_RECORD_BYTES:
        raise RecoveryError(f"Tagcrypt v{version} payload length is invalid.")
    payload_end = cursor + payload_length
    if payload_end + 1 > len(envelope):
        raise RecoveryError(f"Tagcrypt v{version} payload is truncated.")
    payload = envelope[cursor:payload_end]
    cursor = payload_end
    slot_count = envelope[cursor]
    cursor += 1
    if not 1 <= slot_count <= 4:
        raise RecoveryError(f"Tagcrypt v{version} key-slot count is invalid.")

    pass_slot = None
    for _ in range(slot_count):
        if cursor + 3 > len(envelope):
            raise RecoveryError(f"Tagcrypt v{version} key slot is truncated.")
        slot_type = envelope[cursor]
        cursor += 1
        metadata_length = int.from_bytes(envelope[cursor:cursor + 2], "big")
        cursor += 2
        if metadata_length > 512 or cursor + metadata_length + 2 > len(envelope):
            raise RecoveryError(f"Tagcrypt v{version} key-slot metadata length is invalid.")
        metadata = envelope[cursor:cursor + metadata_length]
        cursor += metadata_length
        wrapped_length = int.from_bytes(envelope[cursor:cursor + 2], "big")
        cursor += 2
        if wrapped_length != NONCE_BYTES + 32 + TAG_BYTES or cursor + wrapped_length > len(envelope):
            raise RecoveryError(f"Tagcrypt v{version} wrapped-key length is invalid.")
        wrapped = envelope[cursor:cursor + wrapped_length]
        cursor += wrapped_length
        if slot_type == 1:
            pass_slot = (metadata, wrapped)
    if cursor != len(envelope) or pass_slot is None:
        raise RecoveryError(f"Tagcrypt v{version} record is malformed or has no passphrase recovery slot.")

    metadata, wrapped = pass_slot
    if len(metadata) != 21 or metadata[0] != KDF_ID_PBKDF2_SHA256:
        raise RecoveryError(f"This Tagcrypt v{version} passphrase slot uses unsupported KDF parameters.")
    rounds = int.from_bytes(metadata[1:5], "big")
    if rounds != ITERATIONS:
        raise RecoveryError(f"This Tagcrypt v{version} record uses unsupported KDF parameters.")
    salt = metadata[5:21]
    canonical = unicodedata.normalize("NFC", passphrase.strip())
    candidates = [canonical]
    if canonical != passphrase:
        candidates.append(passphrase)
    dek = None
    aad = magic + payload + b"\x01" + metadata
    for candidate in candidates:
        key = hashlib.pbkdf2_hmac("sha256", candidate.encode("utf-8"), salt, ITERATIONS, dklen=32)
        try:
            dek = ChaCha20Poly1305(key).decrypt(wrapped[:NONCE_BYTES], wrapped[NONCE_BYTES:], aad)
            break
        except (InvalidTag, ValueError):
            continue
    if dek is None:
        raise RecoveryError("Passphrase is incorrect or the record is damaged.")
    try:
        plaintext = ChaCha20Poly1305(dek).decrypt(payload[:NONCE_BYTES], payload[NONCE_BYTES:], magic)
    except (InvalidTag, ValueError) as exc:
        raise RecoveryError(f"Tagcrypt v{version} payload authentication failed.") from exc
    try:
        vault = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RecoveryError("Decrypted data is not valid Tagcrypt JSON.") from exc
    return format_vault(vault)


def format_vault(vault: object) -> str:
    if not isinstance(vault, dict):
        raise RecoveryError("Decrypted JSON is not a Tagcrypt vault object.")
    secret = vault.get("secret")
    slots = vault.get("slots")
    if isinstance(secret, str) and secret:
        return secret
    if not isinstance(slots, list) or not slots:
        raise RecoveryError("Decrypted JSON contains no Tagcrypt secret or slots.")
    lines = []
    for index, slot in enumerate(slots, start=1):
        if not isinstance(slot, dict) or not isinstance(slot.get("title"), str) or not isinstance(slot.get("secret"), str):
            raise RecoveryError("Decrypted slot data is malformed.")
        lines.append(f"[{index}] {slot['title']}\n{slot['secret']}")
    return "\n\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Decrypt a Base64 value copied from a Tagcrypt v2-v6 NDEF/QR record using its passphrase slot."
    )
    parser.add_argument(
        "record_file",
        type=Path,
        help="text file containing only the record's Base64 Text value",
    )
    args = parser.parse_args()

    try:
        encoded = args.record_file.read_bytes()
        if len(encoded) > MAX_RECORD_BYTES * 2:
            raise RecoveryError("Input file is larger than this helper accepts.")
        envelope = decode_text_record_value(encoded)
        passphrase = getpass.getpass("Tagcrypt passphrase (input hidden): ")
        secret = decrypt_envelope(envelope, passphrase)
    except (OSError, RecoveryError) as exc:
        print(f"Recovery failed: {exc}", file=sys.stderr)
        return 1

    print(secret)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
