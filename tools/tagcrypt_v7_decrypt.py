#!/usr/bin/env python3
"""Offline recovery for passphrase and emergency passphrase-slot Tagcrypt v7 records."""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import sys
from pathlib import Path
import unicodedata

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


MARKER = bytes.fromhex("a79d42f1")
FIDO_MARKER = bytes.fromhex("5ad37e91")
SALT_BYTES = 16
NONCE_BYTES = 12
TAG_BYTES = 16
INNER_MARKER = b"TC7\0"
MAX_RECORD_BYTES = 4096
MAX_PLAINTEXT_BYTES = 2048


def read_record(encoded: str | None = None, raw_file: str | Path | None = None) -> bytes:
    if (encoded is None) == (raw_file is None):
        raise ValueError("provide exactly one Base64 record or raw-page dump file")
    if raw_file is not None:
        record = Path(raw_file).read_bytes()
    else:
        record = base64.b64decode(encoded.removeprefix("TAGCRYPT1:").strip(), validate=True)
    if len(record) > MAX_RECORD_BYTES:
        raise ValueError("record is larger than this helper accepts")
    if not record.startswith((MARKER, FIDO_MARKER)):
        raise ValueError("input does not begin with a supported Tagcrypt v7 binary marker")
    return record


def decrypt(record: bytes, passphrase: str) -> bytes:
    if record.startswith(FIDO_MARKER):
        return decrypt_fido_passphrase_slot(record, passphrase)
    header_bytes = len(MARKER) + SALT_BYTES
    if len(record) <= header_bytes + NONCE_BYTES + TAG_BYTES or not record.startswith(MARKER):
        raise ValueError("not a valid v7 record")
    aad, salt = record[:header_bytes], record[len(MARKER):header_bytes]
    nonce = record[header_bytes : header_bytes + NONCE_BYTES]
    ciphertext = record[header_bytes + NONCE_BYTES :]
    key = hash_secret_raw(
        secret=unicodedata.normalize("NFC", passphrase.strip()).encode("utf-8"),
        salt=salt,
        time_cost=2,
        memory_cost=64 * 1024,
        parallelism=1,
        hash_len=32,
        type=Type.ID,
        version=19,
    )
    plaintext = ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)
    return decode_v7_plaintext(plaintext)


def decode_v7_plaintext(plaintext: bytes) -> bytes:
    if len(plaintext) < 9 or not plaintext.startswith(INNER_MARKER) or plaintext[4] not in (0, 1):
        raise ValueError("decrypted data has an invalid v7 structure")
    padded = plaintext[4] == 1
    json_length = int.from_bytes(plaintext[5:9], "big")
    if json_length <= 0 or 9 + json_length > len(plaintext):
        raise ValueError("invalid JSON length")
    if padded and len(plaintext) > MAX_PLAINTEXT_BYTES:
        raise ValueError("padded record is larger than the supported maximum")
    if not padded and 9 + json_length != len(plaintext):
        raise ValueError("invalid unpadded record length")
    return plaintext[9 : 9 + json_length]


def decrypt_fido_passphrase_slot(record: bytes, passphrase: str) -> bytes:
    """Use the standalone emergency passphrase slot in a joint FIDO v7 envelope."""
    if len(record) > MAX_RECORD_BYTES or len(record) < 25:
        raise ValueError("FIDO v7 record length is invalid")
    header = record[:20]  # discriminator + authenticated random record salt
    payload_length = int.from_bytes(record[20:24], "big")
    cursor = 24
    if payload_length < NONCE_BYTES + TAG_BYTES + 9 or cursor + payload_length + 1 > len(record):
        raise ValueError("FIDO v7 payload length is invalid")
    payload = record[cursor : cursor + payload_length]
    cursor += payload_length
    slot_count = record[cursor]
    cursor += 1
    if not 1 <= slot_count <= 4:
        raise ValueError("FIDO v7 slot count is invalid")

    pass_slot = None
    for _ in range(slot_count):
        if cursor + 3 > len(record):
            raise ValueError("FIDO v7 slot is truncated")
        slot_type = record[cursor]
        metadata_length = int.from_bytes(record[cursor + 1 : cursor + 3], "big")
        cursor += 3
        if metadata_length > 512 or cursor + metadata_length + 2 > len(record):
            raise ValueError("FIDO v7 slot metadata is invalid")
        metadata = record[cursor : cursor + metadata_length]
        cursor += metadata_length
        wrapped_length = int.from_bytes(record[cursor : cursor + 2], "big")
        cursor += 2
        if wrapped_length != NONCE_BYTES + 32 + TAG_BYTES or cursor + wrapped_length > len(record):
            raise ValueError("FIDO v7 wrapped key length is invalid")
        wrapped_key = record[cursor : cursor + wrapped_length]
        cursor += wrapped_length
        if slot_type == 1:
            pass_slot = (metadata, wrapped_key)
    if cursor != len(record) or pass_slot is None:
        raise ValueError("FIDO v7 record has no valid passphrase recovery slot")

    metadata, wrapped_key = pass_slot
    if len(metadata) != 25 or metadata[0] != 2:
        raise ValueError("FIDO v7 passphrase slot KDF is unsupported")
    time_cost = int.from_bytes(metadata[1:5], "big")
    memory_cost = int.from_bytes(metadata[5:9], "big")
    if not 1 <= time_cost <= 10 or not 8 * 1024 * 1024 <= memory_cost <= 512 * 1024 * 1024 or memory_cost % 1024:
        raise ValueError("FIDO v7 Argon2id parameters are outside safe bounds")
    canonical = unicodedata.normalize("NFC", passphrase.strip()).encode("utf-8")
    key = hash_secret_raw(
        secret=canonical,
        salt=metadata[9:25],
        time_cost=time_cost,
        memory_cost=memory_cost // 1024,
        parallelism=1,
        hash_len=32,
        type=Type.ID,
        version=19,
    )
    wrapping_aad = header + payload + b"\x01" + metadata
    dek = ChaCha20Poly1305(key).decrypt(wrapped_key[:NONCE_BYTES], wrapped_key[NONCE_BYTES:], wrapping_aad)
    plaintext = ChaCha20Poly1305(dek).decrypt(payload[:NONCE_BYTES], payload[NONCE_BYTES:], header)
    return decode_v7_plaintext(plaintext)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("record", nargs="?", help="Base64 v7 record, optionally prefixed with TAGCRYPT1:")
    parser.add_argument("--raw-file", type=Path, help="binary user-memory dump exported from raw-page mode")
    args = parser.parse_args()
    try:
        record = read_record(args.record, args.raw_file)
        clear = decrypt(record, getpass.getpass("Record passphrase: "))
        value = json.loads(clear)
        json.dump(value, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
        return 0
    except Exception as exc:
        print(f"Could not decrypt v7 record: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
