# Tagcrypt binary record v7

Version 7 is written for passphrase-only, FIDO-only, and joint passphrase/FIDO records. The v2–v6 readers remain in the app for existing tags and QR codes. FIDO PRF output unwraps the record key; joint records include both a passphrase recovery slot and a joint-factor slot. The FIDO PRF output is not serialized.

## Binary layout

All integers are unsigned big-endian. Passphrase-only records use a compact direct envelope: discriminator (4 bytes) || salt (16 bytes) || ChaChaPoly combined box. FIDO-backed records use the slot envelope:

| Field | Bytes | Value |
| --- | ---: | --- |
| Binary discriminator | 4 | Passphrase-only `a7 9d 42 f1`; FIDO envelope `5a d3 7e 91` |
| Record salt | 16 | Random per record |
| Payload length | 4 | Unsigned big-endian byte count |
| ChaChaPoly combined box | variable | CryptoKit nonce (12) || ciphertext || tag (16) |
| Slot count | 1 | Number of key-wrapping slots |
| Slots | variable | Type (1), metadata length (2), metadata, wrapped-key length (2), wrapped DEK |

The discriminator and record salt are authenticated as payload additional data. The discriminator intentionally is not the legacy plaintext `TVLT` header. Key derivation is libsodium Argon2id v1.3 with one lane, 2 operations, 64 MiB memory, and 32-byte output. These values are stored as format constants in this document and source; changing them requires a new format profile/version. FIDO-only records use a PRF-derived HKDF wrapping key; joint records additionally use Argon2id for the passphrase slot. Slot metadata carries per-record KDF parameters/salt or FIDO credential identifier, PRF input, and wrapping salt.

FIDO slot type `01` is a standalone Argon2id passphrase recovery slot (25-byte metadata). Type `02` is a FIDO PRF slot. Type `03` is a joint passphrase-plus-FIDO slot. FIDO metadata is credential-ID length (1), credential ID (variable), PRF input (32), and wrapping salt (16). Every wrapped data-encryption key is a 60-byte ChaChaPoly combined box. Joint mode includes both type `01` and type `03`, so the user can choose passphrase-only emergency recovery; the Python helper supports this type `01` slot. FIDO-only mode cannot be recovered by that helper.

The decrypted plaintext is:

| Field | Bytes | Value |
| --- | ---: | --- |
| Inner marker | 4 | UTF-8 `TC7\0` |
| Padding flag | 1 | `01` padded, `00` unpadded |
| JSON byte length | 4 | Big-endian |
| Vault JSON | variable | Sorted-key JSON encoding |
| Random padding | variable | Cryptographically random bytes |

Padding is encrypted. QR uses the smallest fixed bucket that fits: 32, 64, 128, 256, 384, 512, 640, or 768 plaintext bytes; records that do not fit the last bucket are rejected so `TAGCRYPT1:` stays below 1,200 UTF-8 bytes. NDEF NFC mode, by default, pads the plaintext to the largest binary record that fits the selected tag's estimated usable NDEF capacity. The actual tag capacity is queried again before writing. Optional raw-page mode instead pads to the selected NTAG21x user-memory byte count and writes the complete binary record directly to user pages. It is manually selected for both writing and reading; these tags do not expose an NDEF record in that mode, so iOS background reading is unavailable. The recovery helper accepts a binary dump file with `--raw-file`. NFC padding can be disabled in Settings except when raw-page mode is selected. The recovery decoder accepts padded plaintext up to 2,048 bytes because NFC targets are capacity-dependent. Older v2–v6 records remain readable from NDEF Text records. A separate opt-in NDEF setting, off by default, randomizes and reads back memory after the NDEF TLV terminator on recognized NTAG213/215/216 tags when configuration is readable and unprotected. Raw-page writing and NDEF tail randomization are build-checked but have not been physically validated.

## Python recovery

`tools/tagcrypt_v7_decrypt.py` accepts a Base64-encoded passphrase-only v7 record, a FIDO-envelope v7 record that contains the standalone emergency passphrase slot, or a raw-page binary dump via `--raw-file`. It needs `argon2-cffi` and `cryptography`. It prints the recovered JSON to stdout; use it offline and redirect output only to a protected destination. It does not support FIDO-only records or legacy v2–v6 (see `tools/tagcrypt_v2_decrypt.py` for v2).

## Security and release status

Deterministic passphrase-only, capacity-padding, joint-envelope recovery, and Shamir arithmetic fixtures are documented in [`TEST_VECTORS_V7_AND_SHARES.md`](TEST_VECTORS_V7_AND_SHARES.md). The Python v7 recovery tests cover these v7 decryption vectors; they do not prove Swift/Python interoperability from an app-generated record.

Argon2 parameters have not yet been profiled on the oldest supported physical iPhone. The format has not been validated against a real NFC tag, App Store export-compliance answers, or independent format review. Do not represent those checks as complete until each is recorded.
