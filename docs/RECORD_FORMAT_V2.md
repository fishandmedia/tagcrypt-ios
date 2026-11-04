# Tagcrypt portable record format v2

**Status:** describes the legacy Tagcrypt v2 writer and reader. Current multi-slot writes use a newer record version whose complete format is not documented here. This v2 compatibility specification is not a security certification; implementations should validate against test vectors before handling real credentials.

## NDEF record

Tagcrypt writes one NFC Forum NDEF well-known Text record:

- TNF: NFC well-known (`0x01`)
- Type: UTF-8 byte `T` (`0x54`)
- Identifier: empty
- Payload: status byte `0x02` (UTF-8, language length 2), ASCII language code `en`, then UTF-8 Base64 text of the binary envelope below

The record replaces the tag's previous NDEF message when written, but the app reads the tag first and requires explicit confirmation if any NDEF record already exists. After writing, the app reads back and compares the full NDEF record before reporting verification. The payload is not a secret until decrypted: anyone with a reader can copy it. The app estimates full NDEF message bytes and checks the capacity reported by the physical tag before write.

## Binary envelope

The `TVLT` magic prefix is the historical TagVault format identifier. It is intentionally retained for compatibility; it is not the current product name and must not be changed in v2.

The Base64-decoded envelope is concatenated without padding between fields:

| Offset | Length | Field | Value |
|---:|---:|---|---|
| 0 | 5 | Magic and version | ASCII `TVLT` followed by `0x02` |
| 5 | 1 | KDF id | `0x01` = PBKDF2-HMAC-SHA256 |
| 6 | 4 | Iterations | Unsigned 32-bit big-endian; currently exactly 600,000 |
| 10 | 16 | Salt | Fresh cryptographically random bytes for each encryption |
| 26 | 12 | ChaCha20-Poly1305 nonce | Random nonce from CryptoKit combined representation |
| 38 | variable | Ciphertext | Encrypted UTF-8 JSON bytes |
| end - 16 | 16 | Authentication tag | Poly1305 tag |

The minimum binary envelope length for a valid non-empty secret is 26 + 12 + 16 + JSON byte length. ChaChaPoly uses the combined representation `nonce || ciphertext || tag`.

## Key derivation and encryption

- New-record password input: trim leading/trailing whitespace, normalize to Unicode NFC, then encode as UTF-8; case-sensitive. Readers first use the normalized value and may retry the exact entered value for compatibility with early v2 records.
- New v2 writes require at least 16 UTF-8 bytes. This is only a floor, not a strength/entropy test.
- KDF: PBKDF2-HMAC-SHA256, 600,000 iterations, 32-byte output.
- AEAD: ChaCha20-Poly1305, 96-bit nonce, 128-bit tag.
- Associated data: the complete 26-byte header (`TVLT`, version, KDF id, iteration count, salt).
- Plaintext: `JSONEncoder` UTF-8 encoding of `PasswordVault`, an object with a single string field named `secret`. The current writer uses sorted keys and does not escape `/`.
- Randomness: the salt and nonce are independently generated for every encryption. Re-encrypting the same secret/passphrase produces a different envelope.

Readers must reject unknown magic/version/KDF/iteration values. Do not use the on-record iteration count to request unbounded work; v2 currently accepts only exactly 600,000. Authentication failure means the passphrase is wrong or the record was modified/damaged; it must not return partial plaintext. The iOS app runs derivation on a detached task so the 600,000-round KDF does not block SwiftUI's main actor.

## Recovery helper

`../tools/tagcrypt_v2_decrypt.py` is an offline Python helper for a Base64 Text-record value. It prompts for the passphrase with terminal echo disabled and prints the decrypted secret to stdout. It requires the third-party `cryptography` Python package for ChaCha20-Poly1305. It does not contact a server or write plaintext to a file. Terminal output can still be visible in shell scrollback or screen capture; use a trusted, private computer and clear the terminal afterward.

The helper accepts the Base64 value copied from a Tagcrypt v2 NDEF Text record, not a full raw NFC dump. A reader/export tool must expose the Text record's Base64 value first. Swift and Python implementations are cross-checked against the deterministic fixture in `TEST_VECTORS_V2.md`; this validates format agreement for the fixture and passphrase normalization, not a security audit or full-device recovery guarantee.

## Compatibility and versioning

- v2 is Tagcrypt-specific and is not interoperable with NFC.cool NFC Safe or Numa Wallet's NFC format.
- Tagcrypt v1 device-bound records and the historical `application/vnd.tagvault.record` MIME type are not supported by the current app. Existing v2 records remain supported.
- Do not modify v2 field order, associated data, KDF parameters, plaintext schema, or NDEF wrapper in place. Any incompatible change needs a new version and a reader that continues to support existing records.
