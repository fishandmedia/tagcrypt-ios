# 2-of-3 encrypted-record recovery shares

The Recovery Vault can split an already-encrypted Tagcrypt record into three independent shares. Any two shares reconstruct the exact encrypted bytes; a single share alone does not reveal any of those bytes. The normal record passphrase or security key is still required to decrypt the reconstructed record.

## Share encoding

Each app-generated share is text with the prefix `TAGCRYPT-SHARE1:` followed by Base64 of:

| Field | Bytes | Description |
| --- | ---: | --- |
| Share format | 4 | ASCII `TCS1` |
| Share index | 1 | `1`, `2`, or `3` |
| Record length | 4 | Unsigned big-endian length |
| Set identifier | 16 | Random per split, used to reject mixed sets |
| Share values | record length | One byte per input byte |

For each input byte `s`, the app samples an independent uniform byte `a` and calculates `y(x) = s + a·x` in GF(2^8) at x = 1, 2, 3. Addition is XOR; multiplication uses the AES polynomial `0x11b`. Lagrange interpolation at x = 0 reconstructs the input from any two distinct points.

The input is ciphertext, not a decrypted `PasswordVault`. The random set identifier and length are metadata; they do not authenticate a recovered record. A corrupted share can reconstruct altered bytes, which must subsequently pass the record's own authenticated decryption. Keep each share in a separate place and retain the passphrase/key separately.

The app can write each share to its own NFC tag as a binary NDEF media record, or as a full-user-memory raw-page record when raw mode is enabled. It can scan a share back from either format and fill the first empty recovery field. Each share is larger than the encrypted record by 25 bytes, plus NDEF overhead; the app preflights the selected NTAG size and disables the write action if it will not fit. Raw-page share writes fill the remainder with random bytes. Use larger tags or separate offline storage when a share does not fit. The app does not silently truncate, compress, or change the encrypted payload.

The repository includes a deterministic GF(2^8) arithmetic vector in `TEST_VECTORS_V7_AND_SHARES.md` and a Swift command-line test that reconstructs every pair, round-trips binary and raw-page encodings, and rejects duplicate/mixed-set shares. Independent cryptographic review, corrupted-share, physical NFC read/write, and recovery UX validation remain outstanding. Do not treat source inspection or successful compilation as physical validation.
