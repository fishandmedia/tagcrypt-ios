# Tagcrypt portable record formats v3 through v6

These formats describe multi-slot records (v3) and optional physical FIDO2 security-key unlock (v4-v6). This is an interoperability specification, not a security certification. Validate implementations against vectors and actual devices before relying on records for critical credentials.

## Shared NDEF and QR representation

NFC uses one NDEF well-known Text record (`TNF_WELL_KNOWN`, type `T`, empty identifier) whose payload is UTF-8 status byte `0x02`, language code `en`, then Base64 of the binary envelope. QR uses the text `TAGCRYPT1:` followed immediately by that same Base64 envelope. It contains no plaintext or passphrase. Anyone who copies the data can make offline passphrase guesses. Saving or sharing a QR image sends a copy outside the app; treat it as sensitive ciphertext.

## v3: multi-slot vault

The binary outer envelope is the v2 layout with version byte `0x03` instead of `0x02`:

| Offset | Length | Field |
|---:|---:|---|
| 0 | 5 | `TVLT` + `0x03` |
| 5 | 1 | KDF id `0x01` (PBKDF2-HMAC-SHA256) |
| 6 | 4 | Iterations, unsigned big-endian; exactly 600,000 |
| 10 | 16 | Random per-record salt |
| 26 | variable | ChaCha20-Poly1305 combined value: nonce (12) + ciphertext + tag (16) |

The plaintext is sorted-key UTF-8 JSON, without escaped `/`. A single-secret record is `{"secret":"..."}`. A multi-slot record is `{"secret":"","slots":[{"id":"...","secret":"...","title":"..."}, ...]}`. Swift's `UUID` encodes as a string. Every slot shares the record passphrase. A v3 reader authenticates the full 26-byte header as AEAD associated data. v2 and v3 use separate version bytes; do not change their layouts in place.

## v4: envelope encryption with passphrase and FIDO PRF key slots

v4 creates one random 32-byte data-encryption key (DEK), encrypts the same JSON plaintext with ChaCha20-Poly1305 and authenticates `TVLT\x04` as associated data. It then wraps that DEK independently with a passphrase-derived key and an external FIDO PRF-derived key. At least one passphrase slot and one FIDO slot are required by this version's writer. This allows either the passphrase or the registered physical key to unlock the same encrypted payload.

All unsigned integers below are big-endian. The envelope is:

| Field | Size |
|---|---:|
| Magic/version `TVLT\x04` | 5 bytes |
| Inner payload length | 4 bytes |
| Inner payload | `nonce(12) || ciphertext || tag(16)` |
| Slot count | 1 byte (writer emits 2; reader permits 1–4 but requires both slot types) |
| Key slot(s) | Repeated values below |

Each slot is `type(1) || metadataLength(2) || metadata || wrappedKeyLength(2) || wrappedDEK`. `wrappedKeyLength` is 60; `wrappedDEK` is `nonce(12) || encrypted DEK(32) || tag(16)`. Slot associated data is `TVLT\x04 || innerPayload || typeByte || metadata`.

Type `0x01`, passphrase slot metadata (21 bytes):

| Field | Size |
|---|---:|
| KDF id `0x01` | 1 byte |
| PBKDF2-HMAC-SHA256 iterations (exactly 600,000) | 4 bytes |
| Random salt | 16 bytes |

The passphrase key is PBKDF2-HMAC-SHA256 over the NFC-normalized, edge-trimmed UTF-8 passphrase, 600,000 rounds, 32-byte output.

Type `0x02`, FIDO PRF slot metadata: `credentialIDLength(1) || credentialID(1..255) || PRFInput(32) || HKDFSalt(16)`. The credential ID identifies the WebAuthn credential on the external security key. `PRFInput` is a fresh random value sent as the WebAuthn PRF extension input. The PRF output must be exactly 32 bytes. Derive the wrapping key using HKDF-SHA256 with the PRF output as input key material, `HKDFSalt` as salt, info `Tagcrypt v4 FIDO key-wrap`, and 32-byte output. A key that does not return PRF output cannot open this slot.

The app requests PRF through Apple's Authentication Services roaming-security-key API, available from iOS 26.4 for this path. The credential is scoped to the permanent RP ID `tagcrypt.com` (set before the first public release; pre-release builds used `tagcrypt.fishandmedia.com`); the app's matching Associated Domains/AASA association on tagcrypt.com is required. A plain WebAuthn assertion with no PRF output is not an unlock. A signed-in server account is not used: the app uses the local assertion only to obtain the authenticator's PRF result. The implementation must still be tested on each claimed model/key/transport combination before release.

## Offline recovery

`../tools/tagcrypt_v2_decrypt.py` reads the Base64 NDEF Text value or `TAGCRYPT1:` QR text, and supports v2, v3, and the v4-v6 passphrase slot. It runs offline, prompts without echo, and writes plaintext only to stdout. It cannot use a FIDO security key or open a FIDO-only record. Test any recovery copy on a private machine and retain the original record/passphrase until decrypted output has been confirmed.

## Limits

- Current Tagcrypt QR and NFC records use the same binary envelope, but QR can be copied or shared more easily. It is encrypted backup data, not a passwordless QR login.
- The app does not validate a WebAuthn assertion against a server. The v4 FIDO key slot is based on the PRF extension output, not FIDO's account-authentication signature.
- v4 records are larger than v2/v3. The app estimates NDEF size and the tag is checked again before write; use QR for records that exceed a tag's capacity.
- Older app versions cannot open v4. Keep a passphrase-based independent recovery copy and a compatible newer reader.
- ChaCha20-Poly1305, PBKDF2, HKDF, WebAuthn PRF, or a successful build are not a claim of independent audit, tamper-proof tags, or guaranteed recovery.

## v5: envelope with up to three named-device key choices

v5 uses the same envelope layout and AEAD construction as v4, with magic `TVLT\x05`. It always contains one passphrase recovery slot and can contain one to three type `0x02` FIDO PRF slots. The user selects registered keys for each record. A fresh random PRF input is generated once for the record and shared by its selected key slots because WebAuthn supplies one PRF input per assertion request; each slot stores its credential ID, that shared input, a distinct random HKDF salt, and a wrapped copy of the same random DEK. The key-wrap HKDF info string is `Tagcrypt v5 FIDO key-wrap`. Passphrase and payload associated data use the v5 magic. Any selected physical key can unwrap the DEK; the passphrase recovery slot remains independently usable.

Registration names and credential profiles are local Keychain metadata; only the credential IDs and PRF input needed for selected unlock paths are embedded in a record. The on-record credential identifiers are public metadata and do not disclose the FIDO PRF output. The app's offline recovery helper can open the passphrase slot without a security key. v4 records remain readable and use their original v4 key-wrap info string.

## v6: passphrase-only, FIDO-only, or joint-factor envelope

v6 uses magic `TVLT\x06`, the v4/v5 envelope layout, a random 32-byte DEK, and ChaCha20-Poly1305 for both the payload and wrapped DEK. The payload associated data is the v6 magic. Slot associated data is `TVLT\x06 || innerPayload || typeByte || metadata`. Slot count is one through four; every wrapped DEK is 60 bytes.

The writer expresses the unlock policy through slot types:

- **FIDO-only:** one to three type `0x02` slots. There is no passphrase slot or passphrase recovery route. Each key slot derives its wrapper with HKDF-SHA256 from the 32-byte WebAuthn PRF output, its 16-byte per-slot salt, info `Tagcrypt v6 FIDO key-wrap`, and a 32-byte output. Metadata is identical to the v5 type `0x02` metadata.
- **Passphrase + FIDO:** one type `0x01` passphrase slot and one to three type `0x03` joint slots. The type `0x01` passphrase metadata and wrapper are identical to v5. Each type `0x03` slot uses the v5 FIDO metadata shape. Derive `passKEK` from the passphrase slot's salt with PBKDF2-HMAC-SHA256 (600,000 rounds), and derive `fidoKEK` from the PRF output using HKDF-SHA256 with that type `0x03` slot's salt and info `Tagcrypt v6 FIDO key-wrap`. Concatenate the 32-byte `passKEK` followed by the 32-byte `fidoKEK`, then derive the joint wrapper with HKDF-SHA256, using the same slot salt and info `Tagcrypt v6 passphrase + FIDO key-wrap`, output length 32. Normal joint unlock needs both factors and one selected FIDO key. The separate type `0x01` slot intentionally permits passphrase-only emergency recovery.
- **Passphrase-only:** new passphrase-only records continue to use v2/v3 formats. v4/v5 records retain their original semantics: either the passphrase or any FIDO key slot can unlock them.

Valid v6 slot combinations are either one to three type `0x02` slots and no other slot types, or exactly one type `0x01` slot plus one to three type `0x03` slots. Other combinations are malformed. FIDO-only records cannot be recovered with the offline passphrase helper. Joint-factor records can be recovered through the documented emergency passphrase slot.
