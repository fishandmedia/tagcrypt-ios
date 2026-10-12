# Tagcrypt

Tagcrypt encrypts short secrets on the device and stores the encrypted record on an NFC tag or in a QR code. It has no account or server-side encryption service.

For AI assistants and quick answers, see [LLM.md](LLM.md): a plain-text product guide. The same file ships in the app (About → Guide for AI assistants) and on the website at `/llm.md`. Update it with every release.

## Security model

- New passphrase-only and FIDO-backed v7 records use ChaCha20-Poly1305, a non-`TVLT` binary discriminator, and encrypted padding. NFC padding targets the selected tag's estimated usable capacity; QR uses fixed size buckets. Passphrase slots use libsodium Argon2id with per-record salt and serialized parameters; FIDO slots use the authenticator PRF. Legacy v2–v6 remain readable with their original PBKDF2-HMAC-SHA256 parameters.
- Multi-slot records encrypt named values together. Records can use a passphrase, FIDO2 PRF keys, or both. Joint-factor records normally require both; they also retain a separately labeled passphrase emergency-recovery path.
- The Recovery Vault stores saved phrases, labels, security-key names, and optional encrypted record copies in an encrypted local file. It does not sync.
- Settings can create passphrase-encrypted Recovery Vault backups for import on another Tagcrypt installation. CSV backups are encrypted before export.
- QR images and NFC tags contain ciphertext only, but can be copied and subjected to offline passphrase guessing. A weak passphrase remains weak.
- The optional Recovery Vault viewing prompt is an app-level device-authentication check. It is not a separate hardware-backed lock on the Vault file.
- NFC writes one prepared encrypted record to one tag per scan and verifies it by reading it back. New v7 records use a binary NDEF media record; legacy v2–v6 records remain readable from Base64 NDEF Text records. Core NFC's live NDEF capacity, not the selected model label, is authoritative. If a padded record is too large, Tagcrypt offers to re-encrypt it to the scanned tag's reported capacity. When optional model-specific password setup is unavailable, users can choose encrypted NDEF only or cancel; the same tag must be rescanned and no fallback write occurs without that choice. Optional raw-page mode writes a capacity-sized v7 record directly to recognized NTAG213/215/216 user pages without NDEF; it must be selected manually to read and disables iOS background tag reading.
- Saved encrypted record copies can be split into three Shamir shares; each share can be written to a separate supported NFC tag, read back, or copied as text. Any two reconstruct the encrypted bytes, which still require their normal passphrase/security key to decrypt. Shares are larger than the input record and may require larger tags.
- A local reminder can ask users to read and verify a separate copy every three months. It does not create or sync a backup.
- Basic Settings mode is the default and hides advanced tag controls; enabling Advanced and changing raw-page, page-randomization, or password settings requires an explicit warning acknowledgement. Settings puts About Tagcrypt, Shop for tags, and Help & FAQ together; the latter contains “Which tag should I use?” and “Security and limitations.”
- Settings describe NTAG213/215/216 user memory and current limits. NFC scans make read-only GET_VERSION/configuration requests for supported NTAG21x tags and report detected capacity/protection state when available. Unused-page randomization is opt-in and off by default; it randomizes and verifies user-memory bytes after the NDEF terminator on recognized NTAG213/215/216 tags with no detected password protection. Raw mode verifies every user byte after writing and is also off by default. Password provisioning and the separate permanent seal (freezes user memory, the Capability Container and the configuration pages on GET_VERSION-identified NTAG213/215/216) are opt-in and experimental. The seal was verified at chip level on one NTAG216-compatible test tag; password provisioning is still physically unvalidated. Unknown or incompatible tags may fail, so these controls are not proof of authenticity or secrecy. Plain NDEF reads and writes send no native NTAG command. Protected-file support for NTAG 424 DNA/DESFire EV2/EV3 remains disabled.
- Tagcrypt has not had an independent security audit. Do not treat it as a hardware wallet, secure element, or guaranteed recovery service.

## Record formats

The app reads legacy TVLT records v2–v6 and writes binary v7 records for passphrase and FIDO modes. See [format v2](docs/RECORD_FORMAT_V2.md), [formats v3–v6](docs/RECORD_FORMAT_V3_V4.md), and [format v7](docs/RECORD_FORMAT_V7.md). `tools/tagcrypt_v7_decrypt.py` recovers passphrase-only v7 records and the passphrase emergency slot in joint FIDO envelopes offline with `argon2-cffi` and `cryptography`; it cannot recover FIDO-only records. Supply a raw-page dump as bytes with `--raw-file path/to/dump.bin`; the helper expects the full dump to begin with a supported v7 discriminator. The earlier helper covers v2–v6 passphrase slots. The Recovery Vault's 2-of-3 encrypted-record split is described in [recovery shares](docs/RECOVERY_SHARES.md). NTAG password writes and NTAG213 sealing are opt-in and physically unvalidated; NTAG 424 DNA/DESFire protected-file protocols remain disabled. See the [hardware feasibility boundary](docs/HARDWARE_TIER_FEASIBILITY.md).

## Build

1. Open `Tagcrypt.xcodeproj` in Xcode.
2. Select the Tagcrypt scheme and set your own Apple Developer team under Signing & Capabilities.
3. Build for a supported iPhone or iPad. Physical NFC and FIDO2 PRF paths require compatible hardware and device testing.

The FIDO2 PRF path requires iOS/iPadOS 26.4 or later and an authenticator that supports Apple's external-key PRF API. Support varies by key model and transport. Choose your development team in Xcode before signing.

## First launch and About

First launch uses a five-card, non-dismissible setup flow. Users can set appearance, passphrase reuse, Recovery Vault authentication, and a reminder. Record destination and tag capacity remain per-job choices. Advanced write options start off; replacing existing tag data prompts for confirmation. The final safety card requires an explicit local acknowledgement. The detailed limitations are in `Tagcrypt/SafetyNoticeV4.txt`. Settings opens in Basic mode, with warnings before Advanced and risky tag preferences. Settings provides adjacent About Tagcrypt, Shop for tags, and Help & FAQ destinations; tag guidance and security limitations are outside About. The publisher is `Fish and Media Ltd.`; version is marketing version plus build (for example, 1.1.28). The acknowledgement is local to this device and is not a legal warranty or recovery guarantee.

## Build verification

The 1.1 source is released as marketing version 1.1 (build 46). The generic iOS Simulator build succeeds, and the four standalone Swift harnesses and the Python suite pass. Physical NFC/FIDO behaviour is validated on real hardware as it becomes available (clone tags, password provisioning and sealing, Argon2 latency on the oldest supported iPhone). A simulator build does not establish NFC behaviour.

## Tests

The Python recovery helper and interoperability tests require Python 3 plus the packages in `tools/requirements.txt`:

```sh
python3 -m unittest discover -s tests
```

See [the threat model](docs/THREAT_MODEL.md) for assumptions and residual risks. These tests do not replace physical NFC, QR, FIDO2, or recovery testing.

The four standalone Swift harnesses run on macOS (no Xcode project or simulator needed):

```sh
swiftc Tagcrypt/RecoveryShares.swift tests/shares/main.swift -o /tmp/tagcrypt-shares-tests
/tmp/tagcrypt-shares-tests

swiftc Tagcrypt/FirstRunOnboarding.swift tests/onboarding/main.swift -o /tmp/tagcrypt-onboarding-tests
/tmp/tagcrypt-onboarding-tests

swiftc Tagcrypt/TagLockCrypto.swift tests/tag_lock_crypto/main.swift -o /tmp/tagcrypt-tag-lock-crypto-tests
/tmp/tagcrypt-tag-lock-crypto-tests

swiftc Tagcrypt/TagLockCrypto.swift Tagcrypt/NTAG21xProtocol.swift tests/tag_lock_protocol/main.swift -o /tmp/tagcrypt-tag-lock-protocol-tests
/tmp/tagcrypt-tag-lock-protocol-tests
```

They cover Shamir share encoding, onboarding defaults and the capacity policy, NTAG PWD/PACK derivation, and the NTAG21x command, provisioning and seal plans. They do not exercise Core NFC; physical tests on disposable tags are still required.

## License and trademark

Licensed under Apache-2.0. See [LICENSE](LICENSE).

Tagcrypt is a trademark of Fish and Media Ltd.
