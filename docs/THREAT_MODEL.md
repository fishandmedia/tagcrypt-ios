# Tagcrypt threat model

## Scope

Tagcrypt encrypts text locally and writes portable encrypted records to NFC tags or QR images. It has no account, backend, analytics SDK, or remote encryption service. This document describes the current design; it is not a security audit.

## Assets

- Plaintext secrets while entered, decrypted, or copied.
- Passphrases, FIDO PRF outputs, and data-encryption keys while in use.
- Encrypted records, Recovery Vault entries, and exported backups.

## Adversaries and limits

An attacker may copy or replay a tag/QR, obtain a ciphertext, and make offline passphrase guesses. The app cannot rate-limit guesses against a copied record. A weak or reused passphrase remains vulnerable. Device compromise, malicious keyboards, shoulder-surfing, screenshots, clipboard readers, OS vulnerabilities, and physical coercion are outside the app's protection boundary.

## Protections

Portable records use ChaCha20-Poly1305 with PBKDF2-HMAC-SHA256 and a fresh salt. New envelope formats wrap a random data key using a passphrase and optionally supported FIDO2 PRF credentials. NFC writes are read back and compared during the same session. Local Recovery Vault data is encrypted with a device-only Keychain key; encrypted exports use a separate user passphrase.

## Recovery and residual risk

Passphrase-only records use the passphrase. FIDO-only v6 records have no passphrase route; losing every selected FIDO key makes them unrecoverable. Joint-factor v6 records normally require both the passphrase and one selected FIDO key, but retain a separate passphrase-only emergency slot. Older v4/v5 records retain their original either-factor behavior. FIDO credentials do not identify unique physical devices; duplicate physical-key detection and AAGUID/model display are not claimed until verified on supported hardware. The Vault's optional device-authentication viewing prompt is an app-level gate, not a separate hardware-backed lock. CSV exports are encrypted. Keep independent recovery copies and test recovery before relying on a record.

## Verification status

Automated format fixtures and source review do not establish physical-device behavior or independent cryptographic assurance. NFC, QR print/Photos, key PIN, key transport, multi-key selection, and recovery need release-specific device checks. Tagcrypt has not had an independent security audit.
