# Product Safety, Claims, and Web Backend Decision Notes

**Status:** internal engineering guidance. This is not legal advice, a security certification, or a public end-user agreement.

**Current scope decision:** keep this as an iOS app for now. Do not add a web UI, login system, remote encryption/decryption API, or account backend in this phase. The user wants to handle visual UI separately. Revisit a no-login, local-only web client only if there is a concrete cross-device need and after its crypto implementation and delivery risks are reviewed.

## Scope and competitor research

This review used public product pages, app-store descriptions, and published format documentation. It did not inspect private source code, bypass access controls, or independently validate competitor implementations.

### Closest comparable workflows

- **NFC.cool NFC Safe:** public materials describe an offline encrypt/decrypt flow with a live size estimate, iOS/Android support, and a published NDEF format plus Python recovery decoder. Its documented format uses a custom external NDEF type, a 16-byte random salt, 12-byte nonce, AES-256-GCM, and PBKDF2-HMAC-SHA256 at 100,000 rounds. Its implementation is closed-source; the on-tag format and recovery method are published. Tagcrypt v2 is not wire-compatible: Tagcrypt stores Base64 in an NDEF Text record and uses a versioned header plus ChaCha20-Poly1305 and 600,000 PBKDF2 rounds.
  - Product: <https://nfc.cool/features/nfc-reader-writer/>
  - Published format and recovery script: <https://github.com/NickAtGit/nfc.cool-nfc-safe-format>
- **NFCommunicator:** public Google Play description states offline encrypted message read/write, read-then-password entry, estimated fit, AES-256-GCM, PBKDF2, and random salt/nonce. Android only per its listing; no independent security review was performed here.
  - <https://play.google.com/store/apps/details?id=dev.alsatianconsulting.nfcommunicator>
- **Numa Wallet NFC backup:** focused on BIP39 seed backup; publishes a portable NDEF JSON format, Argon2id/AES-GCM parameters, Python recovery instructions, and a test vector.
  - <https://usenuma.io/nfc-backup>
- **ChipVault:** supports structured secrets on MIFARE DESFire EV2/EV3 cards and advertises chip-level encryption. It is not for generic NTAG215 tags; its app is closed-source and vendor-specific.
  - <https://products.n0agi.com/chipvault/>
- **PassLocals:** markets offline encrypted NFC-card storage and device/card/passphrase roles. Its terms describe installation-bound device registration and role blobs bound to a card and device. Public docs inspected here do not provide an independent portable record specification.
  - <https://passlocals.com/>
  - <https://passlocals.com/enduserlicensagreement/en>

### Methodology and interaction patterns worth adopting

The strongest reusable ideas are a clear Encrypt/Decrypt separation, scan/read first and then ask for the passphrase, live byte-size feedback, offline processing, and a published recovery format with a standalone decoder. Tagcrypt already implements a preflight NDEF estimate and scan-then-enter-passphrase decryption. Visual redesign is deliberately deferred. A critical distinction from NFC Tools' tag password feature: tag write/access protection is not payload encryption. NTAG password protection does not turn a generic tag into an encrypted vault or FIDO2 authenticator.

The published NFC.cool design is a useful compatibility target, but adopting its exact format would trade away Tagcrypt's current record format and KDF parameters, and its docs describe a non-standard external-type byte encoding. Do not silently change existing tags. A future format migration requires a reviewed versioned design, cross-implementation test vectors, preserved v2 reading, and an explicit product decision. No visual interface changes are part of this backend-only update.

## Current implementation facts

- v2 plaintext is JSON-encoded in memory and encrypted using CryptoKit ChaCha20-Poly1305.
- Key derivation is PBKDF2-HMAC-SHA256, 600,000 iterations, 32-byte key, random 16-byte per-record salt. The header is authenticated as additional data.
- New records are Base64 ciphertext inside an NDEF Text record. This is not compatible with NFC.cool NFC Safe.
- The app does not read the retired device-bound TagVault v1 record format. Portable Tagcrypt formats v2–v5 are versioned separately; do not imply the v1 record is recoverable in this app.
- The app queries the physical tag's writable state and NDEF capacity before writing. A selected NTAG size only provides a preflight estimate; the selected label cannot prove the capacity of a particular physical tag.
- Before writing, the app reads existing NDEF data and applies the user's configured populated-tag policy (warn, never overwrite, skip, or always overwrite). After a successful write callback, it reads back and compares the NDEF record fields; this is same-session verification, not proof against later tag damage or removal after verification.
- The app and crypto format have not had an independent security audit. A successful build or NFC round-trip is not evidence of cryptographic review.
- The new minimum passphrase policy applies only when creating new records: at least 16 UTF-8 bytes after trimming and NFC normalization. A generated 24-character, 64-symbol passphrase option is available (144 random bits by construction); custom phrase strength is still not scored and weak choices can pass the length floor. Existing records remain decryptable with their original passphrase.
- A copied ciphertext allows offline guesses. No online rate limit can slow an attacker who already has a tag dump.
- The Activity tab was removed because it was a session-only event list. Build 6 replaces it with a device-local Recovery Vault containing passphrases, tag nicknames, NFC/QR destination labels, and FIDO key-name snapshots. Vault JSON is AES-GCM encrypted with a random 256-bit key stored in `WhenUnlockedThisDeviceOnly` Keychain; its file uses complete file protection. It is not synced, has no server backup, and has not received an independent security review. Loss of the device or its Keychain key can make the local Vault unavailable. The Vault does not store decrypted secret text.
- Settings defaults to an encrypted, passphrase-protected Vault backup. An advanced CSV export is plaintext, contains the passphrases and recovery labels, and may be copied or cloud-synced by Files or a receiving app. Do not describe CSV export as encrypted.
- Passphrase form state is cleared when the app backgrounds; an in-flight detached KDF may retain captured copies until it finishes, and Swift does not guarantee erasure of `String` storage.
- Consent acknowledgement is stored locally on the device. No account/backend exists; local acknowledgement does not establish identity or guarantee legal immunity.

### UI copy and feature gaps

Before public distribution, review all strings against the narrow claims below and only promise portability to an independently tested Tagcrypt-compatible decoder. The first-use notice and supporting copy should state offline guessing, tag-copy/replay limits, unrecoverability after passphrase loss, local-only Vault storage, plaintext CSV export, and prototype/no-audit status in plain language.

## Product claims policy

### Claims supported by the current implementation (describe narrowly)

- “Tagcrypt encrypts one text value locally before writing the encrypted record to a compatible NDEF tag.”
- “For v2 records, Tagcrypt uses ChaCha20-Poly1305 and PBKDF2-HMAC-SHA256 with a 16-byte random salt and 600,000 iterations.”
- “The v2 passphrase is not included in the NFC record.”
- “The app checks the NDEF capacity reported by the tag before writing.”
- “A matching Tagcrypt v2 implementation and the original passphrase are required to decrypt a v2 record.”
- “The current prototype has not received an independent security audit.”

### Claims to avoid

Do not say “military grade,” “unbreakable,” “government-proof,” “impossible to hack,” “tamper-proof,” “secure element,” “FIDO2,” “password locked,” or “guaranteed recovery.” Do not claim the tag is unreadable, unclonable, protected from replay, or protected by Face ID for v2. Do not claim cross-platform compatibility until a separate implementation has successfully read test vectors and tags. Do not call this a password manager or the only safe copy of a credential.

Use “encrypted record” or “ciphertext on an NFC tag,” not “locked tag” or “sealed secret.” Explain that anyone can copy, replace, erase, or replay a generic NTAG record; authentication depends on the passphrase; offline guessing is possible; losing the passphrase loses access; and no recovery service exists.

## Web product security decision

### Recommendation

Do not create a server-side `/encrypt` or `/decrypt` API that accepts plaintext, passphrases, derived keys, or decrypted output. A site login does not make those values safe from the site's JavaScript, hosting compromise, browser extensions, or endpoint compromise. If a login is required only to open a paste-in decryptor, the login adds account/session risk without improving decryption security.

For a first web-capable release, prefer a no-login client-side module and static web shell. The browser should parse pasted/exported ciphertext and perform all KDF/decryption locally. It should not send the record or passphrase to analytics, error-reporting, logging, or application servers. Keep secrets in memory only; do not persist them in localStorage, IndexedDB, service-worker caches, URLs, or logs. Clear fields on explicit clear, successful decrypt, and page exit where feasible. Explain that remotely served code can still change and access inputs when loaded.

For a future account product, the backend should authenticate accounts and store opaque ciphertext only. The server must never receive the encryption passphrase or plaintext. Account auth and record encryption are separate controls; account login cannot replace the passphrase. Design account recovery without claiming it can recover a lost encryption passphrase unless a separately reviewed recovery-key design actually exists.

### Browser/NFC constraints

A paste-in decryptor does not need Web NFC. Web NFC is limited to secure contexts and browsers that implement the API; it is not a dependable cross-browser or iPhone/Safari path. Keep native Core NFC for iPhone tag reading/writing. On desktop, users can export/copy the NDEF payload with a reader and paste it into a local decryptor.

Tagcrypt v2 uses ChaCha20-Poly1305. Web Crypto exposes PBKDF2 but does not provide a broadly supported native ChaCha20-Poly1305 interface. A browser decoder therefore needs a reviewed, pinned implementation (or a separately reviewed new format); do not hand-roll a cipher or silently switch algorithms. Preserve read compatibility for existing v2 tags.

### If accounts are later approved

- Keep plaintext and passphrases out of HTTP requests, server logs, analytics, crash reports, traces, and support tools.
- Use HTTPS, strict same-origin deployment, secure session cookies (`HttpOnly`, `Secure`, `SameSite`), CSRF defenses, rate limits for account authentication, and robust account recovery. These protect accounts but do not prevent hostile JavaScript from reading the user's secret.
- Avoid third-party scripts, tag managers, analytics, chat widgets, and remote fonts on the decrypt origin. Use restrictive CSP and dependency pinning as defense in depth; neither makes the page immune to a compromised host or XSS.
- Do not store plaintext or passphrase in browser persistent storage. A non-extractable browser key does not prevent malicious same-origin JavaScript from invoking that key.
- Define independent security review, release provenance, vulnerability intake and response ownership before accepting public users.

## Legal and release-risk notes

This is product-risk guidance, not legal advice. No disclaimer, “use at your own risk” statement, or security warning can guarantee that a developer will not be sued or remove statutory rights. Public statements can shape what consumers reasonably expect. UK Consumer Rights Act 2015 section 34 treats description and public statements as relevant to digital-content quality; section 47 prevents contracting out of specified digital-content duties. The Competition and Markets Authority's updated 2026 guidance says broad disclaimers that shift responsibility for faults may be unfair.

- Consumer Rights Act: <https://www.legislation.gov.uk/ukpga/2015/15/part/1/chapter/3>
- Section 47: <https://www.legislation.gov.uk/ukpga/2015/15/section/47>
- CMA fair contract guidance (updated 22 July 2026): <https://www.gov.uk/guidance/writing-a-fair-contract-for-customers>
- UK app-store/app-developer security code: <https://www.gov.uk/government/publications/code-of-practice-for-app-store-operators-and-app-developers>

Before public or paid distribution, ask a UK solicitor to review the product description, privacy notice, licence/terms, support and recovery statements, app-store listing, and the exact jurisdictions where it will be offered. Do not use legal terms as a substitute for reducing real failure modes.

## Release gates before public users

1. Complete a source-based threat model and independent cryptographic/security review; document scope and findings honestly.
2. Publish a versioned v2 format specification and an offline recovery tool, then validate with independent test vectors and cross-platform implementations. Do not claim interoperability before this is done.
3. Build explicit failure handling for corrupt/unsupported records, wrong passphrases, unsupported tags, and writes that would replace data. Test on sacrificial tags across capacity boundaries.
4. Review secret lifetime, app-switcher/screenshot exposure, clipboard behavior, analytics, crash logs, backups, and developer tooling.
5. Establish supported OS/tag matrix, maintenance and vulnerability contact path, a realistic response process, backups/recovery guidance, and end-of-life policy.
6. Complete privacy and app-store disclosures and independent legal review before making security promises or charging users.
