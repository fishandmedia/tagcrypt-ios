# Website draft: choosing an NFC tag for Tagcrypt

Status: editorial draft only. Do not publish until the supported-tag matrix and physical tests are reviewed.

## A tag is storage, not the lock

Tagcrypt encrypts a record on your device before writing it. A compatible tag stores those encrypted bytes; it does not keep them secret. Anyone with a reader may be able to copy, replace, replay, or damage a generic NFC record. The passphrase (and, for the relevant record modes, a registered security key) controls decryption. A tag password is a separate access-control feature and must not be described as encryption.

## NTAG21x capacity guide

| Tag family | Nominal user memory | Typical use |
| --- | ---: | --- |
| NTAG213 | 144 bytes | Smallest records; check the app's live capacity estimate |
| NTAG215 | 504 bytes | More room for multi-slot records |
| NTAG216 | 888 bytes | Largest of these three common NTAG21x sizes |

These are chip-family nominal user-memory figures, not a guarantee of the usable NDEF capacity of a particular tag. NDEF TLV overhead, existing content, lock state, tag quality, and encoding all matter. See the [NXP NTAG213/215/216 data sheet](https://www.nxp.com/docs/en/data-sheet/NTAG213_215_216.pdf). Let Tagcrypt query and verify the actual NDEF write. If the record does not fit, use a larger compatible tag, shorten the content, or use a QR copy.

Tagcrypt's current scanner makes a read-only product-version/configuration query for NTAG213/215/216. It may report the chip family and configured AUTH0/PROT state; inaccessible or unknown configuration is shown as unknown. A reported setting is not proof that a tag is genuine or that a lock will behave as expected. Optional raw-page mode is an advanced, manually selected NTAG21x storage mode; it writes binary bytes rather than NDEF, and Tagcrypt must be selected to read it. Keep a separate copy before trying it; physical validation is still outstanding.

## Record length, KDF, and recovery choices

New v7 records use Argon2id for passphrase-derived keys and preserve the old PBKDF2 readers for existing records. Argon2id is memory-hard, but its actual resistance depends on the selected parameters and the user's phrase. Parameters are fixed in the v7 format and still require latency/memory profiling on the oldest supported phone; no universal “time to guess” promise is made here. A custom phrase strength meter is only a rough estimate, while generated phrases use random selection.

Encrypted padding groups record lengths into buckets. This conceals exact plaintext length, not the bucket or whether the same ciphertext was copied. QR always uses a bounded bucket profile; NFC padding can be turned off to fit smaller records at the cost of a closer length signal. The separate page-tail randomization setting can overwrite bytes after the NDEF terminator on supported, unprotected NTAG21x tags. It is not secure deletion from controller spare cells and is not yet physically validated.

| Choice | What it does | What it does not do |
| --- | --- | --- |
| NTAG21x password access control | Can restrict selected tag operations using the chip's 32-bit password mechanism | Does not encrypt the record; Tagcrypt does not configure it in this build |
| Permanent lock bits | Can make selected pages permanently read-only | Cannot be undone; Tagcrypt does not set them in this build |
| 2-of-3 recovery shares | Splits the already-encrypted record; any two shares reconstruct it; each share can be written to or scanned from a separate supported tag | Does not decrypt the record or replace its passphrase/security key; each share is larger than the record and may need a larger tag |

For NFC, a compatible tag is reusable physical storage and requires a compatible reader. A QR copy is visible as an image and can be printed or stored, but can also be copied as an image. Both contain encrypted records and can be attacked offline if the passphrase is weak. Keep a second copy separately.

NTAG21x password protection is not payload encryption or strong authentication. Its 32-bit password mechanism is a write/access-control feature and can be subject to guessing. Keep the record passphrase separate.

## Supported and unvalidated products

The current app's guide describes NTAG213/215/216 only. NTAG 424 DNA and DESFire EV2/EV3 are not enabled as Tagcrypt storage in this build. Do not imply that their cryptographic application/file features are used by Tagcrypt. See [`HARDWARE_TIER_FEASIBILITY.md`](HARDWARE_TIER_FEASIBILITY.md) for the internal integration gates; this document is not consumer copy.

No retailer, exact retail SKU, or affiliate program has been approved. Prices, tag lifetime, and sale availability are intentionally omitted rather than guessed. Any future recommendation must identify the exact tested product, disclose an affiliate relationship next to the link, avoid tracking SDKs, and distinguish tested behavior from manufacturer claims.

## Blog-review queue drafts

These outlines are content drafts only; move each into `Blog Review/` for Can's review before publication.

### NFC tag or QR code for an encrypted record?

Compare reader availability, physical size, copyability, capacity constraints, backup practices, and the fact that both media store ciphertext. Do not claim one is universally safer; explain that passphrase quality and separate recovery copies matter more than the carrier.

### What a tag password, a permanent lock, and recovery shares actually change

Distinguish write/access control from encryption, explain the irreversible nature of permanent locking, and describe 2-of-3 shares as a way to reconstruct encrypted bytes—not as an alternative decryption key. State which functions are not currently enabled and avoid suggesting an unsupported tag family is compatible.

## Editorial safety checklist

- Say “encrypted record stored on a tag,” not “the tag encrypts your secret.”
- State that copying the tag does not reveal the record without its passphrase, but offline guessing is possible.
- Do not claim tamper-proofing, guaranteed recovery, secure deletion, or FIDO2 behavior from a generic NFC tag.
- Only recommend product models that have been physically tested for capacity, NDEF read/write, overwrite behavior, and readback.
- Keep any affiliate disclosure adjacent to a link; never present an untested product as supported.
