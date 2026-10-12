# Protected-tag hardware feasibility (v1.1)

Status: research and architectural boundary only. NTAG 424 DNA and DESFire EV2/EV3 are not supported storage targets in this build; no key is provisioned, no protected-file command is sent, and the app makes no compatibility claim.

## What the platform and vendor sources establish

- Core NFC exposes protocol-specific MIFARE command APIs. DESFire can be surfaced through the ISO 7816 tag interface when an application identifier is declared in the app's Info.plist; otherwise Core NFC may surface a MIFARE tag object. The current project has no selected DESFire/NTAG424 AID configuration. See [Apple's NFCMiFareTag documentation](https://developer.apple.com/documentation/corenfc/nfcmifaretag) and [NFCISO7816Tag documentation](https://developer.apple.com/documentation/corenfc/nfciso7816tag).
- NXP describes NTAG 424 DNA as an NFC Forum Type 4 tag with AES-128, secure file access, 3-pass mutual authentication, and a memory layout including a 256-byte NDEF file plus a separate 128-byte protected data file. That is a different storage/access protocol from the current Type 2 NTAG21x page flow. See [NXP product documentation](https://www.nxp.com/products/rfid-nfc/nfc-hf/ntag-for-tags-and-labels/ntag-424-dna-424-dna-tagtamper-advanced-security-and-privacy-for-trusted-iot-applications%3ANTAG424DNA) and the [NTAG 424 DNA data sheet](https://www.nxp.com/docs/en/data-sheet/NT4H2421Gx.pdf).
- NTAG21x PWD_AUTH is a separate 32-bit, unencrypted access-control mechanism; NXP's family data sheet explains AUTH0/PROT and optional AUTHLIM. It does not provide payload encryption. See [NTAG213/215/216 data sheet](https://community.nxp.com/pwmxy87654/attachments/pwmxy87654/nfc/3761/1/NTAG213_215_216.pdf).

## Recommended implementation boundary

Keep v7 as the application-layer encrypted record format and do not conflate it with tag authentication. A protected-tag transport should only read or write the same opaque v7 bytes after a mutually authenticated secure session. Do not derive a tag's 128-bit AES key directly from the human passphrase: that would make a copied record or protocol transcript an offline guessing target. Do not store a tag key on the tag it protects.

Before enabling the hardware tier, select and independently review a recoverable key hierarchy: how per-tag keys are generated, how the owner can restore them on a replacement device, how a lost tag is revoked, and what happens when the encrypted Vault backup is unavailable. Then specify the exact NDEF/protected-file layout, AIDs, access rights, APDU or native command transcript, secure-messaging counters/MACs, error mapping, and migration from an ordinary v7 tag. Keep protected-file authentication separate from the record passphrase and FIDO PRF.

For NTAG21x write protection, likewise do not provision passwords or AUTH0/ACCESS configuration until a reviewed per-tag credential storage/export design and disposable-tag test plan exist. For permanent locking, keep all lock-bit writes absent from the production workflow until model-specific lock maps, the pre-lock full-memory verification, explicit irreversible confirmation, and post-lock recovery/readback have passed on disposable chips. The current source intentionally does not issue PWD_AUTH, configuration writes, or lock-bit writes.

## Required gates before code is enabled

1. Independent review of key hierarchy, format, threat model, and recovery path.
2. Real NTAG 424 DNA and DESFire EV2/EV3 samples, version/feature identification, and testing on supported iPhone models; simulator success is not evidence of NFC behavior.
3. Interoperability tests for authentication, secure messaging, access-right enforcement, interrupted writes, counters/replay rejection, wrong keys, and recovery after device replacement.
4. Privacy notice, App Store Connect encryption/export answers, supported-hardware help, and claims updated only after actual validation.

## Affiliate and publishing gate

The app's hardware-shop section remains a non-link placeholder. No retailer or affiliate programme has been chosen, so there are no external destinations or tracking SDKs. The comparison/blog material remains in `WEBSITE_TAG_GUIDE_DRAFT.md`; it must go through the owner's `Blog Review/` process before it is copied to a live site. Exact products may be recommended only after their behavior is physically tested and the affiliate disclosure/terms are reviewed.
