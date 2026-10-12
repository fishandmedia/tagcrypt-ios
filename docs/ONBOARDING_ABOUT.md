# First-run onboarding and About

**Implementation:** version 1.1.28 · 2026-10-10

## First run

The old single-scroll safety prompt is replaced by a five-card full-screen sequence. It has no close, skip, or swipe-ahead action. Continue advances one card; Back returns one card. Record destination and tag size are chosen per job rather than during onboarding. The final card shows the detailed limitations in `Tagcrypt/SafetyNoticeV4.txt` and requires an explicit “I have read and understand these limitations” acknowledgement before Enter Tagcrypt is enabled.

The acknowledgement version is stored locally under `tagcrypt.onboarding.acknowledgedVersion`; the completion date is also local. A new onboarding version prompts again. This is an awareness acknowledgement, not an account-linked consent receipt, warranty, or legal defence. Previously acknowledged users see this revised flow once.

The first four cards are intentionally short and configure existing preferences:

1. **Welcome:** local encryption, ciphertext carriers, no account/sync.
2. **Passphrase and appearance:** per-record vs reusable phrase; Light, Dark, or Device Auto.
3. **Recovery:** Vault Face ID/device-passcode prompt and optional local 90-day reminder.
4. **Advanced:** FIDO user verification and overwrite policy (default “Warn before replacing”). Raw-page mode and NTAG password mode are **not** offered on this card; they stay Off and can only be enabled under Settings → Advanced, behind the same risk alert as every other destructive option. Password mode, raw pages, tail randomisation and the NTAG213 seal are experimental and not physically validated; test only on disposable tags with a recovery copy.
5. **Limitations:** the full notice is scrollable at the end, followed by the required acknowledgement.

Settings are persisted as the user chooses them. Unused-page randomization and raw-page mode default off; the overwrite policy defaults to a confirmation warning. Settings opens in Basic mode; each elevated/destructive option displays a confirmation warning before it is changed. If the reminder is enabled, iOS notification permission is requested after onboarding finishes. The onboarding itself does not perform NFC activity.

## About

Settings places three destinations together: About Tagcrypt, Tagcrypt Gear, then Help & FAQ. About contains app identity/version, a concise description, privacy/storage behavior, support, and publisher/trademark information. Tagcrypt Gear contains tested-hardware buying guidance; no shop or affiliate links are active. Help & FAQ contains “Which tag should I use?” and “Security and limitations.” Version is marketing version plus build (`1.1.28`). The official publisher name is “Fish and Media Ltd.” Keep wording evidence-based: do not promise unbreakable encryption, tamper-proof tags, guaranteed recovery, audit status, or general FIDO2 compatibility. Customer-facing wording must be written for any Tagcrypt user, not reference the developer's personal tags/devices or private test setup.

## State of the related NFC decision

Tagcrypt now contains opt-in HMAC PWD/PACK provisioning and a separate irreversible NTAG213 permanent seal flow. These are source/build checked only and have not been physically validated; incompatible clones can fail partway through provisioning. NTAG215/216 permanent sealing is deliberately unsupported. GET_VERSION is not authenticity proof. See `V1_1_IMPLEMENTATION_PLAN.md` and the NTAG implementation plans.

## Verification still required

- Traverse all five cards on a fresh iPhone install and confirm no dismissal or bypass path.
- Confirm each setting persists after leaving onboarding and the reminder permission request occurs only after completion.
- Confirm the final acknowledgement is required and an older version causes the onboarding to reappear.
- Review text sizing, VoiceOver labels/order, Dynamic Type, light/dark themes, and compact/large iPhone/iPad layouts.
- Verify About links and contact details in a release build.
