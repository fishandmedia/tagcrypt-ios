# Tagcrypt CSV import, format v1 (4 Nov 2026)

Status: spec, planned for 1.1.2, not yet in the App Store version (1.1.1). This document is published ahead of the feature so that other apps and tools can target the format. Planned consumers: Tagcrypt iOS import, a batch spreadsheet template, and other apps that export a list of secrets.

## 1. Purpose
A plain, documented file that lets a person or another app hand Tagcrypt a list of secrets to encrypt onto tags or QR codes, one record per tag. The file is **not encrypted**: it is a staging file, like a password-manager CSV export. Tagcrypt never writes this format out with secrets in it; it only reads it and shows a warning to delete the file after import.

## 2. File
- Extension `.tagcrypt.csv` (plain `.csv` is also accepted from the Files picker).
- UTI `com.fishandmedia.tagcrypt.csv`, conforms to `public.comma-separated-values-text`. Declared as an imported and exported type, so "Open in Tagcrypt" appears in the share sheet and Files.
- Encoding UTF-8, optional BOM, LF or CRLF line ends, RFC 4180 quoting (fields with comma, quote or newline are double-quoted; quotes doubled).
- Limits: at most 1 MiB and 500 data rows; rows beyond are rejected with the row number, nothing is imported.

## 3. Columns
Header row is mandatory and must be exactly, in this order:

```
tagcrypt_csv_v1,record,title,secret,nickname,tag,unlock
```

| Column | Required | Meaning |
|---|---|---|
| `tagcrypt_csv_v1` | yes | Row kind: `record` (default when empty) or `slot`. The header name carries the format version. |
| `record` | no | Group id (any string up to 32 chars). Rows with the same id form **one** record with several named secrets (slots), written to one tag. Empty = this row is a record of its own. |
| `title` | slot rows: yes | Slot name shown in the app (max 40 chars). Empty on a single-row record = freeform secret. |
| `secret` | yes | The secret text (max 2,000 UTF-8 bytes; the tag budget is checked separately). |
| `nickname` | no | Vault nickname for the record (what the tag is for). Not written to the tag. |
| `tag` | no | Target: `NTAG213`, `NTAG215` (default), `NTAG216`, `QR`. |
| `unlock` | no | `passphrase` (default), `key` (security key only), `both`. |

Rules: unknown header = reject the file. Exception: the batch template's trailing formula columns `bytes` and `space_left` (section 5) may follow the 7 columns and are ignored. Rows are numbered like a spreadsheet (header = row 1); rows where every cell is empty are skipped and do not count towards the 500-row limit. A row with fewer than 7 cells is padded with empty cells; more cells than the header = rejected row. Unknown `tag` or `unlock` value = reject that row with a message, import the rest only after the user confirms. Leading/trailing spaces are kept inside quotes, trimmed outside. A `slot` row with an empty `record` is an error. If any row of a record group is rejected, or its rows disagree on `tag`, `unlock` or `nickname`, the whole group is rejected (a record is never written with a slot missing). A titled row in a group with an empty title gets the slot name `Secret`. Values of `tag` and `unlock` are matched without regard to case. Broken quoting (an unclosed quote, a quote inside an unquoted field) rejects the whole file.

## 4. Size rule (what fits on which tag)
Tagcrypt pads NFC records to a conservative payload per tag (`safeNDEFPayloadBytes`: NTAG213 128, NTAG215 448, NTAG216 832 bytes), and the v7 record adds a fixed overhead plus per-slot framing on top of the UTF-8 bytes of `title` and `secret`. The exact plaintext budget per tag is published by the implementation in this file's section 7 (table + test vectors, from `VaultCrypto.estimatedBase64TextLength` / `encodeVault`), so that the template and other apps can compute the same number without running the app. Section 7 replaces the earlier rough guide.

The import preview shows, per record, `used / budget bytes` for the chosen tag and marks rows that do not fit; the user can change `tag` per row before importing.

## 5. Batch template
A batch template (planned for 1.1.2; a spreadsheet that Numbers and Excel open): the same columns, one row per secret, `tag` / `unlock` / row-kind dropdowns and two formula columns: `bytes` (this row's share, section 7.2) and `space_left` = budget(tag, unlock) minus the record's used bytes (all rows of a group show the group's value; negative = does not fit; put a group's `tag` and `unlock` on its first row). The formulas count characters, so they are exact for plain ASCII text; for accented letters or emoji the app's preview is the authority. Export as CSV from Numbers/Excel and open it in Tagcrypt. The template is planned to ship with 1.1.2.

## 6. Entry points
1. **Files / share sheet:** open a `.tagcrypt.csv` (or `.csv`) with Tagcrypt. Also a button **Import CSV** in the Encrypt tab.
2. **URL scheme:** `tagcrypt://import?csv=<base64url of the CSV file>`, at most 16 KiB after decoding; same parser, same preview. For one secret: `tagcrypt://import?title=...&secret=...&tag=NTAG215` (percent-encoded). The app always shows the preview; nothing is encrypted or written without a tap.
3. Share extension: not in v1 (the document type covers "Open in Tagcrypt" from other apps' share sheets).

What happens after import: each record becomes a draft in a new **Batch** list on the Encrypt tab; the user goes through them one by one (passphrase mode per tag or reusable, tag scan, write, verify). Drafts live only in memory; leaving the app clears them. Nothing from the CSV is stored unencrypted.

## 7. Byte budget table and test vectors
Planned for `Tagcrypt/CSVImport.swift` (`TagcryptCSVBudget`) in 1.1.2; that code, its test harness and the batch template are not part of this source version. The numbers below are derived from the existing record estimators in this source (`VaultCrypto.estimatedRecordByteLength` / `estimatedBase64TextLength`, `FIDOEnvelopeCrypto.estimatedRecordByteLength` / `estimatedBase64TextLength`). The test vectors in section 7.3 are included in `tests/csv-import/`.

### 7.1 Budget: plaintext bytes that fit (default settings)

| tag | passphrase | key | both |
|---|---|---|---|
| NTAG213 | 50 | 0 | 0 |
| NTAG215 | 400 | 217 | 127 |
| NTAG216 | 784 | 601 | 511 |
| QR | 768 | 640 | 512 |

0 = does not fit at all. Where the numbers come from:
- NFC record size = min(`safeNDEFPayloadBytes`, largest binary payload whose NDEF message fits tag bytes − 12): NTAG213 min(128, 144 − 12 − 34) = **98**, NTAG215 min(448, 504 − 12 − 37) = **448**, NTAG216 min(832, 888 − 12 − 37) = **832**. The NDEF message of one media record `application/vnd.tagcrypt.record` is payload + 34 bytes (short record, payload ≤ 255) or + 37. Records are padded to this size (padding on = default; raw-page mode and "Fit this tag's capacity" after a scan can change it).
- Passphrase envelope (v7): marker 4 + salt 16 + nonce 12 + tag 16 = **48** bytes outside the plaintext. Budget = record size − 48.
- Security key envelope (v7 FIDO): 25 fixed + per key 65 + 1 + credential ID + 32 + 16, + 90 for the passphrase slot in `both`, + 28 nonce/tag. The table assumes **one key with a 64-byte credential ID** (key 231, both 321 bytes). Each extra key costs 114 + its ID length; a shorter ID gives that many bytes back.
- QR: `TAGCRYPT1:` + Base64 of the record must stay ≤ 1,200 characters, and the plaintext is padded to the next bucket of 32, 64, 128, 256, 384, 512, 640, 768 bytes. Budget = the largest bucket that still fits.

### 7.2 Used bytes (what the preview shows as `used`)
Plaintext = 9 bytes (`TC7\0`, padding flag, UInt32 length) + the record JSON (`JSONEncoder`, sorted keys, slashes not escaped). In the JSON, text counts its UTF-8 bytes; `"`, `\` and tab/newline/CR/backspace/form-feed count 2; other control characters count 6.
- Freeform secret (one row, empty `title`): used = **22 + len(secret)**.
- Named slots (a `record` group, or one row with a `title`), n slots: used = **32 + Σ (69 + len(title) + len(secret))**. The 69 includes the slot's 36-character id; an empty title in a group counts as `Secret` (6).
A record fits when used ≤ budget. The app re-checks the exact size when it encrypts.

### 7.3 Test vectors (`tests/csv-import/`)
| file | expected |
|---|---|
| `v1-single-record.tagcrypt.csv` | 1 record, freeform secret, nickname `Bank 2FA backup`, NTAG215 + passphrase: **62 / 400 bytes**, fits. CRLF line ends. |
| `v1-three-slot-record.tagcrypt.csv` | 1 record (`home`) with 3 slots `Wi-Fi`, `Alarm PIN`, `Router admin, web` (quoted comma, doubled quotes in a secret), nickname `Home router`, NTAG216 + passphrase from the first row: **336 / 784 bytes**, fits. |
| `v1-rejected-file.tagcrypt.csv` | whole file rejected: the header lacks the `nickname` column ("The first row must be exactly: …"). Nothing imported. |

URL form of a vector: `tagcrypt://import?csv=` + base64url (no padding) of the file bytes.

## 8. Versioning
The header cell name is the version. A future `tagcrypt_csv_v2` keeps v1 readable. Exporting apps and the template must write `tagcrypt_csv_v1` exactly.
