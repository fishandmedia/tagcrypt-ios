# Tagcrypt v2 known-answer vector

This fixture is generated from the documented v2 format with a deterministic salt and nonce for interoperability testing only. **Never use the fixture or its passphrase for a real secret.**

- Passphrase (NFC): `Café Soho London 1666`
- Equivalent NFD passphrase: `Café Soho London 1666` (the `é` is `e` + combining acute)
- Also equivalent under Tagcrypt normalization: either passphrase followed by spaces, tabs, or newlines
- Salt: `000102030405060708090a0b0c0d0e0f`
- Nonce: `101112131415161718191a1b`
- Plaintext JSON UTF-8: `{"secret":"fixture-secret-not-a-real-credential"}`
- Base64 envelope:

```text
VFZMVAIBAAknwAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGht82rRamc5CvvBFf4tU//ntlyjgAUTDoqPFgZ3oNjRpBOqd2T4OZ11kf0ewrn1twSW8hQ5tEp0pCsk5u+fiA6ndUQ==
```

Run the Python assertions with `python3 -m unittest discover -s tests -p 'test_*.py'`. The Swift executable check is compiled alongside the production crypto source on macOS: `swiftc Tagcrypt/VaultCrypto.swift tests/main.swift -o /tmp/tagcrypt-vector-check && /tmp/tagcrypt-vector-check`.
