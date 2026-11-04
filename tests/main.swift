import Foundation

let encoded = "VFZMVAIBAAknwAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGht82rRamc5CvvBFf4tU//ntlyjgAUTDoqPFgZ3oNjRpBOqd2T4OZ11kf0ewrn1twSW8hQ5tEp0pCsk5u+fiA6ndUQ=="
let expected = "fixture-secret-not-a-real-credential"
let record = Data(base64Encoded: encoded)!
let cases = [
    "Café Soho London 1666",
    "Cafe\u{0301} Soho London 1666",
    "Café Soho London 1666 \t\n"
]
for phrase in cases {
    let actual = try VaultCrypto.open(record, passphrase: phrase)
    guard actual.secret == expected else { fatalError("Known-answer vector mismatch for passphrase variant") }
}
print("Swift Tagcrypt v2 known-answer vectors passed (3 passphrase variants).")
