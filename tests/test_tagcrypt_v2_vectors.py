"""Cross-platform known-answer test for the published Tagcrypt v2 fixture."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from tagcrypt_v2_decrypt import decrypt_envelope, decode_text_record_value  # noqa: E402

VECTOR = (
    "VFZMVAIBAAknwAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGht82rRamc5CvvBFf4tU//ntlyjgAUTDoqPFgZ3oNjRpBOqd2T4OZ11kf0ewrn1twSW8hQ5tEp0pCsk5u+fiA6ndUQ=="
)
EXPECTED = "fixture-secret-not-a-real-credential"
COMPOSED = "Café Soho London 1666"
DECOMPOSED = "Cafe\u0301 Soho London 1666"


class TagcryptV2KnownAnswerTests(unittest.TestCase):
    def test_composed_passphrase(self):
        self.assertEqual(decrypt_envelope(decode_text_record_value(VECTOR.encode()), COMPOSED), EXPECTED)

    def test_decomposed_passphrase(self):
        self.assertEqual(decrypt_envelope(decode_text_record_value(VECTOR.encode()), DECOMPOSED), EXPECTED)

    def test_trailing_whitespace(self):
        self.assertEqual(decrypt_envelope(decode_text_record_value(VECTOR.encode()), COMPOSED + " \t\n"), EXPECTED)


if __name__ == "__main__":
    unittest.main()
