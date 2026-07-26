import unittest

from policy_collector.security import redact_text


class RedactionTests(unittest.TestCase):
    def test_secrets_and_authorization_headers_are_redacted(self):
        text = (
            "password=Secret123\n"
            "Authorization: NTLM abcdef\n"
            "sudo command received Secret123"
        )

        redacted = redact_text(text, secrets=("Secret123",))

        self.assertNotIn("Secret123", redacted)
        self.assertNotIn("abcdef", redacted)
        self.assertIn("password=***", redacted)
        self.assertIn("Authorization: ***", redacted)


if __name__ == "__main__":
    unittest.main()
