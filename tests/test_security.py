import unittest
import json

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

    def test_json_and_space_containing_credentials_are_redacted(self):
        payload = json.dumps(
            {
                "username": "collector",
                "password": "Super Secret Value",
                "nested": {"access_token": "raw-token"},
            },
            ensure_ascii=False,
        )

        redacted_json = redact_text(payload)
        redacted_line = redact_text("password: my secret value\nnext=safe")

        self.assertNotIn("Super Secret Value", redacted_json)
        self.assertNotIn("raw-token", redacted_json)
        self.assertIn('"password": "***"', redacted_json)
        self.assertIn('"access_token": "***"', redacted_json)
        self.assertNotIn("my secret value", redacted_line)
        self.assertIn("password: ***", redacted_line)
        self.assertIn("next=safe", redacted_line)

    def test_embedded_and_truncated_json_credentials_are_redacted(self):
        embedded = (
            'prefix {"password":"SuperSecret",'
            '"Authorization":"Bearer embedded-token"} suffix'
        )
        truncated = '{"nested":{"access_token":"raw-token"'

        redacted_embedded = redact_text(embedded)
        redacted_truncated = redact_text(truncated)

        self.assertNotIn("SuperSecret", redacted_embedded)
        self.assertNotIn("embedded-token", redacted_embedded)
        self.assertIn('"password":"***"', redacted_embedded)
        self.assertIn('"Authorization":"***"', redacted_embedded)
        self.assertNotIn("raw-token", redacted_truncated)
        self.assertIn('"access_token":"***"', redacted_truncated)


if __name__ == "__main__":
    unittest.main()
