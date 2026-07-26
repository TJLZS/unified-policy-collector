import unittest

from policy_collector.models import Credential, TargetConfig, TargetType


class TargetConfigTests(unittest.TestCase):
    def test_target_description_excludes_credentials_and_validates_port(self):
        target = TargetConfig(
            target_type=TargetType.LINUX,
            host="192.168.10.20",
            port=22,
            username="collector",
        )

        self.assertEqual(
            target.public_description(),
            {
                "target_type": "linux",
                "target_ip": "192.168.10.20",
                "port": 22,
                "username": "collector",
            },
        )

        with self.assertRaisesRegex(ValueError, "端口"):
            TargetConfig(
                target_type=TargetType.LINUX,
                host="192.168.10.20",
                port=70000,
                username="collector",
            )

    def test_credentials_are_not_exposed_by_repr(self):
        credential = Credential(
            password="LoginSecret!",
            sudo_password="SudoSecret!",
        )

        rendered = repr(credential)
        self.assertNotIn("LoginSecret!", rendered)
        self.assertNotIn("SudoSecret!", rendered)


if __name__ == "__main__":
    unittest.main()
