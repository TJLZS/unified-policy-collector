import unittest
from pathlib import Path

from policy_collector.config import load_yaml_config, target_from_mapping
from policy_collector.models import TargetType


class ConfigTests(unittest.TestCase):
    def test_yaml_style_mapping_builds_target_but_rejects_persisted_passwords(self):
        mapping = {
            "target": {
                "type": "security",
                "host": "10.0.0.30",
                "username": "collector",
                "security_device": "modsecurity",
            },
            "security_devices": {
                "modsecurity": {"paths": ["/srv/modsec/rules"]}
            },
        }

        target, configured_paths = target_from_mapping(mapping)

        self.assertEqual(target.target_type, TargetType.SECURITY)
        self.assertEqual(target.port, 22)
        self.assertEqual(configured_paths, ("/srv/modsec/rules",))

        mapping["target"]["password"] = "must-not-be-saved"
        with self.assertRaisesRegex(ValueError, "敏感"):
            target_from_mapping(mapping)

    def test_example_yaml_is_loadable_and_contains_no_credentials(self):
        path = Path(__file__).resolve().parents[1] / "config" / "targets.example.yaml"

        mapping = load_yaml_config(path)
        target, paths = target_from_mapping(mapping)

        self.assertEqual(target.security_device, "modsecurity")
        self.assertEqual(paths[0], "/etc/modsecurity")


if __name__ == "__main__":
    unittest.main()
