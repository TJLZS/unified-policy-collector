import unittest

from policy_collector.collectors import (
    LinuxCollector,
    SecurityDeviceCollector,
    WindowsCollector,
)
from policy_collector.factory import create_collector
from policy_collector.models import Credential, TargetConfig, TargetType


class CollectorFactoryTests(unittest.TestCase):
    def test_factory_routes_target_types_and_runtime_paths_win(self):
        credential = Credential(password="secret")
        linux = create_collector(
            TargetConfig(TargetType.LINUX, "10.0.0.1", 22, "root"),
            credential,
        )
        windows = create_collector(
            TargetConfig(TargetType.WINDOWS, "10.0.0.2", 5985, "Administrator"),
            credential,
        )
        security = create_collector(
            TargetConfig(
                TargetType.SECURITY,
                "10.0.0.3",
                22,
                "root",
                security_device="modsecurity",
                custom_paths=("/runtime/rules",),
            ),
            credential,
            configured_paths=("/configured/rules",),
        )

        self.assertIsInstance(linux, LinuxCollector)
        self.assertIsInstance(windows, WindowsCollector)
        self.assertIsInstance(security, SecurityDeviceCollector)
        self.assertEqual(security.adapter.paths, ("/runtime/rules",))

    def test_factory_builds_custom_docker_adapter_from_target(self):
        target = TargetConfig(
            TargetType.SECURITY,
            "10.0.0.88",
            22,
            "collector",
            security_device="custom",
            custom_paths=("/app/rules",),
            container_name="my-waf",
            custom_device_name="自研WAF",
            rule_file_type=".json",
            deployment_mode="docker",
        )

        collector = create_collector(target, Credential(password="secret"))

        self.assertIsInstance(collector, SecurityDeviceCollector)
        self.assertEqual(collector.adapter.key, "custom")
        self.assertEqual(collector.adapter.display_name, "自研WAF")
        self.assertEqual(collector.adapter.paths, ("/app/rules",))
        self.assertTrue(collector.adapter.docker)
        self.assertEqual(collector.adapter.rule_file_type, ".json")


if __name__ == "__main__":
    unittest.main()
