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


if __name__ == "__main__":
    unittest.main()
