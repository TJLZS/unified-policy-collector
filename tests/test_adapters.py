import unittest

from policy_collector.adapters import default_registry


class SecurityAdapterTests(unittest.TestCase):
    def test_runtime_paths_override_yaml_and_builtin_defaults(self):
        registry = default_registry()

        builtin = registry.resolve("modsecurity")
        configured = registry.resolve(
            "modsecurity",
            configured_paths=("/srv/waf/rules",),
        )
        runtime = registry.resolve(
            "modsecurity",
            configured_paths=("/srv/waf/rules",),
            runtime_paths=("/tmp/demo-rules",),
        )

        self.assertIn("/etc/modsecurity", builtin.paths)
        self.assertEqual(configured.paths, ("/srv/waf/rules",))
        self.assertEqual(runtime.paths, ("/tmp/demo-rules",))
        self.assertEqual(
            set(registry.keys()),
            {
                "suricata",
                "snort",
                "modsecurity",
                "zeek",
                "nuclei",
                "bt_waf",
                "uuwaf",
            },
        )


if __name__ == "__main__":
    unittest.main()
