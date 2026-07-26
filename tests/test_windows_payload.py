import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class WindowsPayloadTests(unittest.TestCase):
    def test_wrapper_covers_every_source_script_and_required_defaults(self):
        payload = PROJECT_ROOT / "payloads" / "windows"
        wrapper = payload / "Invoke-AllCollectors.ps1"
        text = wrapper.read_text(encoding="utf-8")
        source_scripts = sorted(
            path
            for path in payload.rglob("*.ps1")
            if path.name != wrapper.name
        )

        self.assertEqual(len(source_scripts), 17)
        for script in source_scripts:
            relative = str(script.relative_to(payload)).replace("/", "\\")
            self.assertIn(relative, text)
        self.assertIn("'-Scope', 'Local'", text)
        self.assertIn("'-Scope', 'Domain'", text)
        self.assertIn("'-Path', 'C:\\'", text)
        self.assertIn("'-LogName', 'Security', '-Count', 100", text)
        self.assertIn("'-Count', 50", text)
        self.assertIn("collection_manifest.json", text)


if __name__ == "__main__":
    unittest.main()
