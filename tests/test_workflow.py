import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from policy_collector.models import (
    CollectionStatus,
    Credential,
    ModuleResult,
    TargetConfig,
    TargetType,
)
from policy_collector.orchestrator import CollectionOrchestrator


class _FakeCollector:
    def check(self):
        return {"connected": True, "capabilities": ["python3"]}

    def collect(self, output_dir: Path):
        (output_dir / "evidence.txt").write_text("collected", encoding="utf-8")
        return [
            ModuleResult(name="firewall", success=True, return_code=0),
            ModuleResult(name="audit", success=False, return_code=2),
        ]

    def cleanup(self):
        return True


class _FailingCollector(_FakeCollector):
    def collect(self, output_dir: Path):
        raise RuntimeError("authentication failed for DoNotPersistThis")


class WorkflowTests(unittest.TestCase):
    def test_partial_collection_writes_secret_free_summary_and_cleans_up(self):
        target = TargetConfig(
            target_type=TargetType.LINUX,
            host="10.10.10.8",
            port=22,
            username="root",
        )
        credential = Credential(password="DoNotPersistThis")
        fixed_now = datetime(2026, 7, 26, 15, 30, tzinfo=timezone.utc)

        with tempfile.TemporaryDirectory() as temp:
            orchestrator = CollectionOrchestrator(
                collector_factory=lambda _target, _credential: _FakeCollector(),
                clock=lambda: fixed_now,
            )
            report = orchestrator.collect(
                target,
                credential,
                output_root=Path(temp),
            )

            self.assertEqual(report.status, CollectionStatus.PARTIAL)
            self.assertTrue(report.cleanup_succeeded)
            summary_text = (report.run_dir / "collection_summary.json").read_text(
                encoding="utf-8"
            )
            summary = json.loads(summary_text)
            self.assertEqual(summary["status"], "partial")
            self.assertNotIn("DoNotPersistThis", summary_text)
            log_text = (report.run_dir / "execution.log").read_text(encoding="utf-8")
            self.assertNotIn("DoNotPersistThis", log_text)
            self.assertIn("采集完成", log_text)
            self.assertTrue((report.run_dir / "data" / "evidence.txt").exists())

    def test_failure_summary_redacts_secret_from_exception(self):
        target = TargetConfig(
            target_type=TargetType.LINUX,
            host="10.10.10.8",
            port=22,
            username="root",
        )
        credential = Credential(password="DoNotPersistThis")

        with tempfile.TemporaryDirectory() as temp:
            orchestrator = CollectionOrchestrator(
                collector_factory=lambda _target, _credential: _FailingCollector()
            )
            report = orchestrator.collect(
                target,
                credential,
                output_root=Path(temp),
            )

            summary_text = (report.run_dir / "collection_summary.json").read_text(
                encoding="utf-8"
            )
            self.assertNotIn("DoNotPersistThis", summary_text)
            self.assertIn("***", summary_text)


if __name__ == "__main__":
    unittest.main()
