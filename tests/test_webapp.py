import json
import tempfile
import time
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from policy_collector.models import ModuleResult
from policy_collector.webapp import JobService, create_app


class _WebFakeCollector:
    def check(self):
        return {"connected": True, "transport": "fake"}

    def collect(self, output_dir: Path):
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "policy.txt").write_text("allow", encoding="utf-8")
        return [ModuleResult(name="firewall", success=True, return_code=0)]

    def cleanup(self):
        return True


class WebAppTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.targets = []

        def collector_factory(target, _credential):
            self.targets.append(target)
            return _WebFakeCollector()

        service = JobService(
            collector_factory=collector_factory,
            output_root=Path(self.temp.name),
        )
        self.client = TestClient(create_app(service))

    def tearDown(self):
        self.client.close()
        self.temp.cleanup()

    def _wait_for_job(self, job_id):
        for _ in range(100):
            response = self.client.get(f"/api/jobs/{job_id}")
            self.assertEqual(response.status_code, 200)
            job = response.json()
            if job["state"] == "completed":
                return job
            time.sleep(0.01)
        self.fail("Web任务未在预期时间内完成")

    def test_check_job_never_exposes_or_persists_password(self):
        secret = "NeverPersistThis!"
        response = self.client.post(
            "/api/jobs",
            json={
                "action": "check",
                "target_type": "linux",
                "host": "10.0.0.8",
                "port": 22,
                "username": "collector",
                "password": secret,
            },
        )

        self.assertEqual(response.status_code, 202)
        job = self._wait_for_job(response.json()["id"])
        rendered = json.dumps(job, ensure_ascii=False)
        self.assertEqual(job["status"], "success")
        self.assertNotIn(secret, rendered)
        self.assertNotIn("password", rendered.lower())
        self.assertEqual(job["result"]["transport"], "fake")

    def test_collect_job_returns_summary_and_result_directory(self):
        response = self.client.post(
            "/api/jobs",
            json={
                "action": "collect",
                "target_type": "windows",
                "host": "10.0.0.9",
                "port": 5985,
                "username": "Administrator",
                "password": "secret",
            },
        )

        job = self._wait_for_job(response.json()["id"])

        self.assertEqual(job["status"], "success")
        self.assertIn("run_dir", job["result"])
        summary = Path(job["result"]["run_dir"]) / "collection_summary.json"
        self.assertTrue(summary.exists())

    def test_meta_lists_all_security_adapters_and_rejects_invalid_target(self):
        meta = self.client.get("/api/meta")
        self.assertEqual(meta.status_code, 200)
        self.assertEqual(len(meta.json()["security_devices"]), 7)

        response = self.client.post(
            "/api/jobs",
            json={
                "action": "collect",
                "target_type": "security",
                "host": "10.0.0.10",
                "username": "root",
                "password": "secret",
            },
        )
        self.assertEqual(response.status_code, 422)
        self.assertNotIn("secret", response.text)

    def test_home_page_contains_collection_controls(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn("统一安全策略采集", response.text)
        self.assertIn("开始采集", response.text)
        self.assertIn("使用默认规则路径", response.text)
        self.assertIn("修改路径", response.text)
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")
        self.assertIn("frame-ancestors 'none'", response.headers["content-security-policy"])

    def test_security_paths_use_defaults_until_explicitly_overridden(self):
        default_response = self.client.post(
            "/api/jobs",
            json={
                "action": "check",
                "target_type": "security",
                "security_device": "suricata",
                "host": "10.0.0.10",
                "username": "root",
                "password": "secret",
                "custom_paths": [],
            },
        )
        self._wait_for_job(default_response.json()["id"])
        self.assertEqual(self.targets[-1].custom_paths, ())

        custom_response = self.client.post(
            "/api/jobs",
            json={
                "action": "check",
                "target_type": "security",
                "security_device": "suricata",
                "host": "10.0.0.10",
                "username": "root",
                "password": "secret",
                "custom_paths": ["/srv/suricata/rules", "/data/local.rules"],
            },
        )
        self._wait_for_job(custom_response.json()["id"])
        self.assertEqual(
            self.targets[-1].custom_paths,
            ("/srv/suricata/rules", "/data/local.rules"),
        )


if __name__ == "__main__":
    unittest.main()
