import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

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

    def _write_historical_run(self):
        run_dir = (
            Path(self.temp.name)
            / "windows"
            / "10.0.0.9"
            / "20260726_120000_000000"
        )
        run_dir.mkdir(parents=True)
        summary = {
            "target_type": "windows",
            "target_ip": "10.0.0.9",
            "port": 5985,
            "username": "Administrator",
            "started_at": "2026-07-26T12:00:00+00:00",
            "finished_at": "2026-07-26T12:01:00+00:00",
            "status": "partial",
            "successful_modules": ["Get-FirewallRules"],
            "failed_modules": ["Get-LAPSSettings"],
            "modules": [
                {
                    "name": "Get-FirewallRules",
                    "success": True,
                    "return_code": 0,
                    "message": "",
                },
                {
                    "name": "Get-LAPSSettings",
                    "success": False,
                    "return_code": 1,
                    "message": "not recognized as the name of a cmdlet",
                },
            ],
            "error": None,
            "cleanup_succeeded": True,
        }
        (run_dir / "collection_summary.json").write_text(
            json.dumps(summary),
            encoding="utf-8",
        )
        return run_dir

    def _write_history_runs(self, count):
        for index in range(count):
            target_type = "linux" if index % 2 == 0 else "windows"
            succeeded = target_type == "linux"
            module_name = "Firewall" if succeeded else "Get-FirewallRules"
            run_dir = (
                Path(self.temp.name)
                / target_type
                / f"10.0.0.{index + 1}"
                / f"20260728_12{index:04d}_000000"
            )
            run_dir.mkdir(parents=True)
            summary = {
                "target_type": target_type,
                "target_ip": f"10.0.0.{index + 1}",
                "port": 22 if target_type == "linux" else 5985,
                "username": "collector",
                "started_at": f"2026-07-28T12:{index:02d}:00+00:00",
                "finished_at": f"2026-07-28T12:{index:02d}:10+00:00",
                "status": "success" if succeeded else "failed",
                "successful_modules": [module_name] if succeeded else [],
                "failed_modules": [] if succeeded else [module_name],
                "modules": [
                    {
                        "name": module_name,
                        "success": succeeded,
                        "return_code": 0 if succeeded else 1,
                        "message": "" if succeeded else "Access is denied",
                    }
                ],
                "error": None,
                "cleanup_succeeded": True,
            }
            (run_dir / "collection_summary.json").write_text(
                json.dumps(summary),
                encoding="utf-8",
            )

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
        devices = meta.json()["security_devices"]
        self.assertEqual(len(devices), 8)
        self.assertEqual(devices[-1]["key"], "custom")
        self.assertTrue(devices[-1]["custom"])

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
        self.assertIn("自定义安全设备", response.text)
        self.assertIn("规则文件类型", response.text)
        self.assertIn("部署方式", response.text)
        self.assertIn("custom-container-name", response.text)
        self.assertIn("请填写目标宿主机上正在运行的准确容器名称", response.text)
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

    def test_user_can_submit_a_custom_host_security_device(self):
        response = self.client.post(
            "/api/jobs",
            json={
                "action": "check",
                "target_type": "security",
                "security_device": "custom",
                "custom_device_name": "自研检测设备",
                "rule_file_type": "rules",
                "deployment_mode": "host",
                "custom_paths": ["/opt/my-device/rules"],
                "host": "10.0.0.88",
                "username": "collector",
                "password": "secret",
            },
        )

        self.assertEqual(response.status_code, 202)
        self._wait_for_job(response.json()["id"])
        target = self.targets[-1]
        self.assertEqual(target.security_device, "custom")
        self.assertEqual(target.custom_device_name, "自研检测设备")
        self.assertEqual(target.rule_file_type, ".rules")
        self.assertEqual(target.deployment_mode, "host")
        self.assertEqual(target.custom_paths, ("/opt/my-device/rules",))

    def test_custom_security_device_rejects_missing_container_and_invalid_type(self):
        base = {
            "action": "check",
            "target_type": "security",
            "security_device": "custom",
            "custom_device_name": "自研WAF",
            "deployment_mode": "docker",
            "custom_paths": ["/app/rules"],
            "host": "10.0.0.88",
            "username": "collector",
            "password": "secret",
        }

        missing_container = self.client.post(
            "/api/jobs",
            json={**base, "rule_file_type": ".json"},
        )
        invalid_type = self.client.post(
            "/api/jobs",
            json={
                **base,
                "container_name": "my-waf",
                "rule_file_type": "../../etc/passwd",
            },
        )
        invalid_path = self.client.post(
            "/api/jobs",
            json={
                **base,
                "container_name": "my-waf",
                "rule_file_type": ".rules",
                "custom_paths": ["relative/rules"],
            },
        )

        self.assertEqual(missing_container.status_code, 422)
        self.assertIn("容器名称", missing_container.text)
        self.assertEqual(invalid_type.status_code, 422)
        self.assertIn("规则文件类型", invalid_type.text)
        self.assertEqual(invalid_path.status_code, 422)
        self.assertIn("绝对路径", invalid_path.text)
        self.assertNotIn(
            "secret",
            missing_container.text + invalid_type.text + invalid_path.text,
        )

    def test_runs_api_returns_opaque_id_dual_status_and_counts(self):
        self._write_historical_run()

        response = self.client.get("/api/runs")

        self.assertEqual(response.status_code, 200)
        run = response.json()[0]
        self.assertEqual(len(run["run_id"]), 64)
        self.assertNotIn("/", run["run_id"])
        self.assertEqual(run["collection_status"], "partial")
        self.assertEqual(run["assessment_status"], "success")
        self.assertEqual(run["counts"]["success"], 1)
        self.assertEqual(run["counts"]["not_applicable"], 1)

    def test_history_api_paginates_all_collection_records(self):
        self._write_history_runs(13)

        response = self.client.get("/api/history?page=2&page_size=5")

        self.assertEqual(response.status_code, 200)
        history = response.json()
        self.assertEqual(history["page"], 2)
        self.assertEqual(history["page_size"], 5)
        self.assertEqual(history["total"], 13)
        self.assertEqual(history["pages"], 3)
        self.assertEqual(len(history["items"]), 5)
        self.assertTrue(
            all(len(item["run_id"]) == 64 for item in history["items"])
        )

    def test_history_api_still_loads_when_old_run_directory_is_read_only(self):
        self._write_historical_run()
        original_write_text = Path.write_text

        def deny_analysis_report_write(path, *args, **kwargs):
            if path.name.startswith(".analysis_report.json."):
                raise PermissionError("只读历史结果目录")
            return original_write_text(path, *args, **kwargs)

        tolerant_client = TestClient(
            self.client.app,
            raise_server_exceptions=False,
        )
        try:
            with mock.patch.object(
                Path,
                "write_text",
                deny_analysis_report_write,
            ):
                response = tolerant_client.get("/api/history")
        finally:
            tolerant_client.close()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["total"], 1)

    def test_history_api_filters_by_type_ip_and_effective_status(self):
        self._write_history_runs(6)

        response = self.client.get(
            "/api/history",
            params={
                "target_type": "windows",
                "target_ip": "10.0.0.4",
                "status": "failed",
            },
        )

        self.assertEqual(response.status_code, 200)
        history = response.json()
        self.assertEqual(history["total"], 1)
        self.assertEqual(len(history["items"]), 1)
        self.assertEqual(history["items"][0]["target_type"], "windows")
        self.assertEqual(history["items"][0]["target_ip"], "10.0.0.4")
        self.assertEqual(history["items"][0]["assessment_status"], "failed")

    def test_history_api_clamps_page_and_hides_server_paths(self):
        self._write_history_runs(13)

        response = self.client.get("/api/history?page=99&page_size=5")

        self.assertEqual(response.status_code, 200)
        history = response.json()
        self.assertEqual(history["page"], 3)
        self.assertEqual(history["pages"], 3)
        self.assertEqual(len(history["items"]), 3)
        self.assertTrue(
            all("run_dir" not in item for item in history["items"])
        )

    def test_run_detail_and_report_download_use_run_id_not_paths(self):
        self._write_historical_run()
        run_id = self.client.get("/api/runs").json()[0]["run_id"]

        detail = self.client.get(f"/api/runs/{run_id}")
        report = self.client.get(f"/api/runs/{run_id}/report")

        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.json()["run_id"], run_id)
        self.assertEqual(detail.json()["assessment_status"], "success")
        self.assertEqual(report.status_code, 200)
        self.assertIn(
            "attachment",
            report.headers["content-disposition"],
        )
        self.assertEqual(report.json()["run_id"], run_id)

    def test_unknown_or_path_like_run_id_is_rejected(self):
        self._write_historical_run()

        unknown = self.client.get("/api/runs/not-a-real-run")
        path_like = self.client.get("/api/runs/%2E%2E%2Fcollection_summary.json")

        self.assertEqual(unknown.status_code, 404)
        self.assertEqual(path_like.status_code, 404)
        self.assertNotIn("collection_summary", unknown.text)

    def test_analysis_detail_page_is_served_without_resolving_a_client_path(self):
        response = self.client.get("/runs/not-a-real-run")

        self.assertEqual(response.status_code, 200)
        self.assertIn("采集结果分析", response.text)
        self.assertIn("analysis.js", response.text)

    def test_history_page_and_home_entry_are_served(self):
        home = self.client.get("/")
        history = self.client.get("/history")
        script = self.client.get("/assets/history.js")

        self.assertEqual(home.status_code, 200)
        self.assertIn('href="/history"', home.text)
        self.assertIn("查看全部历史", home.text)
        self.assertEqual(history.status_code, 200)
        self.assertIn("历史采集结果", history.text)
        self.assertIn("history-target-type", history.text)
        self.assertIn("history-target-ip", history.text)
        self.assertIn("history-status", history.text)
        self.assertIn("history.js", history.text)
        self.assertIn("返回采集首页", history.text)
        self.assertEqual(script.status_code, 200)
        self.assertIn("/api/history", script.text)
        self.assertIn("/runs/", script.text)

    def test_web_assets_render_dual_status_filters_and_escaped_evidence(self):
        home_script = self.client.get("/assets/app.js")
        analysis_script = self.client.get("/assets/analysis.js")

        self.assertEqual(home_script.status_code, 200)
        self.assertIn("assessment_status", home_script.text)
        self.assertIn("查看分析", home_script.text)
        self.assertIn("/runs/", home_script.text)
        self.assertIn("escapeHtml(formatTime(run.started_at))", home_script.text)
        self.assertEqual(analysis_script.status_code, 200)
        self.assertIn("module-search", analysis_script.text)
        self.assertIn("status-filter", analysis_script.text)
        self.assertIn("evidence_excerpt", analysis_script.text)
        self.assertIn("escapeHtml", analysis_script.text)

    def test_web_assets_submit_custom_security_device_fields(self):
        script = self.client.get("/assets/app.js")

        self.assertEqual(script.status_code, 200)
        self.assertIn("custom_device_name", script.text)
        self.assertIn("rule_file_type", script.text)
        self.assertIn("deployment_mode", script.text)
        self.assertIn("custom-security-fields", script.text)


if __name__ == "__main__":
    unittest.main()
