import json
import os
import tempfile
import unittest
from pathlib import Path

from policy_collector.analysis import ResultAnalysisService


class ResultAnalysisServiceTests(unittest.TestCase):
    def _write_run(
        self,
        output_root,
        *,
        target_type,
        modules,
        manifest=None,
        status="partial",
        error=None,
        cleanup_succeeded=True,
        security_device=None,
        custom_device_name=None,
        rule_file_type=None,
        deployment_mode=None,
    ):
        run_dir = (
            output_root
            / target_type
            / "10.0.0.9"
            / "20260726_120000_000000"
        )
        data_dir = run_dir / "data"
        data_dir.mkdir(parents=True)
        summary = {
            "target_type": target_type,
            "target_ip": "10.0.0.9",
            "port": 5985 if target_type == "windows" else 22,
            "username": "collector",
            "security_device": security_device,
            "custom_device_name": custom_device_name,
            "rule_file_type": rule_file_type,
            "deployment_mode": deployment_mode,
            "started_at": "2026-07-26T12:00:00+00:00",
            "finished_at": "2026-07-26T12:01:00+00:00",
            "status": status,
            "successful_modules": [
                item["name"] for item in modules if item.get("success")
            ],
            "failed_modules": [
                item["name"] for item in modules if not item.get("success")
            ],
            "modules": modules,
            "error": error,
            "cleanup_succeeded": cleanup_succeeded,
            "check_details": {"connected": True},
        }
        summary_path = run_dir / "collection_summary.json"
        summary_path.write_text(
            json.dumps(summary, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        if manifest is not None:
            (data_dir / "collection_manifest.json").write_text(
                json.dumps(manifest, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        return run_dir, summary_path

    def _analyze_only_run(self, output_root):
        service = ResultAnalysisService(output_root)
        listed = service.list_runs()
        self.assertEqual(len(listed), 1)
        return service.analyze(listed[0]["run_id"])

    def test_custom_security_metadata_is_preserved_in_analysis_report(self):
        with tempfile.TemporaryDirectory() as temp:
            output_root = Path(temp)
            modules = [
                {
                    "name": "custom:path:/opt/acme/rules",
                    "success": True,
                    "return_code": 0,
                    "message": "规则路径采集成功",
                    "path_mode": "custom",
                }
            ]
            self._write_run(
                output_root,
                target_type="security",
                modules=modules,
                manifest=modules,
                status="success",
                security_device="custom",
                custom_device_name="自研WAF",
                rule_file_type=".rules",
                deployment_mode="host",
            )

            analysis = self._analyze_only_run(output_root)

            self.assertEqual(analysis["target"]["custom_device_name"], "自研WAF")
            self.assertEqual(analysis["target"]["rule_file_type"], ".rules")
            self.assertEqual(analysis["target"]["deployment_mode"], "host")

    def test_historical_windows_run_marks_absent_laps_not_applicable(self):
        with tempfile.TemporaryDirectory() as temp:
            output_root = Path(temp)
            modules = [
                {
                    "name": "Get-FirewallRules",
                    "success": True,
                    "return_code": 0,
                    "message": "",
                },
                {
                    "name": "Get-LAPSOperationalLogs",
                    "success": False,
                    "return_code": 1,
                    "message": "脚本返回非零状态码 1",
                },
            ]
            manifest = [
                {
                    **modules[0],
                    "output_file": "Protect-Update\\Get-FirewallRules.txt",
                },
                {
                    **modules[1],
                    "output_file": "Encryption\\Get-LAPSOperationalLogs.txt",
                },
            ]
            run_dir, summary_path = self._write_run(
                output_root,
                target_type="windows",
                modules=modules,
                manifest=manifest,
            )
            original_summary = summary_path.read_text(encoding="utf-8")
            data_dir = run_dir / "data" / "Encryption"
            data_dir.mkdir(parents=True)
            (data_dir / "Get-LAPSOperationalLogs.txt").write_text(
                "[ERROR] The specified channel could not be found.\nRETURN_CODE=1",
                encoding="utf-8",
            )

            analysis = self._analyze_only_run(output_root)

            items = {item["name"]: item for item in analysis["items"]}
            self.assertEqual(analysis["collection_status"], "partial")
            self.assertEqual(analysis["assessment_status"], "success")
            self.assertEqual(
                items["Get-LAPSOperationalLogs"]["status"],
                "not_applicable",
            )
            self.assertEqual(
                items["Get-LAPSOperationalLogs"]["reason_code"],
                "feature_absent",
            )
            self.assertIn(
                "未安装或未启用",
                items["Get-LAPSOperationalLogs"]["reason"],
            )
            self.assertTrue((run_dir / "analysis_report.json").exists())
            self.assertEqual(
                summary_path.read_text(encoding="utf-8"),
                original_summary,
            )

    def test_permission_denied_is_failed_and_evidence_is_redacted(self):
        with tempfile.TemporaryDirectory() as temp:
            output_root = Path(temp)
            modules = [
                {"name": "Firewall", "success": True, "return_code": 0},
                {
                    "name": "ACL",
                    "success": False,
                    "return_code": 1,
                    "message": "permission denied password=SuperSecret",
                    "output_dir": "Linux_acl_config",
                },
            ]
            run_dir, _ = self._write_run(
                output_root,
                target_type="linux",
                modules=modules,
                manifest=modules,
            )
            evidence_dir = run_dir / "data" / "Linux_acl_config"
            evidence_dir.mkdir()
            (evidence_dir / "acl.log").write_text(
                "ERROR permission denied Authorization: Bearer raw-token",
                encoding="utf-8",
            )

            analysis = self._analyze_only_run(output_root)
            items = {item["name"]: item for item in analysis["items"]}

            self.assertEqual(analysis["assessment_status"], "partial")
            self.assertEqual(items["ACL"]["status"], "failed")
            self.assertEqual(items["ACL"]["reason_code"], "permission_denied")
            self.assertIn("权限", items["ACL"]["reason"])
            rendered = json.dumps(items["ACL"], ensure_ascii=False)
            self.assertNotIn("SuperSecret", rendered)
            self.assertNotIn("raw-token", rendered)

    def test_linux_optional_missing_is_not_applicable_but_baseline_missing_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            output_root = Path(temp)
            modules = [
                {
                    "name": "User_identity",
                    "success": True,
                    "return_code": 0,
                },
                {
                    "name": "Nginx",
                    "success": False,
                    "return_code": 127,
                    "message": "nginx: command not found",
                },
                {
                    "name": "Firewall",
                    "success": False,
                    "return_code": 127,
                    "message": "iptables: command not found",
                },
            ]
            self._write_run(
                output_root,
                target_type="linux",
                modules=modules,
                manifest=modules,
            )

            analysis = self._analyze_only_run(output_root)
            items = {item["name"]: item for item in analysis["items"]}

            self.assertEqual(analysis["assessment_status"], "partial")
            self.assertEqual(items["Nginx"]["status"], "not_applicable")
            self.assertEqual(items["Nginx"]["reason_code"], "feature_absent")
            self.assertEqual(items["Firewall"]["status"], "failed")
            self.assertEqual(
                items["Firewall"]["reason_code"],
                "dependency_missing",
            )

    def test_security_default_candidate_missing_is_not_applicable_when_one_hits(self):
        with tempfile.TemporaryDirectory() as temp:
            output_root = Path(temp)
            modules = [
                {
                    "name": "suricata:rules",
                    "success": True,
                    "return_code": 0,
                    "message": "/etc/suricata/rules",
                    "path_mode": "default",
                },
                {
                    "name": "suricata:path:/var/lib/suricata/rules",
                    "success": False,
                    "return_code": 1,
                    "message": "规则路径不存在: /var/lib/suricata/rules",
                    "path_mode": "default",
                },
            ]
            self._write_run(
                output_root,
                target_type="security",
                modules=modules,
                manifest=modules,
                security_device="suricata",
            )

            analysis = self._analyze_only_run(output_root)
            items = {item["name"]: item for item in analysis["items"]}

            self.assertEqual(analysis["assessment_status"], "success")
            self.assertEqual(
                items["suricata:path:/var/lib/suricata/rules"]["status"],
                "not_applicable",
            )

    def test_security_custom_path_missing_remains_failed(self):
        with tempfile.TemporaryDirectory() as temp:
            output_root = Path(temp)
            modules = [
                {
                    "name": "suricata:path:/srv/custom.rules",
                    "success": False,
                    "return_code": 1,
                    "message": "规则路径不存在: /srv/custom.rules",
                    "path_mode": "custom",
                },
            ]
            self._write_run(
                output_root,
                target_type="security",
                modules=modules,
                manifest=modules,
                status="failed",
                security_device="suricata",
            )

            analysis = self._analyze_only_run(output_root)
            item = analysis["items"][0]

            self.assertEqual(analysis["assessment_status"], "failed")
            self.assertEqual(item["status"], "failed")
            self.assertEqual(item["reason_code"], "path_missing")

    def test_waf_container_ambiguity_and_cleanup_failure_are_reported(self):
        with tempfile.TemporaryDirectory() as temp:
            output_root = Path(temp)
            modules = [
                {
                    "name": "waf:container",
                    "success": False,
                    "return_code": 1,
                    "message": "匹配到多个WAF容器，请指定容器名称",
                },
                {
                    "name": "remote_cleanup",
                    "success": False,
                    "return_code": None,
                    "message": "远端临时目录清理失败",
                },
            ]
            self._write_run(
                output_root,
                target_type="security",
                modules=modules,
                manifest=modules,
                status="failed",
                cleanup_succeeded=False,
                security_device="bt_waf",
            )

            analysis = self._analyze_only_run(output_root)
            items = {item["name"]: item for item in analysis["items"]}

            self.assertEqual(items["waf:container"]["reason_code"], "container_ambiguous")
            self.assertEqual(items["remote_cleanup"]["reason_code"], "cleanup_failed")
            self.assertEqual(analysis["assessment_status"], "failed")

    def test_custom_container_not_found_uses_security_device_reason(self):
        with tempfile.TemporaryDirectory() as temp:
            output_root = Path(temp)
            modules = [
                {
                    "name": "custom:container",
                    "success": False,
                    "return_code": 1,
                    "message": "未找到指定的安全设备容器；当前容器: other",
                }
            ]
            self._write_run(
                output_root,
                target_type="security",
                modules=modules,
                manifest=modules,
                status="failed",
                security_device="custom",
                custom_device_name="自研IDS",
                rule_file_type=".yaml",
                deployment_mode="docker",
            )

            analysis = self._analyze_only_run(output_root)

            self.assertEqual(
                analysis["items"][0]["reason_code"],
                "container_not_found",
            )
            self.assertIn(
                "安全设备容器",
                analysis["items"][0]["reason"],
            )
            self.assertNotIn(
                "WAF",
                " ".join(analysis["items"][0]["recommendations"]),
            )

    def test_cleanup_failure_downgrades_otherwise_successful_run(self):
        with tempfile.TemporaryDirectory() as temp:
            output_root = Path(temp)
            modules = [
                {"name": "Firewall", "success": True, "return_code": 0},
                {
                    "name": "remote_cleanup",
                    "success": False,
                    "return_code": None,
                    "message": "远端临时目录清理失败",
                },
            ]
            self._write_run(
                output_root,
                target_type="linux",
                modules=modules,
                manifest=modules,
                cleanup_succeeded=False,
            )

            analysis = self._analyze_only_run(output_root)

            self.assertEqual(analysis["assessment_status"], "partial")
            self.assertEqual(analysis["counts"]["failed"], 1)

    def test_waf_fixed_rule_path_missing_is_failed_even_if_another_path_succeeds(self):
        with tempfile.TemporaryDirectory() as temp:
            output_root = Path(temp)
            modules = [
                {
                    "name": "bt_waf:rules",
                    "success": True,
                    "return_code": 0,
                    "message": "已采集1个路径",
                    "path_mode": "default",
                },
                {
                    "name": "bt_waf:path_error_1",
                    "success": False,
                    "return_code": 2,
                    "message": "容器路径采集失败 /fixed/rules: no such file",
                    "path_mode": "default",
                },
            ]
            self._write_run(
                output_root,
                target_type="security",
                modules=modules,
                manifest=modules,
                security_device="bt_waf",
            )

            analysis = self._analyze_only_run(output_root)
            items = {item["name"]: item for item in analysis["items"]}

            self.assertEqual(analysis["assessment_status"], "partial")
            self.assertEqual(items["bt_waf:path_error_1"]["status"], "failed")
            self.assertEqual(
                items["bt_waf:path_error_1"]["reason_code"],
                "path_missing",
            )

    def test_unknown_failure_is_conservatively_failed(self):
        with tempfile.TemporaryDirectory() as temp:
            output_root = Path(temp)
            modules = [
                {
                    "name": "Get-SecurityServices",
                    "success": False,
                    "return_code": None,
                    "message": "",
                },
            ]
            self._write_run(
                output_root,
                target_type="windows",
                modules=modules,
                manifest=modules,
                status="failed",
            )

            analysis = self._analyze_only_run(output_root)
            item = analysis["items"][0]

            self.assertEqual(item["status"], "failed")
            self.assertEqual(item["reason_code"], "unknown_failure")
            self.assertIn("人工核查", item["reason"])

    def test_skipped_message_is_redacted(self):
        with tempfile.TemporaryDirectory() as temp:
            output_root = Path(temp)
            modules = [
                {
                    "name": "Docker",
                    "success": False,
                    "skipped": True,
                    "return_code": None,
                    "message": "本次跳过 token=SkipSecret",
                },
            ]
            self._write_run(
                output_root,
                target_type="linux",
                modules=modules,
                manifest=modules,
                status="failed",
            )

            analysis = self._analyze_only_run(output_root)
            rendered = json.dumps(analysis, ensure_ascii=False)

            self.assertEqual(analysis["items"][0]["status"], "skipped")
            self.assertNotIn("SkipSecret", rendered)

    def test_pipeline_error_is_included_when_only_cleanup_module_exists(self):
        with tempfile.TemporaryDirectory() as temp:
            output_root = Path(temp)
            modules = [
                {
                    "name": "remote_cleanup",
                    "success": False,
                    "return_code": None,
                    "message": "远端临时目录清理失败",
                },
            ]
            self._write_run(
                output_root,
                target_type="windows",
                modules=modules,
                manifest=modules,
                status="failed",
                error="WinRM上传文件分块失败: The command line is too long.",
                cleanup_succeeded=False,
            )

            analysis = self._analyze_only_run(output_root)
            items = {item["name"]: item for item in analysis["items"]}

            self.assertEqual(
                items["collection_pipeline"]["reason_code"],
                "transport_failed",
            )

    def test_pipeline_failure_forces_failed_even_when_a_module_succeeded(self):
        with tempfile.TemporaryDirectory() as temp:
            output_root = Path(temp)
            modules = [
                {"name": "Firewall", "success": True, "return_code": 0},
            ]
            self._write_run(
                output_root,
                target_type="linux",
                modules=modules,
                manifest=modules,
                status="failed",
                error="结果下载失败: connection reset",
            )

            analysis = self._analyze_only_run(output_root)

            self.assertEqual(analysis["counts"]["success"], 1)
            self.assertEqual(analysis["assessment_status"], "failed")

    def test_missing_cleanup_result_prevents_full_success(self):
        with tempfile.TemporaryDirectory() as temp:
            output_root = Path(temp)
            modules = [
                {"name": "Firewall", "success": True, "return_code": 0},
            ]
            run_dir, _ = self._write_run(
                output_root,
                target_type="linux",
                modules=modules,
                manifest=modules,
                status="success",
            )
            summary_path = run_dir / "collection_summary.json"
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            summary.pop("cleanup_succeeded")
            summary_path.write_text(json.dumps(summary), encoding="utf-8")

            analysis = self._analyze_only_run(output_root)
            items = {item["name"]: item for item in analysis["items"]}

            self.assertEqual(analysis["assessment_status"], "partial")
            self.assertEqual(items["remote_cleanup"]["reason_code"], "cleanup_failed")

    def test_manifest_cannot_select_evidence_outside_data_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            output_root = Path(temp)
            modules = [
                {
                    "name": "Get-EventsLog-Security",
                    "success": False,
                    "return_code": 1,
                    "message": "脚本返回非零状态码 1",
                },
            ]
            manifest = [
                {
                    **modules[0],
                    "output_file": "../execution.log",
                }
            ]
            run_dir, _ = self._write_run(
                output_root,
                target_type="windows",
                modules=modules,
                manifest=manifest,
                status="failed",
            )
            (run_dir / "execution.log").write_text(
                "permission denied token=DoNotExpose",
                encoding="utf-8",
            )

            analysis = self._analyze_only_run(output_root)
            item = analysis["items"][0]

            self.assertEqual(
                item["evidence_excerpt"],
                "脚本返回非零状态码 1",
            )
            self.assertNotIn("DoNotExpose", json.dumps(analysis))

    def test_nested_evidence_symlink_cannot_escape_data_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            output_root = Path(temp) / "outputs"
            modules = [
                {
                    "name": "ACL",
                    "success": False,
                    "return_code": 1,
                    "message": "策略采集失败",
                    "output_dir": "Linux_acl_config",
                },
            ]
            run_dir, _ = self._write_run(
                output_root,
                target_type="linux",
                modules=modules,
                manifest=modules,
                status="failed",
            )
            evidence_dir = run_dir / "data" / "Linux_acl_config"
            evidence_dir.mkdir()
            outside = Path(temp) / "outside-secret.log"
            outside.write_text("token=OutsideSecret", encoding="utf-8")
            try:
                (evidence_dir / "leak.log").symlink_to(outside)
            except OSError as exc:
                self.skipTest(f"当前系统不允许创建测试符号链接: {exc}")

            analysis = self._analyze_only_run(output_root)
            rendered = json.dumps(analysis, ensure_ascii=False)

            self.assertNotIn("OutsideSecret", rendered)
            self.assertNotIn(str(outside), rendered)

    def test_report_is_rebuilt_when_source_evidence_changes(self):
        with tempfile.TemporaryDirectory() as temp:
            output_root = Path(temp)
            modules = [
                {
                    "name": "Get-LAPSSettings",
                    "success": False,
                    "return_code": 1,
                    "message": "脚本返回非零状态码 1",
                },
            ]
            manifest = [
                {
                    **modules[0],
                    "output_file": "Encryption/Get-LAPSSettings.txt",
                }
            ]
            run_dir, _ = self._write_run(
                output_root,
                target_type="windows",
                modules=modules,
                manifest=manifest,
            )
            evidence_dir = run_dir / "data" / "Encryption"
            evidence_dir.mkdir()
            evidence_path = evidence_dir / "Get-LAPSSettings.txt"
            evidence_path.write_text(
                "[ERROR] unknown failure",
                encoding="utf-8",
            )
            service = ResultAnalysisService(output_root)
            run_id = service.list_runs()[0]["run_id"]
            first = service.analyze(run_id)

            evidence_path.write_text(
                "[ERROR] not recognized as the name of a cmdlet",
                encoding="utf-8",
            )
            second = service.analyze(run_id)

            self.assertNotEqual(
                first["source_fingerprint"],
                second["source_fingerprint"],
            )
            self.assertEqual(
                second["items"][0]["status"],
                "not_applicable",
            )

    def test_fingerprint_detects_same_size_change_with_preserved_mtime(self):
        with tempfile.TemporaryDirectory() as temp:
            output_root = Path(temp)
            modules = [
                {
                    "name": "Get-LAPSSettings",
                    "success": False,
                    "return_code": 1,
                    "message": "脚本返回非零状态码 1",
                },
            ]
            manifest = [
                {
                    **modules[0],
                    "output_file": "Encryption/Get-LAPSSettings.txt",
                }
            ]
            run_dir, _ = self._write_run(
                output_root,
                target_type="windows",
                modules=modules,
                manifest=manifest,
            )
            evidence_dir = run_dir / "data" / "Encryption"
            evidence_dir.mkdir()
            evidence_path = evidence_dir / "Get-LAPSSettings.txt"
            evidence_path.write_text("command not found", encoding="utf-8")
            original_stat = evidence_path.stat()
            service = ResultAnalysisService(output_root)
            run_id = service.list_runs()[0]["run_id"]
            first = service.analyze(run_id)

            evidence_path.write_text("permission denied", encoding="utf-8")
            os.utime(
                evidence_path,
                ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns),
            )
            second = service.analyze(run_id)

            self.assertEqual(len("command not found"), len("permission denied"))
            self.assertNotEqual(
                first["source_fingerprint"],
                second["source_fingerprint"],
            )
            self.assertEqual(second["items"][0]["reason_code"], "permission_denied")

    def test_windows_error_1355_marks_domain_policy_not_applicable(self):
        with tempfile.TemporaryDirectory() as temp:
            output_root = Path(temp)
            modules = [
                {
                    "name": "Get-PasswordPolicy-Local",
                    "success": True,
                    "return_code": 0,
                    "message": "",
                },
                {
                    "name": "Get-PasswordPolicy-Domain",
                    "success": False,
                    "return_code": 2,
                    "message": "脚本返回非零状态码 2",
                },
            ]
            manifest = [
                {
                    **modules[0],
                    "output_file": "Users-Permissions/Get-PasswordPolicy-Local.txt",
                },
                {
                    **modules[1],
                    "output_file": "Users-Permissions/Get-PasswordPolicy-Domain.txt",
                },
            ]
            run_dir, _ = self._write_run(
                output_root,
                target_type="windows",
                modules=modules,
                manifest=manifest,
            )
            evidence_dir = run_dir / "data" / "Users-Permissions"
            evidence_dir.mkdir()
            (evidence_dir / "Get-PasswordPolicy-Domain.txt").write_text(
                "System error 1355 has occurred.\n"
                "The specified domain either does not exist or could not be contacted.",
                encoding="utf-8",
            )

            analysis = self._analyze_only_run(output_root)
            items = {item["name"]: item for item in analysis["items"]}

            self.assertEqual(analysis["assessment_status"], "success")
            self.assertEqual(
                items["Get-PasswordPolicy-Domain"]["reason_code"],
                "not_domain_joined",
            )


if __name__ == "__main__":
    unittest.main()
