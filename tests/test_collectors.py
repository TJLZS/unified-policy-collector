import io
import json
import os
import runpy
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from policy_collector.adapters import SecurityDeviceAdapter, default_registry
from policy_collector.collectors import (
    LinuxCollector,
    SecurityDeviceCollector,
    WindowsCollector,
)
from policy_collector.models import Credential, TargetConfig, TargetType
from policy_collector.transports import CommandResult


class _FakeSSHTransport:
    def __init__(self):
        self.commands = []
        self.uploaded = None
        self.closed = False

    def check(self):
        return {"connected": True, "python3": "3.10"}

    def run(self, command, *, sudo=False, sudo_password=None, timeout=300):
        self.commands.append(command)
        return CommandResult(return_code=0, stdout="ok", stderr="")

    def upload_tree(self, local_path, remote_path):
        self.uploaded = (Path(local_path), remote_path)

    def upload_file(self, local_path, remote_path):
        self.uploaded_file = (Path(local_path), remote_path)
        self.uploaded_file_content = Path(local_path).read_text(encoding="utf-8")

    def download_file(self, remote_path, local_path):
        with tarfile.open(local_path, "w:gz") as archive:
            content = b"firewall rules"
            info = tarfile.TarInfo("Linux_firewall_config/rules.txt")
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))

    def close(self):
        self.closed = True


class _MaliciousArchiveSSHTransport(_FakeSSHTransport):
    def download_file(self, remote_path, local_path):
        with tarfile.open(local_path, "w:gz") as archive:
            content = b"escape"
            info = tarfile.TarInfo("../outside.txt")
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))


class _PartialLinuxArchiveSSHTransport(_FakeSSHTransport):
    def run(self, command, *, sudo=False, sudo_password=None, timeout=300):
        self.commands.append(command)
        if "main.py" in command:
            return CommandResult(return_code=1, stdout="partial", stderr="")
        return CommandResult(return_code=0, stdout="ok", stderr="")

    def download_file(self, remote_path, local_path):
        manifest = json.dumps(
            [
                {"name": "firewall", "success": True, "return_code": 0},
                {"name": "audit", "success": False, "return_code": 1},
            ]
        ).encode("utf-8")
        with tarfile.open(local_path, "w:gz") as archive:
            info = tarfile.TarInfo("collection_manifest.json")
            info.size = len(manifest)
            archive.addfile(info, io.BytesIO(manifest))


class _FakeWinRMTransport:
    def __init__(self):
        self.scripts = []
        self.uploaded = None
        self.closed = False

    def check(self):
        return {"connected": True, "powershell": "5.1"}

    def run_ps(self, script):
        self.scripts.append(script)
        return CommandResult(return_code=0, stdout="ok", stderr="")

    def upload_tree(self, local_path, remote_path):
        self.uploaded = (Path(local_path), remote_path)

    def download_file(self, remote_path, local_path):
        manifest = (
            '[{"name":"Get-FirewallRules","success":true,"return_code":0},'
            '{"name":"Get-GPOs","success":false,"return_code":2}]'
        )
        with zipfile.ZipFile(local_path, "w") as archive:
            archive.writestr("collection_manifest.json", manifest)
            archive.writestr("Protect-Update/Get-FirewallRules.txt", "rules")

    def close(self):
        self.closed = True


class LinuxCollectorTests(unittest.TestCase):
    def test_cleanup_before_collection_only_closes_transport(self):
        target = TargetConfig(
            target_type=TargetType.LINUX,
            host="10.0.0.8",
            port=22,
            username="root",
        )
        transport = _FakeSSHTransport()
        collector = LinuxCollector(
            target,
            Credential(password="secret"),
            transport=transport,
        )

        self.assertTrue(collector.cleanup())
        self.assertTrue(transport.closed)
        self.assertFalse(any("rm -rf" in command for command in transport.commands))

    def test_linux_collection_delivers_extracted_results(self):
        target = TargetConfig(
            target_type=TargetType.LINUX,
            host="10.0.0.8",
            port=22,
            username="root",
        )
        transport = _FakeSSHTransport()

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            payload = root / "payload"
            payload.mkdir()
            (payload / "main.py").write_text("print('payload')", encoding="utf-8")
            output = root / "output"
            output.mkdir()
            collector = LinuxCollector(
                target,
                Credential(password="secret"),
                transport=transport,
                payload_root=payload,
            )

            results = collector.collect(output)

            self.assertTrue(results[0].success)
            self.assertTrue(
                (output / "Linux_firewall_config" / "rules.txt").exists()
            )
            self.assertIsNotNone(transport.uploaded)
            self.assertTrue(any("--all --output" in cmd for cmd in transport.commands))

    def test_linux_collection_rejects_archive_path_traversal(self):
        target = TargetConfig(
            target_type=TargetType.LINUX,
            host="10.0.0.8",
            port=22,
            username="root",
        )

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            payload = root / "payload"
            payload.mkdir()
            (payload / "main.py").write_text("print('payload')", encoding="utf-8")
            output = root / "output"
            output.mkdir()
            collector = LinuxCollector(
                target,
                Credential(password="secret"),
                transport=_MaliciousArchiveSSHTransport(),
                payload_root=payload,
            )

            with self.assertRaisesRegex(Exception, "不安全路径"):
                collector.collect(output)
            self.assertFalse((root / "outside.txt").exists())

    def test_linux_collection_uses_strategy_manifest_for_partial_results(self):
        target = TargetConfig(
            target_type=TargetType.LINUX,
            host="10.0.0.8",
            port=22,
            username="root",
        )

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            payload = root / "payload"
            payload.mkdir()
            (payload / "main.py").write_text("print('payload')", encoding="utf-8")
            collector = LinuxCollector(
                target,
                Credential(password="secret"),
                transport=_PartialLinuxArchiveSSHTransport(),
                payload_root=payload,
            )

            results = collector.collect(root / "output")

            self.assertEqual([item.success for item in results], [True, False])
            self.assertEqual([item.name for item in results], ["firewall", "audit"])


class WindowsCollectorTests(unittest.TestCase):
    def test_windows_collection_uses_manifest_for_module_results(self):
        target = TargetConfig(
            target_type=TargetType.WINDOWS,
            host="10.0.0.9",
            port=5985,
            username="Administrator",
        )
        transport = _FakeWinRMTransport()

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            payload = root / "payload"
            payload.mkdir()
            (payload / "Invoke-AllCollectors.ps1").write_text(
                "param([string]$OutputDirectory)",
                encoding="utf-8",
            )
            output = root / "output"
            output.mkdir()
            collector = WindowsCollector(
                target,
                Credential(password="secret"),
                transport=transport,
                payload_root=payload,
            )

            results = collector.collect(output)

            self.assertEqual([item.success for item in results], [True, False])
            self.assertTrue(
                (output / "Protect-Update" / "Get-FirewallRules.txt").exists()
            )
            self.assertTrue(
                any("Invoke-AllCollectors.ps1" in script for script in transport.scripts)
            )


class SecurityCollectorTests(unittest.TestCase):
    def test_security_collection_uses_selected_adapter_defaults(self):
        target = TargetConfig(
            target_type=TargetType.SECURITY,
            host="10.0.0.10",
            port=22,
            username="root",
            security_device="bt_waf",
        )
        transport = _FakeSSHTransport()

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            payload = root / "payload"
            payload.mkdir()
            (payload / "remote_collect.py").write_text(
                "print('security payload')",
                encoding="utf-8",
            )
            output = root / "output"
            output.mkdir()
            collector = SecurityDeviceCollector(
                target,
                Credential(password="secret"),
                adapter=default_registry().resolve("bt_waf"),
                transport=transport,
                payload_root=payload,
            )

            results = collector.collect(output)

            self.assertTrue(results[0].success)
            self.assertTrue(
                any("remote_collect.py" in command for command in transport.commands)
            )
            self.assertTrue(
                any(
                    "/etc/nginx/waf/rule" in command
                    or getattr(transport, "uploaded_file", None)
                    for command in transport.commands
                )
            )
            uploaded_config = json.loads(transport.uploaded_file_content)
            self.assertEqual(uploaded_config["path_mode"], "default")

    def test_custom_security_collection_uploads_dynamic_adapter_metadata(self):
        target = TargetConfig(
            target_type=TargetType.SECURITY,
            host="10.0.0.88",
            port=22,
            username="collector",
            security_device="custom",
            custom_paths=("/opt/custom/rules",),
            custom_device_name="自研设备",
            rule_file_type=".rules",
            deployment_mode="host",
        )
        transport = _FakeSSHTransport()

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            payload = root / "payload"
            payload.mkdir()
            (payload / "remote_collect.py").write_text(
                "print('security payload')",
                encoding="utf-8",
            )
            output = root / "output"
            output.mkdir()
            collector = SecurityDeviceCollector(
                target,
                Credential(password="secret"),
                adapter=SecurityDeviceAdapter(
                    key="custom",
                    display_name="自研设备",
                    paths=("/opt/custom/rules",),
                    rule_file_type=".rules",
                ),
                transport=transport,
                payload_root=payload,
            )

            collector.collect(output)

            uploaded_config = json.loads(transport.uploaded_file_content)
            self.assertEqual(uploaded_config["display_name"], "自研设备")
            self.assertEqual(uploaded_config["rule_file_type"], ".rules")
            self.assertEqual(uploaded_config["path_mode"], "custom")
            self.assertFalse(uploaded_config["docker"])

    def test_security_payload_reports_partial_when_one_path_is_missing(self):
        payload = (
            Path(__file__).resolve().parents[1]
            / "payloads"
            / "security"
            / "remote_collect.py"
        )
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            existing = root / "existing.rules"
            existing.write_text("allow", encoding="utf-8")
            config = root / "config.json"
            output = root / "output"
            config.write_text(
                json.dumps(
                    {
                        "key": "suricata",
                        "paths": [str(existing), str(root / "missing.rules")],
                        "path_mode": "custom",
                        "status_commands": [],
                        "docker": False,
                    }
                ),
                encoding="utf-8",
            )

            completed = subprocess.run(
                [
                    sys.executable,
                    str(payload),
                    "--config",
                    str(config),
                    "--output",
                    str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            manifest = json.loads(
                (output / "collection_manifest.json").read_text(encoding="utf-8")
            )

            self.assertEqual(completed.returncode, 2)
            self.assertEqual(
                [item["success"] for item in manifest],
                [True, False],
            )
            self.assertEqual(
                [item["path_mode"] for item in manifest],
                ["custom", "custom"],
            )
            self.assertTrue(
                all(item["output_dir"] in {"rules", "status"} for item in manifest)
            )

    def test_custom_security_payload_filters_directory_by_rule_file_type(self):
        payload = (
            Path(__file__).resolve().parents[1]
            / "payloads"
            / "security"
            / "remote_collect.py"
        )
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            rules = root / "device-rules"
            nested = rules / "nested"
            nested.mkdir(parents=True)
            (rules / "allow.rules").write_text("allow", encoding="utf-8")
            (nested / "block.rules").write_text("block", encoding="utf-8")
            (rules / "notes.conf").write_text("ignore", encoding="utf-8")
            config = root / "config.json"
            output = root / "output"
            config.write_text(
                json.dumps(
                    {
                        "key": "custom",
                        "display_name": "自研设备",
                        "paths": [str(rules)],
                        "path_mode": "custom",
                        "rule_file_type": ".rules",
                        "status_commands": [],
                        "docker": False,
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            completed = subprocess.run(
                [
                    sys.executable,
                    str(payload),
                    "--config",
                    str(config),
                    "--output",
                    str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            collected_names = {
                path.name for path in (output / "rules").rglob("*") if path.is_file()
            }
            manifest = json.loads(
                (output / "collection_manifest.json").read_text(encoding="utf-8")
            )

            self.assertEqual(completed.returncode, 0)
            self.assertEqual(collected_names, {"allow.rules", "block.rules"})
            self.assertEqual(manifest[0]["rule_file_type"], ".rules")

    def test_custom_docker_device_requires_exact_container_name(self):
        payload = (
            Path(__file__).resolve().parents[1]
            / "payloads"
            / "security"
            / "remote_collect.py"
        )
        namespace = runpy.run_path(str(payload))
        select_container = namespace["select_container"]
        select_container.__globals__["run"] = lambda *_args, **_kwargs: (
            subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout="abc123456789\tactual-device\tvendor/image:latest\n",
                stderr="",
            )
        )

        with self.assertRaisesRegex(RuntimeError, "未找到指定的安全设备容器"):
            select_container(
                {
                    "key": "custom",
                    "container_name": "abc123",
                    "container_patterns": [],
                }
            )

        selected = select_container(
            {
                "key": "custom",
                "container_name": "actual-device",
                "container_patterns": [],
            }
        )
        self.assertEqual(selected["name"], "actual-device")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "需要POSIX命名管道支持")
    def test_docker_rule_filter_removes_special_files(self):
        payload = (
            Path(__file__).resolve().parents[1]
            / "payloads"
            / "security"
            / "remote_collect.py"
        )
        sanitize_docker_copy = runpy.run_path(str(payload))[
            "sanitize_docker_copy"
        ]
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / "docker-copy"
            destination.mkdir()
            (destination / "allow.rules").write_text("allow", encoding="utf-8")
            fifo = destination / "runtime.pipe"
            os.mkfifo(fifo)

            sanitize_docker_copy(destination, ".rules")

            self.assertTrue((destination / "allow.rules").exists())
            self.assertFalse(fifo.exists())

    @unittest.skipUnless(hasattr(os, "mkfifo"), "需要POSIX命名管道支持")
    def test_docker_rule_filter_rejects_top_level_special_file(self):
        payload = (
            Path(__file__).resolve().parents[1]
            / "payloads"
            / "security"
            / "remote_collect.py"
        )
        sanitize_docker_copy = runpy.run_path(str(payload))[
            "sanitize_docker_copy"
        ]
        with tempfile.TemporaryDirectory() as temp:
            fifo = Path(temp) / "docker-copy"
            os.mkfifo(fifo)

            with self.assertRaisesRegex(RuntimeError, "特殊文件"):
                sanitize_docker_copy(fifo, ".rules")

            self.assertFalse(fifo.exists())

    @unittest.skipUnless(os.name == "posix", "需要POSIX符号链接支持")
    def test_docker_rule_filter_removes_dangling_top_level_symlink(self):
        payload = (
            Path(__file__).resolve().parents[1]
            / "payloads"
            / "security"
            / "remote_collect.py"
        )
        sanitize_docker_copy = runpy.run_path(str(payload))[
            "sanitize_docker_copy"
        ]
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / "docker-copy"
            destination.symlink_to(Path(temp) / "missing-target")

            with self.assertRaisesRegex(RuntimeError, "符号链接"):
                sanitize_docker_copy(destination, ".rules")

            self.assertFalse(destination.is_symlink())


if __name__ == "__main__":
    unittest.main()
