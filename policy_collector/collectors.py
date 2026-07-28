from __future__ import annotations

import json
import re
import shlex
import stat
import sys
import tarfile
import tempfile
import uuid
import zipfile
from pathlib import Path

from .adapters import (
    CUSTOM_SECURITY_DEVICE_KEY,
    SecurityDeviceAdapter,
    default_registry,
)
from .errors import CollectorError, TransportError
from .models import Credential, ModuleResult, TargetConfig
from .transports import SSHTransport, WinRMTransport


_POSIX_TEMP = re.compile(r"^/tmp/policy_collector_[0-9a-f]{32}$")
_WINDOWS_TEMP = re.compile(
    r"^C:\\Windows\\Temp\\policy_collector_[0-9a-f]{32}$",
    re.IGNORECASE,
)


def _extract_tar_safely(archive_path: Path, output_dir: Path) -> None:
    output_root = output_dir.resolve()
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive.getmembers():
            if (
                member.issym()
                or member.islnk()
                or member.isdev()
                or member.isfifo()
            ):
                raise CollectorError("采集结果压缩包包含不安全的特殊文件")
            destination = (output_dir / member.name).resolve()
            try:
                destination.relative_to(output_root)
            except ValueError as exc:
                raise CollectorError("采集结果压缩包包含不安全路径") from exc
        if sys.version_info >= (3, 12):
            archive.extractall(output_dir, filter="fully_trusted")
        else:
            archive.extractall(output_dir)


def _extract_zip_safely(archive_path: Path, output_dir: Path) -> None:
    output_root = output_dir.resolve()
    with zipfile.ZipFile(archive_path) as archive:
        for member in archive.infolist():
            unix_mode = (member.external_attr >> 16) & 0o170000
            if unix_mode == stat.S_IFLNK:
                raise CollectorError("采集结果ZIP包含不安全的符号链接")
            destination = (output_dir / member.filename).resolve()
            try:
                destination.relative_to(output_root)
            except ValueError as exc:
                raise CollectorError("采集结果ZIP包含不安全路径") from exc
        archive.extractall(output_dir)


class LinuxCollector:
    def __init__(
        self,
        target: TargetConfig,
        credential: Credential,
        *,
        transport=None,
        payload_root: Path | None = None,
    ) -> None:
        self.target = target
        self.credential = credential
        self.transport = transport or SSHTransport(target, credential)
        self.payload_root = payload_root or (
            Path(__file__).resolve().parents[1] / "payloads" / "linux"
        )
        self.remote_temp = f"/tmp/policy_collector_{uuid.uuid4().hex}"
        self._remote_created = False

    def check(self) -> dict[str, object]:
        return self.transport.check()

    def collect(self, output_dir: Path) -> list[ModuleResult]:
        output_dir.mkdir(parents=True, exist_ok=True)
        remote_payload = f"{self.remote_temp}/payload"
        remote_output = f"{self.remote_temp}/result"
        remote_archive = f"{self.remote_temp}/result.tar.gz"
        self._remote_created = True
        mkdir = self.transport.run(
            f"mkdir -p {shlex.quote(remote_payload)} {shlex.quote(remote_output)}"
        )
        if mkdir.return_code != 0:
            raise TransportError(f"无法创建Linux临时目录: {mkdir.stderr}")
        self.transport.upload_tree(self.payload_root, remote_payload)
        run = self.transport.run(
            f"python3 {shlex.quote(remote_payload + '/main.py')} "
            f"--all --output {shlex.quote(remote_output)}",
            sudo=self.target.use_sudo,
            sudo_password=self.credential.sudo_password,
            timeout=1800,
        )
        archive = self.transport.run(
            f"tar -czf {shlex.quote(remote_archive)} "
            f"-C {shlex.quote(remote_output)} .",
            sudo=self.target.use_sudo,
            sudo_password=self.credential.sudo_password,
            timeout=300,
        )
        if archive.return_code != 0:
            raise TransportError(f"Linux采集结果打包失败: {archive.stderr}")
        local_archive = output_dir / "linux-results.tar.gz"
        self.transport.download_file(remote_archive, local_archive)
        _extract_tar_safely(local_archive, output_dir)
        manifest_path = output_dir / "collection_manifest.json"
        if manifest_path.exists():
            try:
                items = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
                return [
                    ModuleResult(
                        name=str(item["name"]),
                        success=bool(item["success"]),
                        return_code=item.get("return_code"),
                        message=str(item.get("message", "")),
                    )
                    for item in items
                ]
            except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
                raise CollectorError(f"Linux采集清单无效: {exc}") from exc
        return [
            ModuleResult(
                name="linux_all",
                success=run.return_code == 0,
                return_code=run.return_code,
                message=(run.stderr or run.stdout)[-2000:],
            )
        ]

    def cleanup(self) -> bool:
        if not _POSIX_TEMP.fullmatch(self.remote_temp):
            raise CollectorError("拒绝清理不安全的Linux临时目录")
        if not self._remote_created:
            self.transport.close()
            return True
        succeeded = True
        try:
            result = self.transport.run(
                f"rm -rf -- {shlex.quote(self.remote_temp)}",
                sudo=self.target.use_sudo,
                sudo_password=self.credential.sudo_password,
                timeout=60,
            )
            succeeded = result.return_code == 0
            if succeeded:
                self._remote_created = False
        except Exception:
            succeeded = False
        finally:
            self.transport.close()
        return succeeded


class WindowsCollector:
    def __init__(
        self,
        target: TargetConfig,
        credential: Credential,
        *,
        transport=None,
        payload_root: Path | None = None,
    ) -> None:
        self.target = target
        self.credential = credential
        self.transport = transport or WinRMTransport(target, credential)
        self.payload_root = payload_root or (
            Path(__file__).resolve().parents[1] / "payloads" / "windows"
        )
        self.remote_temp = (
            "C:\\Windows\\Temp\\policy_collector_" + uuid.uuid4().hex
        )
        self._remote_created = False

    def check(self) -> dict[str, object]:
        return self.transport.check()

    def collect(self, output_dir: Path) -> list[ModuleResult]:
        output_dir.mkdir(parents=True, exist_ok=True)
        payload = self.remote_temp + "\\payload"
        result_dir = self.remote_temp + "\\result"
        archive = self.remote_temp + "\\result.zip"
        self._remote_created = True
        create = self.transport.run_ps(
            "$ErrorActionPreference='Stop';"
            f"New-Item -ItemType Directory -Path '{payload}','{result_dir}' "
            "-Force | Out-Null"
        )
        if create.return_code != 0:
            raise TransportError(f"无法创建Windows临时目录: {create.stderr}")
        self.transport.upload_tree(self.payload_root, payload)
        run = self.transport.run_ps(
            "$OutputEncoding=[Console]::OutputEncoding="
            "[Text.UTF8Encoding]::new();"
            f"& '{payload}\\Invoke-AllCollectors.ps1' "
            f"-OutputDirectory '{result_dir}'"
        )
        packed = self.transport.run_ps(
            "$ErrorActionPreference='Stop';"
            f"if(Test-Path -LiteralPath '{archive}')"
            f"{{Remove-Item -LiteralPath '{archive}' -Force}};"
            f"Compress-Archive -Path '{result_dir}\\*' "
            f"-DestinationPath '{archive}' -Force"
        )
        if packed.return_code != 0:
            raise TransportError(f"Windows采集结果打包失败: {packed.stderr}")
        local_archive = output_dir / "windows-results.zip"
        self.transport.download_file(archive, local_archive)
        _extract_zip_safely(local_archive, output_dir)

        manifest_path = output_dir / "collection_manifest.json"
        if not manifest_path.exists():
            return [
                ModuleResult(
                    name="windows_all",
                    success=run.return_code == 0,
                    return_code=run.return_code,
                    message=(run.stderr or run.stdout)[-2000:],
                )
            ]
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CollectorError(f"Windows采集清单无效: {exc}") from exc
        return [
            ModuleResult(
                name=str(item["name"]),
                success=bool(item["success"]),
                return_code=item.get("return_code"),
                message=str(item.get("message", "")),
            )
            for item in manifest
        ]

    def cleanup(self) -> bool:
        if not _WINDOWS_TEMP.fullmatch(self.remote_temp):
            raise CollectorError("拒绝清理不安全的Windows临时目录")
        if not self._remote_created:
            self.transport.close()
            return True
        succeeded = True
        try:
            result = self.transport.run_ps(
                f"if(Test-Path -LiteralPath '{self.remote_temp}')"
                f"{{Remove-Item -LiteralPath '{self.remote_temp}' "
                "-Recurse -Force}}"
            )
            succeeded = result.return_code == 0
            if succeeded:
                self._remote_created = False
        except Exception:
            succeeded = False
        finally:
            self.transport.close()
        return succeeded


class SecurityDeviceCollector:
    def __init__(
        self,
        target: TargetConfig,
        credential: Credential,
        *,
        adapter: SecurityDeviceAdapter,
        transport=None,
        payload_root: Path | None = None,
    ) -> None:
        self.target = target
        self.credential = credential
        self.adapter = adapter
        self.transport = transport or SSHTransport(target, credential)
        self.payload_root = payload_root or (
            Path(__file__).resolve().parents[1] / "payloads" / "security"
        )
        self.remote_temp = f"/tmp/policy_collector_{uuid.uuid4().hex}"
        self._remote_created = False

    def check(self) -> dict[str, object]:
        details = dict(self.transport.check())
        details["security_device"] = self.adapter.key
        details["security_device_name"] = self.adapter.display_name
        if self.adapter.rule_file_type:
            details["rule_file_type"] = self.adapter.rule_file_type
        if self.adapter.docker:
            result = self.transport.run(
                "docker version --format '{{.Server.Version}}'",
                sudo=self.target.use_sudo,
                sudo_password=self.credential.sudo_password,
                timeout=30,
            )
            if result.return_code != 0:
                raise TransportError(
                    "目标宿主机无法执行Docker命令，请检查Docker及用户权限"
                )
            details["docker"] = result.stdout.strip()
        return details

    def collect(self, output_dir: Path) -> list[ModuleResult]:
        output_dir.mkdir(parents=True, exist_ok=True)
        remote_payload = f"{self.remote_temp}/payload"
        remote_output = f"{self.remote_temp}/result"
        remote_config = f"{self.remote_temp}/adapter.json"
        remote_archive = f"{self.remote_temp}/result.tar.gz"
        self._remote_created = True
        mkdir = self.transport.run(
            f"mkdir -p {shlex.quote(remote_payload)} {shlex.quote(remote_output)}"
        )
        if mkdir.return_code != 0:
            raise TransportError(f"无法创建安全设备临时目录: {mkdir.stderr}")
        self.transport.upload_tree(self.payload_root, remote_payload)

        if self.adapter.key == CUSTOM_SECURITY_DEVICE_KEY:
            path_mode = "custom"
        else:
            default_paths = default_registry().resolve(self.adapter.key).paths
            path_mode = (
                "custom"
                if self.target.custom_paths or self.adapter.paths != default_paths
                else "default"
            )
        config = {
            "key": self.adapter.key,
            "display_name": self.adapter.display_name,
            "paths": list(self.adapter.paths),
            "path_mode": path_mode,
            "status_commands": list(self.adapter.status_commands),
            "docker": self.adapter.docker,
            "container_patterns": list(self.adapter.container_patterns),
            "container_name": self.target.container_name,
            "rule_file_type": self.adapter.rule_file_type,
        }
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            suffix=".json",
            delete=False,
        ) as stream:
            json.dump(config, stream, ensure_ascii=False, indent=2)
            local_config = Path(stream.name)
        try:
            self.transport.upload_file(local_config, remote_config)
        finally:
            local_config.unlink(missing_ok=True)

        run = self.transport.run(
            f"python3 {shlex.quote(remote_payload + '/remote_collect.py')} "
            f"--config {shlex.quote(remote_config)} "
            f"--output {shlex.quote(remote_output)}",
            sudo=self.target.use_sudo,
            sudo_password=self.credential.sudo_password,
            timeout=900,
        )
        archive = self.transport.run(
            f"tar -czf {shlex.quote(remote_archive)} "
            f"-C {shlex.quote(remote_output)} .",
            sudo=self.target.use_sudo,
            sudo_password=self.credential.sudo_password,
            timeout=300,
        )
        if archive.return_code != 0:
            raise TransportError(f"安全设备采集结果打包失败: {archive.stderr}")
        local_archive = output_dir / f"{self.adapter.key}-results.tar.gz"
        self.transport.download_file(remote_archive, local_archive)
        _extract_tar_safely(local_archive, output_dir)

        manifest_path = output_dir / "collection_manifest.json"
        if manifest_path.exists():
            try:
                items = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
                return [
                    ModuleResult(
                        name=str(item["name"]),
                        success=bool(item["success"]),
                        return_code=item.get("return_code"),
                        message=str(item.get("message", "")),
                    )
                    for item in items
                ]
            except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
                raise CollectorError(f"安全设备采集清单无效: {exc}") from exc
        return [
            ModuleResult(
                name=self.adapter.key,
                success=run.return_code == 0,
                return_code=run.return_code,
                message=(run.stderr or run.stdout)[-2000:],
            )
        ]

    def cleanup(self) -> bool:
        if not _POSIX_TEMP.fullmatch(self.remote_temp):
            raise CollectorError("拒绝清理不安全的安全设备临时目录")
        if not self._remote_created:
            self.transport.close()
            return True
        succeeded = True
        try:
            result = self.transport.run(
                f"rm -rf -- {shlex.quote(self.remote_temp)}",
                sudo=self.target.use_sudo,
                sudo_password=self.credential.sudo_password,
                timeout=60,
            )
            succeeded = result.return_code == 0
            if succeeded:
                self._remote_created = False
        except Exception:
            succeeded = False
        finally:
            self.transport.close()
        return succeeded
