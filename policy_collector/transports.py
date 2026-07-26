from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
import os
import posixpath
import socket
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from .errors import TransportError
from .models import Credential, TargetConfig


@dataclass(frozen=True)
class CommandResult:
    return_code: int
    stdout: str
    stderr: str


def _check_tcp(host: str, port: int, timeout: int) -> None:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return
    except OSError as exc:
        raise TransportError(f"无法连接 {host}:{port}: {exc}") from exc


class SSHTransport:
    def __init__(
        self,
        target: TargetConfig,
        credential: Credential,
        *,
        connect_timeout: int = 10,
        client_factory: Callable[[], Any] | None = None,
    ) -> None:
        self.target = target
        self.credential = credential
        self.connect_timeout = connect_timeout
        self._client_factory = client_factory
        self._client: Any | None = None
        self._sftp: Any | None = None

    def connect(self) -> None:
        if self._client is not None:
            return
        try:
            import paramiko
        except ImportError as exc:
            raise TransportError(
                "缺少Paramiko，请先执行 pip install -r requirements.txt"
            ) from exc
        client = self._client_factory() if self._client_factory else paramiko.SSHClient()
        client.load_system_host_keys()
        if self.target.trust_new_host_key:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        try:
            client.connect(
                hostname=self.target.host,
                port=self.target.port,
                username=self.target.username,
                password=self.credential.password,
                timeout=self.connect_timeout,
                auth_timeout=self.connect_timeout,
                banner_timeout=self.connect_timeout,
                look_for_keys=False,
                allow_agent=False,
            )
        except Exception as exc:
            client.close()
            raise TransportError(f"SSH认证或连接失败: {exc}") from exc
        self._client = client

    def check(self) -> dict[str, object]:
        _check_tcp(self.target.host, self.target.port, self.connect_timeout)
        self.connect()
        result = self.run(
            "command -v python3 >/dev/null && python3 --version && "
            "command -v tar >/dev/null && tar --version | head -n 1",
            timeout=20,
        )
        if result.return_code != 0:
            raise TransportError("目标机缺少可用的python3或tar")
        details: dict[str, object] = {
            "connected": True,
            "transport": "ssh",
            "capabilities": (result.stdout or result.stderr).strip(),
        }
        if self.target.use_sudo:
            sudo_result = self.run(
                "true",
                sudo=True,
                sudo_password=self.credential.sudo_password,
                timeout=20,
            )
            if sudo_result.return_code != 0:
                raise TransportError(
                    "已连接SSH，但当前账号无法使用配置的sudo凭据"
                )
            details["sudo"] = "available"
        return details

    def run(
        self,
        command: str,
        *,
        sudo: bool = False,
        sudo_password: str | None = None,
        timeout: int = 300,
    ) -> CommandResult:
        import shlex

        self.connect()
        assert self._client is not None
        remote_command = f"sh -lc {shlex.quote(command)}"
        if sudo:
            remote_command = f"sudo -S -p '' -- {remote_command}"
        try:
            stdin, stdout, stderr = self._client.exec_command(
                remote_command,
                timeout=timeout,
                get_pty=sudo,
            )
            if sudo:
                if not sudo_password:
                    raise TransportError("需要sudo密码，但未提供")
                stdin.write(sudo_password + "\n")
                stdin.flush()
            with ThreadPoolExecutor(max_workers=2) as pool:
                stdout_future = pool.submit(stdout.read)
                stderr_future = pool.submit(stderr.read)
                stdout_bytes = stdout_future.result()
                stderr_bytes = stderr_future.result()
            return_code = stdout.channel.recv_exit_status()
            return CommandResult(
                return_code=return_code,
                stdout=stdout_bytes.decode("utf-8", errors="replace"),
                stderr=stderr_bytes.decode("utf-8", errors="replace"),
            )
        except TransportError:
            raise
        except Exception as exc:
            raise TransportError(f"SSH远程命令执行失败: {exc}") from exc

    def _get_sftp(self):
        self.connect()
        if self._sftp is None:
            assert self._client is not None
            self._sftp = self._client.open_sftp()
        return self._sftp

    def _mkdir(self, remote_dir: str) -> None:
        sftp = self._get_sftp()
        current = "/"
        for part in PurePosixPath(remote_dir).parts:
            if part == "/":
                continue
            current = posixpath.join(current, part)
            try:
                sftp.stat(current)
            except OSError:
                sftp.mkdir(current)

    def upload_file(self, local_path: Path, remote_path: str) -> None:
        self._mkdir(posixpath.dirname(remote_path))
        try:
            self._get_sftp().put(str(local_path), remote_path)
        except Exception as exc:
            raise TransportError(f"SFTP上传失败: {local_path.name}: {exc}") from exc

    def upload_tree(self, local_path: Path, remote_path: str) -> None:
        local_path = Path(local_path)
        for root, dirs, files in os.walk(local_path):
            dirs[:] = [name for name in dirs if name != "__pycache__"]
            relative = Path(root).relative_to(local_path)
            remote_dir = remote_path
            if relative.parts:
                remote_dir = posixpath.join(remote_path, *relative.parts)
            self._mkdir(remote_dir)
            for filename in files:
                if filename.endswith((".pyc", ".pyo")):
                    continue
                self.upload_file(Path(root) / filename, posixpath.join(remote_dir, filename))

    def download_file(self, remote_path: str, local_path: Path) -> None:
        local_path = Path(local_path)
        local_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self._get_sftp().get(remote_path, str(local_path))
        except Exception as exc:
            raise TransportError(f"SFTP下载失败: {remote_path}: {exc}") from exc

    def close(self) -> None:
        if self._sftp is not None:
            self._sftp.close()
            self._sftp = None
        if self._client is not None:
            self._client.close()
            self._client = None


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


class WinRMTransport:
    # Upload data is embedded in a PowerShell script and encoded again by
    # pywinrm. Keep it well below Windows' 8191-character command-line limit.
    UPLOAD_CHUNK_SIZE = 1 * 1024
    DOWNLOAD_CHUNK_SIZE = 48 * 1024

    def __init__(
        self,
        target: TargetConfig,
        credential: Credential,
        *,
        connect_timeout: int = 10,
        session_factory: Callable[..., Any] | None = None,
    ) -> None:
        self.target = target
        self.credential = credential
        self.connect_timeout = connect_timeout
        self._session_factory = session_factory
        self._session: Any | None = None

    def connect(self) -> None:
        if self._session is not None:
            return
        if self._session_factory is not None:
            factory = self._session_factory
        else:
            try:
                import winrm as winrm_module
            except ImportError as exc:
                raise TransportError(
                    "缺少pywinrm，请先执行 pip install -r requirements.txt"
                ) from exc
            factory = winrm_module.Session
        scheme = "https" if self.target.winrm_https else "http"
        endpoint = f"{scheme}://{self.target.host}:{self.target.port}/wsman"
        try:
            self._session = factory(
                endpoint,
                auth=(self.target.username, self.credential.password),
                transport="ntlm",
                server_cert_validation=(
                    "ignore" if self.target.winrm_insecure else "validate"
                ),
            )
        except Exception as exc:
            raise TransportError(f"WinRM会话创建失败: {exc}") from exc

    def run_ps(self, script: str) -> CommandResult:
        self.connect()
        assert self._session is not None
        try:
            response = self._session.run_ps(script)
        except Exception as exc:
            raise TransportError(f"WinRM命令执行失败: {exc}") from exc
        return CommandResult(
            return_code=int(response.status_code),
            stdout=response.std_out.decode("utf-8", errors="replace"),
            stderr=response.std_err.decode("utf-8", errors="replace"),
        )

    def check(self) -> dict[str, object]:
        _check_tcp(self.target.host, self.target.port, self.connect_timeout)
        result = self.run_ps(
            "$PSVersionTable.PSVersion.ToString(); "
            "if (Get-Command Compress-Archive -ErrorAction SilentlyContinue) "
            "{ 'Compress-Archive=available' } else { exit 3 }"
        )
        if result.return_code != 0:
            raise TransportError(
                "WinRM已连接，但PowerShell或Compress-Archive不可用"
            )
        return {
            "connected": True,
            "transport": "winrm",
            "powershell": result.stdout.strip(),
        }

    def upload_file(self, local_path: Path, remote_path: str) -> None:
        data = Path(local_path).read_bytes()
        quoted_path = _ps_quote(remote_path)
        parent = str(PurePosixPath(remote_path.replace("\\", "/")).parent).replace(
            "/", "\\"
        )
        init = self.run_ps(
            f"$p={_ps_quote(parent)}; "
            "New-Item -ItemType Directory -Path $p -Force | Out-Null; "
            f"[IO.File]::WriteAllBytes({quoted_path}, [byte[]]@())"
        )
        if init.return_code != 0:
            raise TransportError(f"WinRM创建远程文件失败: {init.stderr}")
        for offset in range(0, len(data), self.UPLOAD_CHUNK_SIZE):
            encoded = base64.b64encode(
                data[offset : offset + self.UPLOAD_CHUNK_SIZE]
            ).decode("ascii")
            script = (
                f"$b=[Convert]::FromBase64String({_ps_quote(encoded)});"
                f"$f=[IO.File]::Open({quoted_path},[IO.FileMode]::Append,"
                "[IO.FileAccess]::Write,[IO.FileShare]::None);"
                "$f.Write($b,0,$b.Length);$f.Dispose()"
            )
            result = self.run_ps(script)
            if result.return_code != 0:
                raise TransportError(f"WinRM上传文件分块失败: {result.stderr}")

    def upload_tree(self, local_path: Path, remote_path: str) -> None:
        local_path = Path(local_path)
        for path in local_path.rglob("*"):
            if not path.is_file() or "__pycache__" in path.parts:
                continue
            relative = path.relative_to(local_path)
            destination = remote_path.rstrip("\\") + "\\" + "\\".join(relative.parts)
            self.upload_file(path, destination)

    def download_file(self, remote_path: str, local_path: Path) -> None:
        quoted_path = _ps_quote(remote_path)
        length_result = self.run_ps(f"(Get-Item -LiteralPath {quoted_path}).Length")
        if length_result.return_code != 0:
            raise TransportError(f"WinRM读取远程文件长度失败: {length_result.stderr}")
        try:
            length = int(length_result.stdout.strip())
        except ValueError as exc:
            raise TransportError("WinRM返回了无效的文件长度") from exc
        local_path = Path(local_path)
        local_path.parent.mkdir(parents=True, exist_ok=True)
        with local_path.open("wb") as stream:
            for offset in range(0, length, self.DOWNLOAD_CHUNK_SIZE):
                count = min(self.DOWNLOAD_CHUNK_SIZE, length - offset)
                script = (
                    f"$f=[IO.File]::OpenRead({quoted_path});"
                    f"$null=$f.Seek({offset},[IO.SeekOrigin]::Begin);"
                    f"$b=New-Object byte[] {count};$n=$f.Read($b,0,{count});"
                    "$f.Dispose();[Convert]::ToBase64String($b,0,$n)"
                )
                result = self.run_ps(script)
                if result.return_code != 0:
                    raise TransportError(f"WinRM下载文件分块失败: {result.stderr}")
                try:
                    stream.write(base64.b64decode(result.stdout.strip(), validate=True))
                except ValueError as exc:
                    raise TransportError("WinRM返回了无效的Base64文件分块") from exc

    def close(self) -> None:
        self._session = None
