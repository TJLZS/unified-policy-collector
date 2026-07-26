import base64
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from policy_collector.models import Credential, TargetConfig, TargetType
from policy_collector.transports import CommandResult, SSHTransport, WinRMTransport


class _Response:
    def __init__(self, status_code=0, stdout="", stderr=""):
        self.status_code = status_code
        self.std_out = stdout.encode("utf-8")
        self.std_err = stderr.encode("utf-8")


class _MemoryWinRMSession:
    def __init__(self):
        self.files = {}

    def run_ps(self, script):
        if "WriteAllBytes" in script:
            path = re.search(r"WriteAllBytes\('([^']+)'", script).group(1)
            self.files[path] = bytearray()
            return _Response()
        if "FromBase64String" in script and "FileMode]::Append" in script:
            encoded = re.search(r"FromBase64String\('([^']*)'\)", script).group(1)
            path = re.search(r"Open\('([^']+)'", script).group(1)
            self.files[path].extend(base64.b64decode(encoded))
            return _Response()
        if "(Get-Item -LiteralPath" in script:
            path = re.search(r"-LiteralPath '([^']+)'", script).group(1)
            return _Response(stdout=str(len(self.files[path])))
        if "OpenRead" in script:
            path = re.search(r"OpenRead\('([^']+)'\)", script).group(1)
            offset = int(re.search(r"Seek\((\d+),", script).group(1))
            count = int(re.search(r"New-Object byte\[\] (\d+)", script).group(1))
            chunk = bytes(self.files[path][offset : offset + count])
            return _Response(stdout=base64.b64encode(chunk).decode("ascii"))
        return _Response()


class _LengthLimitedWinRMSession(_MemoryWinRMSession):
    WINDOWS_COMMAND_LINE_LIMIT = 32767

    def __init__(self):
        super().__init__()
        self.command_lengths = []

    def run_ps(self, script):
        encoded_command = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        command_length = len("powershell.exe -encodedcommand ") + len(encoded_command)
        self.command_lengths.append(command_length)
        if command_length > self.WINDOWS_COMMAND_LINE_LIMIT:
            return _Response(status_code=1, stderr="The command line is too long.")
        return super().run_ps(script)


class WinRMTransportTests(unittest.TestCase):
    def test_chunked_upload_and_download_round_trip(self):
        target = TargetConfig(
            TargetType.WINDOWS,
            "10.0.0.9",
            5985,
            "Administrator",
        )
        session = _MemoryWinRMSession()
        transport = WinRMTransport(
            target,
            Credential(password="secret"),
            session_factory=lambda *args, **kwargs: session,
        )
        data = (b"policy-data-" * 10000) + b"end"

        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "source.bin"
            downloaded = Path(temp) / "downloaded.bin"
            source.write_bytes(data)
            transport.upload_file(source, r"C:\Temp\source.bin")
            transport.download_file(r"C:\Temp\source.bin", downloaded)

            self.assertEqual(downloaded.read_bytes(), data)

    def test_upload_chunks_fit_windows_command_line_limit(self):
        target = TargetConfig(
            TargetType.WINDOWS,
            "10.0.0.9",
            5985,
            "Administrator",
        )
        session = _LengthLimitedWinRMSession()
        transport = WinRMTransport(
            target,
            Credential(password="secret"),
            session_factory=lambda *args, **kwargs: session,
        )
        data = b"A" * (50 * 1024)

        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "payload.ps1"
            source.write_bytes(data)
            transport.upload_file(source, r"C:\Temp\payload.ps1")

        self.assertEqual(bytes(session.files[r"C:\Temp\payload.ps1"]), data)
        self.assertLess(
            max(session.command_lengths),
            _LengthLimitedWinRMSession.WINDOWS_COMMAND_LINE_LIMIT,
        )


class _CapabilitySSHTransport(SSHTransport):
    def __init__(self, target, credential):
        super().__init__(target, credential)
        self.calls = []

    def connect(self):
        return None

    def run(
        self,
        command,
        *,
        sudo=False,
        sudo_password=None,
        timeout=300,
    ):
        self.calls.append((command, sudo, sudo_password, timeout))
        return CommandResult(0, "ok", "")


class _PolicyRecordingClient:
    def __init__(self):
        self.policy = None

    def load_system_host_keys(self):
        return None

    def set_missing_host_key_policy(self, policy):
        self.policy = policy

    def connect(self, **kwargs):
        return None

    def close(self):
        return None


class SSHTransportTests(unittest.TestCase):
    @patch("policy_collector.transports._check_tcp")
    def test_check_validates_python_tar_and_requested_sudo(self, _tcp_check):
        target = TargetConfig(
            TargetType.LINUX,
            "10.0.0.8",
            22,
            "collector",
            use_sudo=True,
        )
        transport = _CapabilitySSHTransport(
            target,
            Credential(password="login", sudo_password="sudo-secret"),
        )

        details = transport.check()

        self.assertIn("command -v python3", transport.calls[0][0])
        self.assertIn("command -v tar", transport.calls[0][0])
        self.assertTrue(transport.calls[1][1])
        self.assertEqual(transport.calls[1][2], "sudo-secret")
        self.assertEqual(details["sudo"], "available")

    def test_unknown_ssh_host_keys_are_rejected_unless_explicitly_allowed(self):
        strict_target = TargetConfig(
            TargetType.LINUX,
            "10.0.0.8",
            22,
            "collector",
        )
        strict_client = _PolicyRecordingClient()
        SSHTransport(
            strict_target,
            Credential(password="secret"),
            client_factory=lambda: strict_client,
        ).connect()

        trusted_target = TargetConfig(
            TargetType.LINUX,
            "10.0.0.8",
            22,
            "collector",
            trust_new_host_key=True,
        )
        trusted_client = _PolicyRecordingClient()
        SSHTransport(
            trusted_target,
            Credential(password="secret"),
            client_factory=lambda: trusted_client,
        ).connect()

        self.assertEqual(type(strict_client.policy).__name__, "RejectPolicy")
        self.assertEqual(type(trusted_client.policy).__name__, "AutoAddPolicy")


if __name__ == "__main__":
    unittest.main()
