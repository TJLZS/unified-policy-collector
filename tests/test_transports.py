import base64
import re
import tempfile
import unittest
from pathlib import Path

from policy_collector.models import Credential, TargetConfig, TargetType
from policy_collector.transports import WinRMTransport


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


if __name__ == "__main__":
    unittest.main()
