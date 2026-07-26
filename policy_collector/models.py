from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path


class TargetType(str, Enum):
    LINUX = "linux"
    WINDOWS = "windows"
    SECURITY = "security"


class CollectionStatus(str, Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"


@dataclass(frozen=True)
class Credential:
    password: str = field(repr=False)
    sudo_password: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not self.password:
            raise ValueError("密码不能为空")


@dataclass(frozen=True)
class TargetConfig:
    target_type: TargetType
    host: str
    port: int
    username: str
    use_sudo: bool = False
    security_device: str | None = None
    custom_paths: tuple[str, ...] = ()
    container_name: str | None = None
    winrm_https: bool = False
    winrm_insecure: bool = False

    def __post_init__(self) -> None:
        if not self.host or any(ch.isspace() for ch in self.host):
            raise ValueError("目标IP或主机名不能为空，也不能包含空白字符")
        if not 1 <= self.port <= 65535:
            raise ValueError("端口必须在1到65535之间")
        if not self.username:
            raise ValueError("用户名不能为空")
        if self.target_type is TargetType.SECURITY and not self.security_device:
            raise ValueError("安全设备目标必须指定设备类型")

    def public_description(self) -> dict[str, object]:
        description: dict[str, object] = {
            "target_type": self.target_type.value,
            "target_ip": self.host,
            "port": self.port,
            "username": self.username,
        }
        if self.security_device:
            description["security_device"] = self.security_device
        return description


@dataclass(frozen=True)
class ModuleResult:
    name: str
    success: bool
    return_code: int | None = None
    message: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "success": self.success,
            "return_code": self.return_code,
            "message": self.message,
        }


@dataclass
class CollectionReport:
    status: CollectionStatus
    target: TargetConfig
    started_at: datetime
    finished_at: datetime
    run_dir: Path
    modules: list[ModuleResult] = field(default_factory=list)
    error: str | None = None
    cleanup_succeeded: bool | None = None
    check_details: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            **self.target.public_description(),
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "status": self.status.value,
            "successful_modules": [
                item.name for item in self.modules if item.success
            ],
            "failed_modules": [
                item.name for item in self.modules if not item.success
            ],
            "modules": [item.to_dict() for item in self.modules],
            "error": self.error,
            "cleanup_succeeded": self.cleanup_succeeded,
            "check_details": self.check_details,
        }
