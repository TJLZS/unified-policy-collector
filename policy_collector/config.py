from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .models import TargetConfig, TargetType


_SENSITIVE_KEYS = {
    "password",
    "passwd",
    "sudo_password",
    "token",
    "secret",
    "authorization",
}


def _reject_sensitive_values(value: Any, path: str = "config") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized = str(key).strip().lower()
            if normalized in _SENSITIVE_KEYS:
                raise ValueError(f"配置文件不得保存敏感字段: {path}.{key}")
            _reject_sensitive_values(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_sensitive_values(child, f"{path}[{index}]")


def load_yaml_config(path: Path) -> dict[str, Any]:
    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError(
            "缺少PyYAML，请先执行 pip install -r requirements.txt"
        ) from exc
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError("YAML配置根节点必须是对象")
    _reject_sensitive_values(data)
    return data


def target_from_mapping(
    mapping: Mapping[str, Any],
) -> tuple[TargetConfig, tuple[str, ...]]:
    _reject_sensitive_values(mapping)
    raw_target = mapping.get("target", {})
    if not isinstance(raw_target, Mapping):
        raise ValueError("target必须是对象")
    try:
        target_type = TargetType(str(raw_target["type"]).lower())
        host = str(raw_target["host"])
        username = str(raw_target["username"])
    except KeyError as exc:
        raise ValueError(f"配置缺少必填字段: target.{exc.args[0]}") from exc
    default_port = 5985 if target_type is TargetType.WINDOWS else 22
    security_device = raw_target.get("security_device")
    target = TargetConfig(
        target_type=target_type,
        host=host,
        port=int(raw_target.get("port", default_port)),
        username=username,
        use_sudo=bool(raw_target.get("use_sudo", False)),
        security_device=(
            str(security_device).lower() if security_device is not None else None
        ),
        container_name=(
            str(raw_target["container_name"])
            if raw_target.get("container_name")
            else None
        ),
        winrm_https=bool(raw_target.get("winrm_https", False)),
        winrm_insecure=bool(raw_target.get("winrm_insecure", False)),
        trust_new_host_key=bool(raw_target.get("trust_new_host_key", False)),
    )

    configured_paths: tuple[str, ...] = ()
    if target.security_device:
        device_configs = mapping.get("security_devices", {})
        if device_configs and not isinstance(device_configs, Mapping):
            raise ValueError("security_devices必须是对象")
        selected = device_configs.get(target.security_device, {})
        if selected and not isinstance(selected, Mapping):
            raise ValueError("安全设备覆盖配置必须是对象")
        paths = selected.get("paths", []) if selected else []
        if paths and (
            not isinstance(paths, list)
            or not all(isinstance(item, str) and item for item in paths)
        ):
            raise ValueError("安全设备paths必须是非空字符串列表")
        configured_paths = tuple(paths)
    return target, configured_paths


def configured_paths_from_mapping(
    mapping: Mapping[str, Any],
    security_device: str,
) -> tuple[str, ...]:
    _reject_sensitive_values(mapping)
    device_configs = mapping.get("security_devices", {})
    if not device_configs:
        return ()
    if not isinstance(device_configs, Mapping):
        raise ValueError("security_devices必须是对象")
    selected = device_configs.get(security_device, {})
    if not selected:
        return ()
    if not isinstance(selected, Mapping):
        raise ValueError("安全设备覆盖配置必须是对象")
    paths = selected.get("paths", [])
    if paths and (
        not isinstance(paths, list)
        or not all(isinstance(item, str) and item for item in paths)
    ):
        raise ValueError("安全设备paths必须是非空字符串列表")
    return tuple(paths)
