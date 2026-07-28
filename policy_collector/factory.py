from __future__ import annotations

from .adapters import (
    CUSTOM_SECURITY_DEVICE_KEY,
    AdapterRegistry,
    SecurityDeviceAdapter,
    default_registry,
)
from .collectors import LinuxCollector, SecurityDeviceCollector, WindowsCollector
from .models import Credential, TargetConfig, TargetType


def create_collector(
    target: TargetConfig,
    credential: Credential,
    *,
    configured_paths: tuple[str, ...] = (),
    registry: AdapterRegistry | None = None,
):
    if target.target_type is TargetType.LINUX:
        return LinuxCollector(target, credential)
    if target.target_type is TargetType.WINDOWS:
        return WindowsCollector(target, credential)
    if target.target_type is TargetType.SECURITY:
        active_registry = registry or default_registry()
        assert target.security_device is not None
        if target.security_device == CUSTOM_SECURITY_DEVICE_KEY:
            assert target.custom_device_name is not None
            adapter = SecurityDeviceAdapter(
                key=CUSTOM_SECURITY_DEVICE_KEY,
                display_name=target.custom_device_name,
                paths=target.custom_paths,
                docker=target.deployment_mode == "docker",
                rule_file_type=target.rule_file_type,
            )
        else:
            adapter = active_registry.resolve(
                target.security_device,
                configured_paths=configured_paths,
                runtime_paths=target.custom_paths,
            )
        return SecurityDeviceCollector(
            target,
            credential,
            adapter=adapter,
        )
    raise ValueError(f"不支持的目标类型: {target.target_type}")
