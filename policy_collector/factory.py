from __future__ import annotations

from .adapters import AdapterRegistry, default_registry
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
