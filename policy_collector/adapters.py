from __future__ import annotations

from dataclasses import dataclass, replace


@dataclass(frozen=True)
class SecurityDeviceAdapter:
    key: str
    display_name: str
    paths: tuple[str, ...]
    status_commands: tuple[str, ...] = ()
    docker: bool = False
    container_patterns: tuple[str, ...] = ()


class AdapterRegistry:
    """安全设备适配器注册表，是CLI和设备实现之间的稳定接缝。"""

    def __init__(self) -> None:
        self._adapters: dict[str, SecurityDeviceAdapter] = {}
        self._aliases: dict[str, str] = {}

    def register(
        self,
        adapter: SecurityDeviceAdapter,
        *,
        aliases: tuple[str, ...] = (),
    ) -> None:
        if adapter.key in self._adapters:
            raise ValueError(f"安全设备适配器已存在: {adapter.key}")
        self._adapters[adapter.key] = adapter
        for alias in aliases:
            self._aliases[alias.lower()] = adapter.key

    def keys(self) -> tuple[str, ...]:
        return tuple(self._adapters)

    def all(self) -> tuple[SecurityDeviceAdapter, ...]:
        return tuple(self._adapters.values())

    def resolve(
        self,
        key: str,
        *,
        configured_paths: tuple[str, ...] = (),
        runtime_paths: tuple[str, ...] = (),
    ) -> SecurityDeviceAdapter:
        canonical = self._aliases.get(key.lower(), key.lower())
        try:
            adapter = self._adapters[canonical]
        except KeyError as exc:
            raise ValueError(f"不支持的安全设备类型: {key}") from exc
        paths = runtime_paths or configured_paths or adapter.paths
        return replace(adapter, paths=tuple(paths))


def default_registry() -> AdapterRegistry:
    registry = AdapterRegistry()
    registry.register(
        SecurityDeviceAdapter(
            key="suricata",
            display_name="Suricata",
            paths=(
                "/etc/suricata/rules",
                "/var/lib/suricata/rules",
                "**/suricata/rules",
            ),
            status_commands=(
                "suricata --build-info",
                "systemctl status suricata --no-pager",
            ),
        )
    )
    registry.register(
        SecurityDeviceAdapter(
            key="snort",
            display_name="Snort",
            paths=(
                "/etc/snort/rules",
                "/usr/local/etc/snort/rules",
                "**/snort/rules",
                "**/scripts/policy",
                "**/scripts/site",
            ),
            status_commands=("snort -V", "systemctl status snort --no-pager"),
        )
    )
    registry.register(
        SecurityDeviceAdapter(
            key="modsecurity",
            display_name="ModSecurity",
            paths=(
                "/etc/modsecurity",
                "/etc/nginx/modsecurity",
                "/usr/local/modsecurity",
                "**/crs4/rules",
            ),
            status_commands=(
                "nginx -V 2>&1 | grep -i modsecurity",
                "apachectl -M 2>&1 | grep -i security",
            ),
        ),
        aliases=("ModSecurity",),
    )
    registry.register(
        SecurityDeviceAdapter(
            key="zeek",
            display_name="Zeek",
            paths=(
                "/opt/zeek/share/zeek/policy",
                "/usr/local/zeek/share/zeek/policy",
                "/usr/share/zeek/policy",
                "**/zeek/share/zeek/policy",
            ),
            status_commands=("zeek --version", "zeekctl status"),
        )
    )
    registry.register(
        SecurityDeviceAdapter(
            key="nuclei",
            display_name="Nuclei",
            paths=(
                "/root/nuclei-templates",
                "/opt/nuclei-templates",
                "**/nuclei-templates",
            ),
            status_commands=("nuclei -version",),
        )
    )
    registry.register(
        SecurityDeviceAdapter(
            key="bt_waf",
            display_name="堡塔云WAF",
            paths=("/etc/nginx/waf/rule",),
            docker=True,
            container_patterns=("btwaf", "bt-waf", "baota", "堡塔"),
        ),
        aliases=("堡塔云waf", "堡塔云WAF"),
    )
    registry.register(
        SecurityDeviceAdapter(
            key="uuwaf",
            display_name="南墙uuwaf",
            paths=("/uuwaf/waf/plugins",),
            docker=True,
            container_patterns=("uuwaf", "southwall", "南墙"),
        ),
        aliases=("南墙uuwaf",),
    )
    return registry
