# -*- coding: utf-8 -*-
"""TCP_Wrappers 策略：路径与命令的集中配置。"""

from .paths_commands import (
    StrategyPathsConfig,
    StrategyCommandsConfig,
    build_paths_config,
    build_commands_config,
)


def get_tcp_wrappers_paths_config() -> StrategyPathsConfig:
    """TCP_Wrappers 相关配置文件路径。"""
    return build_paths_config(
        config_paths=[
            "/etc/hosts.allow",
            "/etc/hosts.deny",
            "/etc/hosts",
            "/etc/networks",
            "/etc/protocols",
            "/etc/services",
            "/etc/hosts.equiv",
            "/etc/shosts.equiv",
            "/etc/hosts.allow.d/",
            "/etc/hosts.deny.d/",
        ],
        log_paths=[],
    )


def get_tcp_wrappers_commands_config() -> StrategyCommandsConfig:
    """TCP_Wrappers 相关命令（库依赖、服务、端口等）。"""
    all_commands = {
        "which_tcpd": "which tcpd",
        "libwrap_find": "find /lib* /usr/lib* -name '*libwrap*' 2>/dev/null",
        "sshd_libwrap": "ldd /usr/sbin/sshd 2>/dev/null | grep -i wrap",
        "vsftpd_libwrap": "ldd /usr/sbin/vsftpd 2>/dev/null | grep -i wrap",
        "syslog_tcp_wrappers": "grep -i 'tcp_wrappers\\|hosts.allow\\|hosts.deny' /var/log/syslog 2>/dev/null | tail -20",
        "messages_tcp_wrappers": "grep -i 'tcp_wrappers\\|hosts.allow\\|hosts.deny' /var/log/messages 2>/dev/null | tail -20",
        "systemd_services": "systemctl list-units --type=service 2>/dev/null | grep -E '(ssh|ftp|telnet|rsh)'",
        "netstat_ports": "netstat -tulpn 2>/dev/null | grep -E ':(22|21|23|513|514)'",
        "ss_ports": "ss -tulpn 2>/dev/null | grep -E ':(22|21|23|513|514)'",
    }
    status_group = dict(all_commands)
    return build_commands_config(
        commands=all_commands,
        status_group=status_group,
        log_group=None,
    )
