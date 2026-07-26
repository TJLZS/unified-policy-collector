# -*- coding: utf-8 -*-
"""SSH 安全策略：路径与命令的集中配置。"""

from .paths_commands import (
    StrategyPathsConfig,
    StrategyCommandsConfig,
    build_paths_config,
    build_commands_config,
)


def get_ssh_paths_config() -> StrategyPathsConfig:
    """SSH 策略相关文件/目录路径。"""
    return build_paths_config(
        config_paths=[
            "/etc/ssh/sshd_config",
            "/etc/ssh/ssh_config",
            "/etc/ssh/ssh_host_keys/",
            "/etc/ssh/moduli",
            "/etc/hosts.allow",
            "/etc/hosts.deny",
            "/etc/ssh/ssh_config.d/",
            "/root/.ssh/",
            "/etc/ssh/sshd_config.d/",
        ],
        log_paths=[],
    )


def get_ssh_commands_config() -> StrategyCommandsConfig:
    """SSH 状态与密钥采集命令。"""
    commands = {
        "ssh_host_keys": "find /etc/ssh -name 'ssh_host_*' -ls 2>/dev/null",
        "sshd_effective_config": "sshd -T 2>/dev/null",
        "ssh_version": "ssh -V 2>&1",
        "ssh_connections": "netstat -tulpn | grep :22 2>/dev/null",
        "ssh_connections_ss": "ss -tulpn | grep :22 2>/dev/null",
        "recent_logins": "last | head -20 2>/dev/null",
        "current_users": "who",
    }
    return build_commands_config(
        commands=commands,
        status_group=commands,
        log_group=None,
    )
