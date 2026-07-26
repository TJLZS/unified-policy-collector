# -*- coding: utf-8 -*-
"""chkrootkit 策略：路径与命令的集中配置。"""

from .paths_commands import (
    StrategyPathsConfig,
    StrategyCommandsConfig,
    build_paths_config,
    build_commands_config,
)


def get_chkrootkit_paths_config() -> StrategyPathsConfig:
    """chkrootkit 相关配置文件/目录路径。"""
    return build_paths_config(
        config_paths=[
            "/etc/chkrootkit.conf",
            "/etc/chkrootkit/",
            "/usr/local/etc/chkrootkit.conf",
            "/usr/local/etc/chkrootkit/",
            "/etc/default/chkrootkit",
            "/etc/sysconfig/chkrootkit",
            "/usr/share/chkrootkit/",
            "/opt/chkrootkit/",
        ],
        log_paths=[],
    )


def get_chkrootkit_commands_config() -> StrategyCommandsConfig:
    """chkrootkit 状态与相关工具采集命令。"""
    all_commands = {
        "version": "chkrootkit --version",
        "help": "chkrootkit --help",
        "location": "which chkrootkit",
        "config_file": "cat /etc/chkrootkit.conf 2>/dev/null",
        "config_dir": "ls -la /etc/chkrootkit* 2>/dev/null",
        "log_files": "find /var/log -name '*chkrootkit*' -o -name '*rootkit*' 2>/dev/null",
        "rkhunter_check": "which rkhunter 2>/dev/null",
        "aide_check": "which aide 2>/dev/null",
        "tripwire_check": "which tripwire 2>/dev/null",
        "kernel_modules": "lsmod | head -20",
        "suspicious_files": "find /tmp /var/tmp -type f -perm -002 2>/dev/null | head -20",
        "network_connections": "netstat -tulpn 2>/dev/null | head -20",
        "network_connections_ss": "ss -tulpn 2>/dev/null | head -20",
        "running_processes": "ps aux | head -20",
        "mount_points": "mount | grep -v tmpfs",
        "disk_usage": "df -h",
    }
    status_group = {
        "chkrootkit_version": all_commands["version"],
        "chkrootkit_help": all_commands["help"],
        **{k: v for k, v in all_commands.items() if k not in ("version", "help")},
    }
    return build_commands_config(
        commands=all_commands,
        status_group=status_group,
        log_group=None,
    )
