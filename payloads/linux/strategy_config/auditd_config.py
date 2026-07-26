# -*- coding: utf-8 -*-
"""Auditd 策略：路径与命令的集中配置。"""

from pathlib import Path
from .paths_commands import (
    StrategyPathsConfig,
    StrategyCommandsConfig,
    build_paths_config,
    build_commands_config,
)


def get_auditd_paths_config() -> StrategyPathsConfig:
    """Auditd 策略相关文件/目录路径。"""
    return build_paths_config(
        config_paths=[
            "/etc/audit/auditd.conf",
            "/etc/audit/audit.rules",
            "/etc/libaudit.conf",
            "/etc/audit/rules.d/",
        ],
        log_paths=[
            "/var/log/audit/audit.log",
        ],
    )


def get_auditd_commands_config() -> StrategyCommandsConfig:
    """Auditd 运行时与状态采集命令。"""
    all_commands = {
        "active_rules": "auditctl -l",
        "status": "auditctl -s",
        "version": "auditctl -v",
        "service_status": "systemctl status auditd",
    }
    status_group = {"active_rules": all_commands["active_rules"], "status": all_commands["status"], "version": all_commands["version"], "service_status": all_commands["service_status"]}
    return build_commands_config(
        commands=all_commands,
        status_group=status_group,
        log_group=None,
    )
