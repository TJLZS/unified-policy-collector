# -*- coding: utf-8 -*-
"""AppArmor 策略：路径与命令的集中配置。"""

from .paths_commands import (
    StrategyPathsConfig,
    StrategyCommandsConfig,
    build_paths_config,
    build_commands_config,
)


def get_apparmor_paths_config() -> StrategyPathsConfig:
    """AppArmor 策略相关文件/目录路径。"""
    return build_paths_config(
        config_paths=[
            "/etc/apparmor/parser.conf",
            "/etc/apparmor/logprof.conf",
            "/etc/apparmor/notify.conf",
            "/etc/apparmor.d/",
            "/usr/share/apparmor/extra-profiles/",
        ],
        log_paths=[],
    )


def get_apparmor_commands_config() -> StrategyCommandsConfig:
    """AppArmor 状态与策略采集命令。"""
    all_commands = {
        "status": "aa-status",
        "version": "apparmor_status --version 2>/dev/null || aa-status --version 2>/dev/null",
        "enforce": "aa-enforce",
        "complain": "aa-complain",
        "disable": "aa-disable",
        "enable": "aa-enable",
        "list_profiles": "aa-status --profiled",
        "list_complaining": "aa-status --complaining",
        "list_enforced": "aa-status --enforced",
        "list_disabled": "aa-status --disabled",
        "main_config": "cat /etc/apparmor/parser.conf 2>/dev/null",
        "log_config": "cat /etc/apparmor/logprof.conf 2>/dev/null",
        "notify_config": "cat /etc/apparmor/notify.conf 2>/dev/null",
        "kernel_modules": "lsmod | grep apparmor",
        "apparmor_service": "systemctl status apparmor 2>/dev/null",
        "apparmor_enabled": "systemctl is-enabled apparmor 2>/dev/null",
        "audit_logs": "grep -i apparmor /var/log/audit/audit.log 2>/dev/null | tail -20",
        "syslog_logs": "grep -i apparmor /var/log/syslog 2>/dev/null | tail -20",
        "messages_logs": "grep -i apparmor /var/log/messages 2>/dev/null | tail -20",
        "apparmor_processes": "ps aux | grep apparmor",
        "confined_processes": "ps -Z | grep -v unconfined",
    }
    status_group = dict(all_commands)
    return build_commands_config(
        commands=all_commands,
        status_group=status_group,
        log_group=None,
    )
