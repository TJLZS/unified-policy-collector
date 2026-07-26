# -*- coding: utf-8 -*-
"""密码策略：路径与命令的集中配置。"""

from .paths_commands import (
    StrategyPathsConfig,
    StrategyCommandsConfig,
    build_paths_config,
    build_commands_config,
)


def get_password_policy_paths_config() -> StrategyPathsConfig:
    """密码策略相关文件/目录路径。"""
    return build_paths_config(
        config_paths=[
            "/etc/login.defs",
            "/etc/security/pwquality.conf",
            "/etc/security/pwquality.conf.d/",
            "/etc/security/pam_pwquality.so",
            "/etc/pam.d/system-auth",
            "/etc/pam.d/password-auth",
            "/etc/default/passwd",
            "/etc/default/useradd",
            "/etc/security/opasswd",
        ],
        log_paths=[],
    )


def get_password_policy_commands_config() -> StrategyCommandsConfig:
    """密码策略状态与账户采集命令。"""
    commands = {
        "root_password_policy": "chage -l root 2>/dev/null",
        "password_policy_summary": "grep -E '^PASS_' /etc/login.defs 2>/dev/null",
        "shadow_users": "cat /etc/shadow | awk -F: '{print $1}' 2>/dev/null",
        "passwd_users": "cat /etc/passwd | awk -F: '{print $1}' 2>/dev/null",
    }
    return build_commands_config(
        commands=commands,
        status_group=commands,
        log_group=None,
    )
