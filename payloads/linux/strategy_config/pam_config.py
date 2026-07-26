# -*- coding: utf-8 -*-
"""PAM 安全策略：路径与命令的集中配置。"""

from .paths_commands import (
    StrategyPathsConfig,
    StrategyCommandsConfig,
    build_paths_config,
    build_commands_config,
)


def get_pam_paths_config() -> StrategyPathsConfig:
    """PAM 策略相关文件/目录路径。"""
    return build_paths_config(
        config_paths=[
            "/etc/pam.d/",
            "/etc/pam.conf",
            "/etc/security/",
            "/etc/nsswitch.conf",
            "/etc/security/access.conf",
            "/etc/security/time.conf",
            "/etc/security/namespace.conf",
        ],
        log_paths=[],
    )


def get_pam_commands_config() -> StrategyCommandsConfig:
    """PAM 状态与模块采集命令。"""
    commands = {
        "pam_modules": "find /lib* -name 'pam_*.so' -ls 2>/dev/null",
        "pam_packages": "rpm -qa | grep pam 2>/dev/null",
        "pam_packages_debian": "dpkg -l | grep pam 2>/dev/null",
    }
    return build_commands_config(
        commands=commands,
        status_group=commands,
        log_group=None,
    )
