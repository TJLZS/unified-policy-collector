# -*- coding: utf-8 -*-
"""用户环境安全策略：路径与命令的集中配置。"""

from .paths_commands import (
    StrategyPathsConfig,
    StrategyCommandsConfig,
    build_paths_config,
    build_commands_config,
)


def get_user_environment_paths_config() -> StrategyPathsConfig:
    """用户环境策略相关文件/目录路径。"""
    return build_paths_config(
        config_paths=[
            "/etc/profile",
            "/etc/bashrc",
            "/etc/skel/",
            "/etc/environment",
            "/etc/profile.d/",
            "/etc/shells",
            "/etc/securetty",
            "/etc/security/limits.conf",
            "/etc/security/limits.d/",
            "/etc/default/useradd",
            "/etc/group-",
            "/etc/gshadow",
            "/etc/gshadow-",
            "/etc/subuid",
            "/etc/subgid",
            "/etc/login.defs",
        ],
        log_paths=[],
    )


def get_user_environment_commands_config() -> StrategyCommandsConfig:
    """用户环境与权限采集命令。"""
    commands = {
        "passwd": "cat /etc/passwd",
        "group": "cat /etc/group",
        "sudoers": "cat /etc/sudoers",
        "sudoers_directory": "ls -la /etc/sudoers.d/ 2>/dev/null",
        "sudoers_d_contents": "cat /etc/sudoers.d/* 2>/dev/null",
        "current_umask": "umask",
        "umask_settings": "grep -r umask /etc/profile /etc/bashrc /etc/profile.d/ 2>/dev/null",
    }
    return build_commands_config(
        commands=commands,
        status_group=commands,
        log_group=None,
    )
