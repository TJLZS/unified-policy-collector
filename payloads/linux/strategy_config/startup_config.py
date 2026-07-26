# -*- coding: utf-8 -*-
"""启动项与计划任务策略：路径与命令的集中配置。"""

from pathlib import Path
from .paths_commands import (
    StrategyPathsConfig,
    StrategyCommandsConfig,
    build_paths_config,
    build_commands_config,
)


def get_startup_systemd_paths() -> list:
    """systemd 服务目录路径。"""
    return [
        "/usr/lib/systemd/system/",
        "/etc/systemd/system/",
        "/lib/systemd/system/",
    ]


def get_startup_init_paths() -> list:
    """SysV init 脚本与 rc 路径。"""
    return [
        "/etc/init.d/",
        "/etc/rc.d/",
        "/etc/rc.local",
    ]


def get_startup_autostart_paths() -> list:
    """用户与系统级 autostart 目录（需 expanduser）。"""
    return [
        "~/.config/autostart/",
        "/etc/xdg/autostart/",
    ]


def get_startup_user_files() -> list:
    """用户 shell 配置文件（需 expanduser）。"""
    return [
        "~/.bashrc",
        "~/.bash_profile",
        "~/.profile",
        "~/.xinitrc",
        "~/.xsession",
    ]


def get_startup_paths_config() -> StrategyPathsConfig:
    """启动项相关路径（合并 systemd / init / autostart）。"""
    return build_paths_config(
        config_paths=get_startup_systemd_paths() + get_startup_init_paths(),
        log_paths=[],
        extra_paths=[
            (str(Path(p).expanduser()), "autostart") for p in get_startup_autostart_paths()
        ] + [(str(Path(p).expanduser()), "user_shell") for p in get_startup_user_files()],
    )


def get_startup_commands_config() -> StrategyCommandsConfig:
    """启动项与计划任务状态采集命令。"""
    commands = {
        "enabled_services": "systemctl list-unit-files --type=service --state=enabled",
        "systemctl_version": "systemctl --version",
        "lsmod": "lsmod",
        "boot_time": "who -b",
        "cron_status": "systemctl status cron 2>/dev/null || systemctl status crond 2>/dev/null",
    }
    return build_commands_config(
        commands=commands,
        status_group=commands,
        log_group=None,
    )
