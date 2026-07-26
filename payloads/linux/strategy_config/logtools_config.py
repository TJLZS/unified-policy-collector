# -*- coding: utf-8 -*-
"""日志分析工具策略（Logwatch / swatchdog）：路径与命令的集中配置。"""

from .paths_commands import (
    StrategyPathsConfig,
    StrategyCommandsConfig,
    build_paths_config,
    build_commands_config,
)


def get_logtools_paths_config() -> StrategyPathsConfig:
    """日志分析工具相关文件/目录路径（Logwatch + swatchdog）。"""
    return build_paths_config(
        config_paths=[
            "/usr/share/logwatch/default.conf/",
            "/etc/logwatch/conf/dist.conf/",
            "/etc/logwatch/conf/dist.conf",
            "/etc/logwatch/conf/",
            "/etc/systemd/system/swatchdog.service",
            "/etc/swatchdog.conf",
            "/etc/swatch.d",
            "/etc/swatchdog/swatchdog.conf",
            "/etc/init.d/swatchdog",
        ],
        log_paths=[],
    )


def get_logtools_commands_config() -> StrategyCommandsConfig:
    """Logwatch / swatchdog 状态与采集命令。"""
    logwatch_commands = {
        "executable_path": "which logwatch",
        "version": "logwatch --version 2>/dev/null || echo '版本信息不可用'",
        "cron_jobs": "crontab -l | grep -i logwatch || echo '未找到Logwatch定时任务'",
    }
    all_commands = dict(logwatch_commands)
    return build_commands_config(
        commands=all_commands,
        status_group=all_commands,
        log_group=None,
        extra_groups={"logwatch": logwatch_commands},
    )
