# -*- coding: utf-8 -*-
"""
安全策略收集：路径与命令的集中配置。

- StrategyPathsConfig: 策略文件/目录路径配置
- StrategyCommandsConfig: 采集用命令配置
- 各策略 get_xxx_paths_config / get_xxx_commands_config 见对应模块
- 分析器见 analyzer 包（与 strategy_config 同级）
"""

from .paths_commands import (
    StrategyPathsConfig,
    StrategyCommandsConfig,
    PathItem,
    CommandGroup,
)
# SecurityAnalyzerBase、AnalysisResult 及各策略分析器见 analyzer 包
from analyzer import SecurityAnalyzerBase, AnalysisResult

# 策略配置（按需导入）
# from .apache_config import get_apache_paths_config, get_apache_commands_config
# from .selinux_config import get_selinux_paths_config, get_selinux_commands_config
# from .nginx_config import get_nginx_paths_config, get_nginx_commands_config
# from .mysql_config import get_mysql_paths_config, get_mysql_commands_config
# from .k8s_config import get_k8s_paths_config, get_k8s_commands_config
# from .user_identity_config import get_user_identity_paths_config, get_user_identity_commands_config
# from .pam_config import get_pam_paths_config, get_pam_commands_config
# from .ssh_config import get_ssh_paths_config, get_ssh_commands_config
# from .ssl_config import get_ssl_paths_config, get_ssl_commands_config
# from .password_policy_config import get_password_policy_paths_config, get_password_policy_commands_config
# from .user_environment_config import get_user_environment_paths_config, get_user_environment_commands_config
# from .logtools_config import get_logtools_paths_config, get_logtools_commands_config

__all__ = [
    "StrategyPathsConfig",
    "StrategyCommandsConfig",
    "PathItem",
    "CommandGroup",
    "SecurityAnalyzerBase",
    "AnalysisResult",
]
