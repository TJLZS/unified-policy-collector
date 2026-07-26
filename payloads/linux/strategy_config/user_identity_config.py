# -*- coding: utf-8 -*-
"""
用户身份与组策略：聚合配置入口。

本模块聚合以下子模块的路径与命令配置：
- pam_config: PAM 安全配置
- ssh_config: SSH 安全配置
- ssl_config: SSL/TLS 安全配置
- password_policy_config: 密码策略
- user_environment_config: 用户环境安全

各子模块提供独立的 get_xxx_paths_config() 与 get_xxx_commands_config()，
脚本可按模块分别导入使用；本模块提供聚合后的 get_user_identity_paths_config()
与 get_user_identity_commands_config() 用于统一采集。
"""

from .paths_commands import (
    StrategyPathsConfig,
    StrategyCommandsConfig,
    build_paths_config,
    build_commands_config,
)
from .pam_config import get_pam_paths_config, get_pam_commands_config
from .ssh_config import get_ssh_paths_config, get_ssh_commands_config
from .ssl_config import get_ssl_paths_config, get_ssl_commands_config
from .password_policy_config import (
    get_password_policy_paths_config,
    get_password_policy_commands_config,
)
from .user_environment_config import (
    get_user_environment_paths_config,
    get_user_environment_commands_config,
)


def get_user_identity_paths_config() -> StrategyPathsConfig:
    """用户身份与组策略相关文件/目录路径（聚合 PAM/SSH/SSL/密码策略/用户环境）。"""
    paths = []
    for getter in [
        get_pam_paths_config,
        get_ssh_paths_config,
        get_ssl_paths_config,
        get_password_policy_paths_config,
        get_user_environment_paths_config,
    ]:
        cfg = getter()
        paths.extend(cfg.config_paths)
        paths.extend(cfg.log_paths)
    # 去重并保持顺序
    seen = set()
    unique_paths = []
    for p in paths:
        if p not in seen:
            seen.add(p)
            unique_paths.append(p)
    return build_paths_config(
        config_paths=unique_paths,
        log_paths=[],
    )


def get_user_identity_commands_config() -> StrategyCommandsConfig:
    """PAM/SSH/SSL/密码策略/用户环境相关命令（聚合）。"""
    pam_cfg = get_pam_commands_config()
    ssh_cfg = get_ssh_commands_config()
    ssl_cfg = get_ssl_commands_config()
    pw_cfg = get_password_policy_commands_config()
    env_cfg = get_user_environment_commands_config()

    all_commands = {}
    all_commands.update(pam_cfg.get_all_commands())
    all_commands.update(ssh_cfg.get_all_commands())
    all_commands.update(ssl_cfg.get_all_commands())
    all_commands.update(pw_cfg.get_all_commands())
    all_commands.update(env_cfg.get_all_commands())

    return build_commands_config(
        commands=all_commands,
        status_group=all_commands,
        log_group=None,
        extra_groups={
            "pam": pam_cfg.get_all_commands(),
            "ssh": ssh_cfg.get_all_commands(),
            "ssl": ssl_cfg.get_all_commands(),
            "password": pw_cfg.get_all_commands(),
            "user_env": env_cfg.get_all_commands(),
        },
    )
