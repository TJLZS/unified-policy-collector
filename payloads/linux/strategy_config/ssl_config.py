# -*- coding: utf-8 -*-
"""SSL/TLS 安全策略：路径与命令的集中配置。"""

from .paths_commands import (
    StrategyPathsConfig,
    StrategyCommandsConfig,
    build_paths_config,
    build_commands_config,
)


def get_ssl_paths_config() -> StrategyPathsConfig:
    """SSL 策略相关文件/目录路径。"""
    return build_paths_config(
        config_paths=[
            "/etc/ssl/",
            "/etc/pki/tls/",
            "/etc/openssl/",
            "/etc/ca-certificates/",
            "/etc/ssl/openssl.cnf",
        ],
        log_paths=[],
    )


def get_ssl_commands_config() -> StrategyCommandsConfig:
    """SSL 证书与版本采集命令。"""
    commands = {
        "ca_trust_status": "update-ca-trust status",
        "ssl_certificates": "find /etc/ssl/certs -type f -name '*.pem' | head -20",
        "openssl_version": "openssl version 2>/dev/null",
        "ssl_ciphers": "openssl ciphers -v",
    }
    return build_commands_config(
        commands=commands,
        status_group=commands,
        log_group=None,
    )
