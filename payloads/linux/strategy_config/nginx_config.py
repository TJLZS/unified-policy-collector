# -*- coding: utf-8 -*-
"""Nginx 策略：路径与命令的集中配置。"""

from .paths_commands import (
    StrategyPathsConfig,
    StrategyCommandsConfig,
    build_paths_config,
    build_commands_config,
)


def get_nginx_paths_config() -> StrategyPathsConfig:
    """Nginx 策略相关文件/目录路径。"""
    return build_paths_config(
        config_paths=[
            "/etc/nginx/nginx.conf",
            "/etc/nginx/conf.d/",
            "/etc/nginx/sites-available/",
            "/etc/nginx/sites-enabled/",
            "/etc/nginx/snippets/",
            "/etc/nginx/ssl/",
            "/etc/nginx/conf/",
            "/etc/apparmor.d/usr.sbin.nginx",
            "/etc/logrotate.d/nginx",
            "/var/log/nginx/",
        ],
        log_paths=[],
    )


def get_nginx_commands_config() -> StrategyCommandsConfig:
    """Nginx 安全状态与配置采集命令。"""
    all_commands = {
        "version": "nginx -v 2>&1",
        "version_detailed": "nginx -V 2>&1",
        "service_status": "systemctl status nginx 2>/dev/null",
        "service_enabled": "systemctl is-enabled nginx 2>/dev/null",
        "config_test": "nginx -t 2>&1",
        "config_test_detailed": "nginx -T 2>/dev/null",
        "running_processes": "ps aux | grep -E '(nginx|httpd)' | grep -v grep",
        "nginx_ports": "netstat -tlnp | grep nginx 2>/dev/null || ss -tlnp | grep nginx 2>/dev/null",
        "nginx_user": "ps aux | grep nginx | head -1 | awk '{print $1}'",
        "ssl_certificates": "find /etc/nginx -name '*.crt' -o -name '*.pem' 2>/dev/null | head -10",
        "ssl_private_keys": "find /etc/nginx -name '*.key' 2>/dev/null | head -10",
        "ssl_cert_info": "openssl x509 -in /etc/nginx/ssl/*.crt -text -noout 2>/dev/null | head -20",
        "nginx_ssl_connections": "netstat -an | grep :443 | wc -l",
        "nginx_log_files": "find /var/log -name '*nginx*' -type f 2>/dev/null | head -10",
        "nginx_error_log": "tail -20 /var/log/nginx/error.log 2>/dev/null",
        "nginx_access_log": "tail -20 /var/log/nginx/access.log 2>/dev/null",
        "nginx_config_permissions": "ls -la /etc/nginx/ 2>/dev/null",
        "nginx_log_permissions": "ls -la /var/log/nginx/ 2>/dev/null",
        "compiled_modules": "nginx -V 2>&1 | grep -o 'with-[^ ]*'",
        "nginx_connections": "netstat -an | grep :80 | wc -l",
    }
    status_group = dict(all_commands)
    return build_commands_config(
        commands=all_commands,
        status_group=status_group,
        log_group=None,
    )
