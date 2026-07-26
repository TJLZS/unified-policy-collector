# -*- coding: utf-8 -*-
"""
Apache 安全策略：路径与命令的集中配置。

脚本中通过「路径搜索」和「命令执行」采集策略时，应使用本模块提供的
get_apache_paths_config() 与 get_apache_commands_config()，便于统一维护与修改。
"""

from .paths_commands import (
    StrategyPathsConfig,
    StrategyCommandsConfig,
    build_paths_config,
    build_commands_config,
)


def get_apache_paths_config() -> StrategyPathsConfig:
    """Apache 策略相关文件/目录路径（配置文件、策略文件、日志等）."""
    return build_paths_config(
        config_paths=[
            "/etc/httpd/conf/httpd.conf",
            "/etc/httpd/conf.d/",
            "/etc/apache2/apache2.conf",
            "/etc/apache2/ports.conf",
            "/etc/apparmor.d/usr.sbin.apache2",
            "/etc/apparmor.d/local/usr.sbin.apache2",
            "/etc/systemd/system/httpd.service",
            "/etc/systemd/system/apache2.service",
            "/etc/httpd/conf.d/logging.conf",
            "/etc/apache2/conf-available/security.conf",
            "/etc/logrotate.d/httpd",
            "/etc/logrotate.d/apache2",
        ],
        log_paths=[],
    )


def get_apache_commands_config() -> StrategyCommandsConfig:
    """Apache 安全状态检查与配置采集命令（按组组织）."""
    all_commands = {
        "apache2_version": "apache2 -v 2>/dev/null || httpd -v 2>/dev/null",
        "apache_modules": "apache2ctl -M 2>/dev/null || httpd -M 2>/dev/null",
        "apache_configtest": "apache2ctl configtest 2>/dev/null || httpd -t 2>/dev/null",
        "service_status": "systemctl status httpd 2>/dev/null || systemctl status apache2 2>/dev/null",
        "service_enabled": "systemctl is-enabled httpd 2>/dev/null || systemctl is-enabled apache2 2>/dev/null",
        "running_processes": "ps aux | grep -E '(apache|httpd)' | grep -v grep",
        "apache_ports": "netstat -tlnp | grep -E '(80|443)' 2>/dev/null || ss -tlnp | grep -E '(80|443)' 2>/dev/null",
        "security_modules": "apache2ctl -M 2>/dev/null || httpd -M 2>/dev/null | grep -E '(security|auth|ssl)'",
        "ssl_module": "apache2ctl -M 2>/dev/null || httpd -M 2>/dev/null | grep ssl",
        "user_group": "cat /etc/httpd/conf/httpd.conf 2>/dev/null | grep -E '^User|^Group'",
        "server_tokens": "cat /etc/httpd/conf/httpd.conf 2>/dev/null | grep ServerTokens",
        "server_signature": "cat /etc/httpd/conf/httpd.conf 2>/dev/null | grep ServerSignature",
        "directory_options": "cat /etc/httpd/conf/httpd.conf 2>/dev/null | grep Options",
        "cgi_settings": "cat /etc/httpd/conf/httpd.conf 2>/dev/null | grep -E 'ScriptAlias|ExecCGI'",
        "symlinks": "cat /etc/httpd/conf/httpd.conf 2>/dev/null | grep FollowSymLinks",
        "server_info": "grep -r ServerTokens /etc/apache2/* 2>/dev/null || grep ServerTokens /etc/httpd/conf/* 2>/dev/null",
        "apache_packages": "dpkg -l | grep -E '(apache|httpd)' 2>/dev/null || rpm -qa | grep -E '(apache|httpd)' 2>/dev/null",
        "apache_error_log": "tail -50 /var/log/httpd/error_log 2>/dev/null || tail -50 /var/log/apache2/error.log 2>/dev/null",
        "apache_access_log": "tail -50 /var/log/httpd/access_log 2>/dev/null || tail -50 /var/log/apache2/access.log 2>/dev/null",
        "apache_ssl_log": "tail -50 /var/log/httpd/ssl_access_log 2>/dev/null",
        "apache_service_files": "systemctl cat httpd 2>/dev/null || systemctl cat apache2 2>/dev/null",
        "apache_init_script": "cat /etc/init.d/httpd 2>/dev/null || cat /etc/init.d/apache2 2>/dev/null",
        "firewall_apache_rules": "iptables -L | grep -E '(80|443)' 2>/dev/null || ufw status | grep -E '(80|443)' 2>/dev/null",
        "apparmor_apache_status": "aa-status | grep apache 2>/dev/null",
        "selinux_apache_context": "ls -Z /usr/sbin/httpd 2>/dev/null || ls -Z /usr/sbin/apache2 2>/dev/null || echo 'SELinux not available'",
        "apache_config_permissions": "ls -la /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf 2>/dev/null",
        "apache_log_dir_permissions": "ls -ld /var/log/httpd 2>/dev/null || ls -ld /var/log/apache2 2>/dev/null",
    }
    status_group = dict(all_commands)
    return build_commands_config(
        commands=all_commands,
        status_group=status_group,
        log_group=None,
    )
