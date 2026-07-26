# -*- coding: utf-8 -*-
"""SELinux 策略：路径与命令的集中配置。"""

from .paths_commands import (
    StrategyPathsConfig,
    StrategyCommandsConfig,
    build_paths_config,
    build_commands_config,
)


def get_selinux_paths_config() -> StrategyPathsConfig:
    """SELinux 策略相关文件/目录路径。"""
    return build_paths_config(
        config_paths=[
            "/etc/selinux/config",
            "/etc/selinux/targeted/policy/",
            "/etc/selinux/mls/policy/",
            "/etc/selinux/minimum/policy/",
            "/usr/share/selinux/targeted/",
            "/usr/share/selinux/mls/",
            "/usr/share/selinux/minimum/",
        ],
        log_paths=[
            "/var/log/audit/audit.log",
            "/var/log/audit/",
            "/var/log/messages",
            "/var/log/secure",
        ],
    )


def get_selinux_commands_config() -> StrategyCommandsConfig:
    """SELinux 状态与策略采集命令。"""
    all_commands = {
        "status": "sestatus",
        "mode": "getenforce",
        "policy": "getsebool -a",
        "context": "ls -Z /",
        "modules": "semodule -l",
        "policy_files": "find /etc/selinux -type f -name '*.te' -o -name '*.pp' -o -name '*.fc' -o -name '*.if' 2>/dev/null",
        "policy_dirs": "find /usr/share/selinux -type d 2>/dev/null",
        "binary_policy": "find /etc/selinux -name 'policy.*' 2>/dev/null",
        "config_file": "cat /etc/selinux/config",
        "local_policies": "find /etc/selinux/local -type f 2>/dev/null",
        "custom_policies": "find /usr/share/selinux/custom -type f 2>/dev/null",
        "audit_logs": "grep -i selinux /var/log/audit/audit.log 2>/dev/null | tail -50",
        "messages_logs": "grep -i selinux /var/log/messages 2>/dev/null | tail -50",
        "denied_logs": "ausearch -m avc -ts today 2>/dev/null | head -20",
        "port_contexts": "semanage port -l",
        "network_contexts": "semanage fcontext -l | grep -E '(httpd|ssh|ftp)'",
        "users": "semanage user -l",
        "roles": "semanage role -l",
        "logins": "semanage login -l",
        "file_contexts": "semanage fcontext -l | head -50",
        "boolean_settings": "getsebool -a | head -30",
        "service_status": "systemctl status selinux-policy-mls 2>/dev/null || systemctl status selinux-policy-targeted 2>/dev/null",
        "selinux_service": "systemctl status selinux-autorelabel 2>/dev/null",
        "policy_version": "cat /etc/selinux/targeted/policy/policy.30 2>/dev/null | head -5",
        "selinux_version": "selinux-policy-* --version 2>/dev/null || echo 'SELinux policy version not available'",
    }
    status_group = {
        "selinux_status": all_commands["status"],
        "selinux_mode": all_commands["mode"],
        "selinux_policy": all_commands["policy"],
        "selinux_contexts": all_commands["context"],
        "selinux_modules": all_commands["modules"],
        "port_contexts": all_commands["port_contexts"],
        "network_contexts": all_commands["network_contexts"],
        "selinux_users": all_commands["users"],
        "selinux_roles": all_commands["roles"],
        "selinux_logins": all_commands["logins"],
        "file_contexts": all_commands["file_contexts"],
        "boolean_settings": all_commands["boolean_settings"],
        "service_status": all_commands["service_status"],
        "selinux_service": all_commands["selinux_service"],
        "policy_version": all_commands["policy_version"],
        "selinux_version": all_commands["selinux_version"],
    }
    log_group = {"audit_logs": all_commands["audit_logs"], "messages_logs": all_commands["messages_logs"], "denied_logs": all_commands["denied_logs"]}
    return build_commands_config(
        commands=all_commands,
        status_group=status_group,
        log_group=log_group,
    )
