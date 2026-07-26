# -*- coding: utf-8 -*-
"""Firewall 策略（iptables / firewalld）：路径与命令的集中配置。"""

from .paths_commands import (
    StrategyPathsConfig,
    StrategyCommandsConfig,
    build_paths_config,
    build_commands_config,
)


def get_iptables_paths_config() -> StrategyPathsConfig:
    """iptables 相关配置文件路径（合并 debian/redhat/通用）。"""
    return build_paths_config(
        config_paths=[
            "/etc/iptables/",
            "/etc/iptables/rules.v4",
            "/etc/iptables/rules.v6",
            "/etc/sysconfig/iptables",
            "/etc/sysconfig/ip6tables",
        ],
        log_paths=[],
    )


def get_firewalld_paths_config() -> StrategyPathsConfig:
    """firewalld 相关配置文件路径。"""
    return build_paths_config(
        config_paths=[
            "/etc/firewalld/firewalld.conf",
            "/etc/firewalld/zones/",
            "/etc/firewalld/services/",
            "/etc/firewalld/policies/",
            "/usr/lib/firewalld/zones/",
            "/usr/lib/firewalld/services/",
            "/usr/lib/firewalld/policies/",
        ],
        log_paths=[],
    )


def get_firewall_commands_config() -> StrategyCommandsConfig:
    """iptables / firewalld 状态与规则采集命令。"""
    all_commands = {
        "iptables_rules_ipv4": "iptables -L -n -v",
        "iptables_nat_rules": "iptables -t nat -L -n -v",
        "iptables_mangle_rules": "iptables -t mangle -L -n -v",
        "iptables_raw_rules": "iptables -t raw -L -n -v",
        "ip6tables_rules_ipv6": "ip6tables -L -n -v",
        "iptables_rule_count": "iptables -L -n | wc -l",
        "iptables_service_status": "systemctl status iptables 2>/dev/null",
        "iptables_enabled": "systemctl is-enabled iptables 2>/dev/null",
        "iptables_version": "iptables --version",
        "ip6tables_version": "ip6tables --version",
        "firewall_cmd_state": "firewall-cmd --state 2>/dev/null",
        "firewall_cmd_list_all": "firewall-cmd --list-all 2>/dev/null",
        "firewall_cmd_list_zones": "firewall-cmd --list-zones 2>/dev/null",
        "firewall_cmd_list_services": "firewall-cmd --list-services 2>/dev/null",
    }
    status_group = dict(all_commands)
    return build_commands_config(
        commands=all_commands,
        status_group=status_group,
        log_group=None,
    )
