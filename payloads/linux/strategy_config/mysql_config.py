# -*- coding: utf-8 -*-
"""MySQL 策略：路径与命令的集中配置。"""

from .paths_commands import (
    StrategyPathsConfig,
    StrategyCommandsConfig,
    build_paths_config,
    build_commands_config,
)


def get_mysql_paths_config() -> StrategyPathsConfig:
    """MySQL 策略相关文件/目录路径。"""
    return build_paths_config(
        config_paths=[
            "/etc/my.cnf",
            "/etc/mysql/my.cnf",
            "/etc/mysql/conf.d/",
            "/etc/mysql/mysql.conf.d/",
            "/etc/mysql/mariadb.conf.d/",
            "/etc/apparmor.d/usr.sbin.mysqld",
            "/etc/apparmor.d/local/usr.sbin.mysqld",
            "/etc/systemd/system/mysql.service",
            "/etc/systemd/system/mysqld.service",
            "/etc/logrotate.d/mysql",
            "/etc/selinux/targeted/contexts/files/file_contexts.local",
            "/etc/selinux/targeted/modules/active/modules/mysql.pp",
            "/etc/firewalld/services/mysql.xml",
            "/etc/ufw/applications.d/mysql",
            "/etc/init.d/mysql",
            "/etc/init.d/mysqld",
            "/var/lib/mysql/mysql/",
        ],
        log_paths=[],
    )


def get_mysql_commands_config() -> StrategyCommandsConfig:
    """MySQL 安全状态与配置采集命令。"""
    all_commands = {
        "version": "mysql --version 2>/dev/null",
        "mysqld_version": "mysqld --version 2>/dev/null",
        "service_status": "systemctl status mysql 2>/dev/null || systemctl status mysqld 2>/dev/null",
        "service_enabled": "systemctl is-enabled mysql 2>/dev/null || systemctl is-enabled mysqld 2>/dev/null",
        "running_processes": "ps aux | grep -E '(mysql|mysqld)' | grep -v grep",
        "mysql_ports": "netstat -tlnp | grep mysql 2>/dev/null || ss -tlnp | grep mysql 2>/dev/null",
        "mysql_sockets": "ls -la /var/run/mysqld/ 2>/dev/null || ls -la /tmp/mysql.sock 2>/dev/null",
        "mysql_network_interfaces": "mysql -e 'SHOW VARIABLES LIKE \"%bind%\";' 2>/dev/null",
        "mysql_skip_networking": "mysql -e 'SHOW VARIABLES LIKE \"skip_networking\";' 2>/dev/null",
        "mysql_users": "mysql -e 'SELECT user,host FROM mysql.user;' 2>/dev/null",
        "mysql_privileges": "mysql -e 'SELECT user,host,authentication_string FROM mysql.user;' 2>/dev/null",
        "mysql_ssl_config": "mysql -e 'SHOW VARIABLES LIKE \"%ssl%\";' 2>/dev/null",
        "mysql_password_policy": "mysql -e 'SHOW VARIABLES LIKE \"%password%\";' 2>/dev/null",
        "mysql_secure_file_priv": "mysql -e 'SHOW VARIABLES LIKE \"secure_file_priv\";' 2>/dev/null",
        "mysql_local_infile": "mysql -e 'SHOW VARIABLES LIKE \"local_infile\";' 2>/dev/null",
        "mysql_log_variables": "mysql -e \"SHOW VARIABLES LIKE 'log%';\" 2>/dev/null",
        "mysql_databases": "mysql -e 'SHOW DATABASES;' 2>/dev/null",
        "mysql_packages": "dpkg -l | grep mysql 2>/dev/null || rpm -qa | grep mysql 2>/dev/null",
        "mysql_data_dir": "mysql -e 'SELECT @@datadir;' 2>/dev/null",
        "mysql_error_log_tail": "tail -50 /var/log/mysql/error.log 2>/dev/null || tail -50 /var/log/mysqld.log 2>/dev/null",
        "mysql_service_files": "systemctl cat mysql 2>/dev/null || systemctl cat mysqld 2>/dev/null",
        "firewall_mysql_rules": "iptables -L | grep mysql 2>/dev/null || ufw status | grep mysql 2>/dev/null",
        "apparmor_mysql_status": "aa-status | grep mysql 2>/dev/null",
        "selinux_mysql_context": "ls -Z /usr/sbin/mysqld 2>/dev/null || echo 'SELinux not available'",
        "mysql_config_permissions": "ls -la /etc/my.cnf /etc/mysql/my.cnf 2>/dev/null",
        "mysql_data_dir_permissions": "ls -ld /var/lib/mysql 2>/dev/null",
        "mysql_log_dir_permissions": "ls -ld /var/log/mysql 2>/dev/null",
    }
    status_group = dict(all_commands)
    return build_commands_config(
        commands=all_commands,
        status_group=status_group,
        log_group=None,
    )
