# -*- coding: utf-8 -*-
"""
MySQL 采集结果的安全分析封装。

对已采集的 MySQL 配置与状态信息进行分析，产出 security_issues、各维度分析结果，
并写入 mysql_security_analysis.json。
"""

from pathlib import Path
from typing import Any, Dict, List

from .base import SecurityAnalyzerBase


class MysqlSecurityAnalyzer(SecurityAnalyzerBase):
    """MySQL 安全策略分析器：基于已采集文件进行分析并写 JSON。"""

    default_analysis_filename = "mysql_security_analysis.json"

    def analysis_template(self) -> Dict[str, Any]:
        return {
            "mysql_status": {},
            "security_issues": [],
            "recommendations": [],
            "configuration_analysis": {},
            "user_analysis": {},
            "network_analysis": {},
            "ssl_analysis": {},
            "logging_analysis": {},
            "permission_analysis": {},
            "firewall_analysis": {},
        }

    def get_analyzer_steps(self) -> List[Any]:
        return [
            self._analyze_status,
            self._analyze_configuration,
            self._analyze_users,
            self._analyze_networking,
            self._analyze_ssl,
            self._analyze_logging,
            self._analyze_permissions,
            self._analyze_firewall,
        ]

    def _analyze_status(self, analysis: Dict[str, Any]) -> None:
        content = self.read_collected_file("status_info/version.txt")
        if "mysql" in content.lower():
            analysis["mysql_status"]["mysql_installed"] = True
            analysis["mysql_status"]["version"] = content.strip()
        else:
            analysis["mysql_status"]["mysql_installed"] = False
            self.append_issue(
                analysis,
                "MySQL未安装或不可用",
                severity="low",
                recommendation="如果系统需要MySQL，请安装MySQL服务",
            )
        content = self.read_collected_file("status_info/service_status.txt")
        analysis["mysql_status"]["service_running"] = "active (running)" in content.lower()
        if not analysis["mysql_status"]["service_running"]:
            self.append_issue(
                analysis,
                "MySQL服务未运行",
                severity="medium",
                recommendation="启动MySQL服务以确保数据库可用性",
            )

    def _analyze_configuration(self, analysis: Dict[str, Any]) -> None:
        config_content = self.read_collected_file("config_files/my.cnf")
        if not config_content:
            config_content = self.read_collected_file("config_files/mysql.conf.d/mysqld.cnf")
        if not config_content:
            analysis["configuration_analysis"]["config_file_exists"] = False
            self.append_issue(
                analysis,
                "MySQL配置文件不存在",
                severity="medium",
                recommendation="创建MySQL配置文件以进行安全配置",
            )
            return
        analysis["configuration_analysis"]["config_file_exists"] = True
        analysis["configuration_analysis"]["config_content"] = config_content
        c = config_content.lower()
        for key in ["bind-address", "skip-networking", "skip-grant-tables", "local-infile", "secure-file-priv", "log-error", "slow_query_log", "general_log"]:
            analysis["configuration_analysis"][f"has_{key.replace('-', '_')}"] = key in c

    def _analyze_users(self, analysis: Dict[str, Any]) -> None:
        content = self.read_collected_file("status_info/mysql_users.txt")
        analysis["user_analysis"]["users_output"] = content
        lines = [l for l in content.split("\n") if l.strip() and "user" not in l.lower()[:10]]
        analysis["user_analysis"]["user_count"] = len(lines)
        if "''" in content or "anonymous" in content.lower():
            self.append_issue(
                analysis,
                "检测到匿名用户",
                severity="high",
                recommendation="删除匿名用户以提高安全性",
            )
        analysis["user_analysis"]["has_root_user"] = "root" in content.lower()
        content = self.read_collected_file("status_info/mysql_privileges.txt")
        analysis["user_analysis"]["privileges_output"] = content
        if "authentication_string" in content and "''" in content:
            self.append_issue(
                analysis,
                "检测到空密码用户",
                severity="high",
                recommendation="为所有用户设置强密码",
            )

    def _analyze_networking(self, analysis: Dict[str, Any]) -> None:
        content = self.read_collected_file("status_info/mysql_network_interfaces.txt")
        analysis["network_analysis"]["networking_output"] = content
        content = self.read_collected_file("status_info/mysql_ports.txt")
        analysis["network_analysis"]["ports_output"] = content
        analysis["network_analysis"]["default_port"] = ":3306" in content

    def _analyze_ssl(self, analysis: Dict[str, Any]) -> None:
        content = self.read_collected_file("status_info/mysql_ssl_config.txt")
        analysis["ssl_analysis"]["ssl_config_output"] = content
        analysis["ssl_analysis"]["ssl_configured"] = "ssl" in content.lower() and "on" in content.lower()

    def _analyze_logging(self, analysis: Dict[str, Any]) -> None:
        content = self.read_collected_file("status_info/mysql_log_variables.txt")
        analysis["logging_analysis"]["log_variables"] = content
        analysis["logging_analysis"]["error_log_tail"] = self.read_collected_file("status_info/mysql_error_log_tail.txt")

    def _analyze_permissions(self, analysis: Dict[str, Any]) -> None:
        analysis["permission_analysis"]["config_permissions"] = self.read_collected_file("status_info/mysql_config_permissions.txt")
        analysis["permission_analysis"]["data_dir_permissions"] = self.read_collected_file("status_info/mysql_data_dir_permissions.txt")
        analysis["permission_analysis"]["log_dir_permissions"] = self.read_collected_file("status_info/mysql_log_dir_permissions.txt")

    def _analyze_firewall(self, analysis: Dict[str, Any]) -> None:
        content = self.read_collected_file("status_info/firewall_mysql_rules.txt")
        analysis["firewall_analysis"]["firewall_rules"] = content
        analysis["firewall_analysis"]["apparmor_status"] = self.read_collected_file("status_info/apparmor_mysql_status.txt")
        analysis["firewall_analysis"]["selinux_context"] = self.read_collected_file("status_info/selinux_mysql_context.txt")
