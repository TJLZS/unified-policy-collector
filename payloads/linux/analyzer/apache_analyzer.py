# -*- coding: utf-8 -*-
"""
Apache 采集结果的安全分析封装。

对已采集的 Apache 配置与状态信息进行分析，产出 security_issues、各维度分析结果，
并写入 apache_security_analysis.json。脚本中调用 ApacheSecurityAnalyzer.run() 即可。
"""

from pathlib import Path
from typing import Any, Dict, List

from .base import SecurityAnalyzerBase


class ApacheSecurityAnalyzer(SecurityAnalyzerBase):
    """Apache 安全策略分析器：基于已采集文件进行分析并写 JSON."""

    default_analysis_filename = "apache_security_analysis.json"

    def analysis_template(self) -> Dict[str, Any]:
        return {
            "apache_status": {},
            "security_issues": [],
            "recommendations": [],
            "configuration_analysis": {},
            "module_analysis": {},
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
            self._analyze_modules,
            self._analyze_networking,
            self._analyze_ssl,
            self._analyze_logging,
            self._analyze_permissions,
            self._analyze_firewall,
        ]

    def _analyze_status(self, analysis: Dict[str, Any]) -> None:
        content = self.read_collected_file("status_info/apache2_version.txt")
        if "apache" in content.lower() or "httpd" in content.lower():
            analysis["apache_status"]["apache_installed"] = True
            analysis["apache_status"]["version"] = content.strip()
        else:
            analysis["apache_status"]["apache_installed"] = False
            self.append_issue(
                analysis,
                "Apache未安装或不可用",
                severity="low",
                recommendation="如果系统需要Apache，请安装Apache服务",
            )
        content = self.read_collected_file("status_info/service_status.txt")
        analysis["apache_status"]["service_running"] = "active (running)" in content.lower()
        if not analysis["apache_status"]["service_running"]:
            self.append_issue(
                analysis,
                "Apache服务未运行",
                severity="medium",
                recommendation="启动Apache服务以确保Web服务器可用",
            )

    def _analyze_configuration(self, analysis: Dict[str, Any]) -> None:
        for path in ["/etc/httpd/conf/httpd.conf", "/etc/apache2/apache2.conf"]:
            if Path(path).exists():
                try:
                    config_content = Path(path).read_text(encoding="utf-8", errors="replace")
                except Exception:
                    config_content = ""
                analysis["configuration_analysis"]["config_file_exists"] = True
                analysis["configuration_analysis"]["config_file_path"] = path
                analysis["configuration_analysis"]["config_content"] = config_content
                for key in ["ServerTokens", "ServerSignature", "User", "Group", "Options", "AllowOverride", "ScriptAlias", "FollowSymLinks"]:
                    analysis["configuration_analysis"][f"has_{key.replace('-', '_')}"] = key in config_content
                break
        else:
            analysis["configuration_analysis"]["config_file_exists"] = False
            self.append_issue(
                analysis,
                "Apache配置文件不存在",
                severity="medium",
                recommendation="创建Apache配置文件以进行安全配置",
            )

    def _analyze_modules(self, analysis: Dict[str, Any]) -> None:
        content = self.read_collected_file("status_info/apache_modules.txt")
        analysis["module_analysis"]["modules_output"] = content
        analysis["module_analysis"]["ssl_module_enabled"] = "ssl_module" in content.lower()
        if not analysis["module_analysis"]["ssl_module_enabled"]:
            self.append_issue(
                analysis,
                "Apache SSL模块未启用",
                severity="medium",
                recommendation="启用SSL模块以支持HTTPS加密传输",
            )
        analysis["module_analysis"]["security_modules_enabled"] = "security" in content.lower() or "auth" in content.lower()

    def _analyze_networking(self, analysis: Dict[str, Any]) -> None:
        content = self.read_collected_file("status_info/apache_ports.txt")
        analysis["network_analysis"]["ports_output"] = content
        analysis["network_analysis"]["http_port_enabled"] = ":80" in content
        if ":80" in content:
            self.append_issue(
                analysis,
                "Apache使用默认HTTP端口80",
                severity="low",
                recommendation="考虑是否需要更改HTTP端口以提高安全性",
            )
        analysis["network_analysis"]["https_port_enabled"] = ":443" in content
        if not analysis["network_analysis"]["https_port_enabled"]:
            self.append_issue(
                analysis,
                "Apache HTTPS端口443未监听",
                severity="medium",
                recommendation="启用HTTPS端口以支持SSL/TLS加密传输",
            )

    def _analyze_ssl(self, analysis: Dict[str, Any]) -> None:
        content = self.read_collected_file("status_info/ssl_module.txt")
        analysis["ssl_analysis"]["ssl_output"] = content
        analysis["ssl_analysis"]["ssl_enabled"] = "ssl_module" in content.lower()
        if not analysis["ssl_analysis"]["ssl_enabled"]:
            self.append_issue(
                analysis,
                "Apache SSL/TLS模块未启用",
                severity="high",
                recommendation="启用SSL模块以保护数据传输安全",
            )

    def _analyze_logging(self, analysis: Dict[str, Any]) -> None:
        analysis["logging_analysis"]["error_log_output"] = self.read_collected_file("status_info/apache_error_log.txt")
        analysis["logging_analysis"]["error_log_enabled"] = bool(analysis["logging_analysis"]["error_log_output"])
        analysis["logging_analysis"]["access_log_output"] = self.read_collected_file("status_info/apache_access_log.txt")
        analysis["logging_analysis"]["access_log_enabled"] = bool(analysis["logging_analysis"]["access_log_output"])
        if not analysis["logging_analysis"]["access_log_enabled"]:
            self.append_issue(
                analysis,
                "Apache访问日志未启用",
                severity="medium",
                recommendation="启用访问日志以监控Web服务器访问情况",
            )

    def _analyze_permissions(self, analysis: Dict[str, Any]) -> None:
        analysis["permission_analysis"]["config_permissions"] = self.read_collected_file("status_info/apache_config_permissions.txt")
        analysis["permission_analysis"]["log_dir_permissions"] = self.read_collected_file("status_info/apache_log_dir_permissions.txt")
        perm = analysis["permission_analysis"]["config_permissions"]
        if "rw-rw-rw-" in perm or "rwxrwxrwx" in perm:
            self.append_issue(
                analysis,
                "Apache配置文件权限过于宽松",
                severity="high",
                recommendation="限制配置文件权限，建议设置为644",
            )

    def _analyze_firewall(self, analysis: Dict[str, Any]) -> None:
        content = self.read_collected_file("status_info/firewall_apache_rules.txt")
        analysis["firewall_analysis"]["firewall_rules"] = content
        analysis["firewall_analysis"]["apache_rules_exist"] = (
            "80" in content or "443" in content or "http" in content.lower() or "apache" in content.lower()
        )
        if not analysis["firewall_analysis"]["apache_rules_exist"]:
            self.append_issue(
                analysis,
                "未检测到Apache防火墙规则",
                severity="medium",
                recommendation="配置防火墙规则限制Apache访问",
            )
        apparmor = self.read_collected_file("status_info/apparmor_apache_status.txt")
        analysis["firewall_analysis"]["apparmor_status"] = apparmor
        analysis["firewall_analysis"]["apparmor_apache_enabled"] = "apache" in apparmor.lower()
        if not analysis["firewall_analysis"]["apparmor_apache_enabled"]:
            self.append_issue(
                analysis,
                "Apache AppArmor策略未启用",
                severity="medium",
                recommendation="启用Apache AppArmor策略以提高安全性",
            )
