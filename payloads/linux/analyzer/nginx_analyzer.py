# -*- coding: utf-8 -*-
"""
Nginx 采集结果的安全分析封装。

对已采集的 Nginx 配置与状态信息进行分析，产出 security_issues、各维度分析结果，
并写入 nginx_security_analysis.json。
"""

from pathlib import Path
from typing import Any, Dict, List

from .base import SecurityAnalyzerBase


class NginxSecurityAnalyzer(SecurityAnalyzerBase):
    """Nginx 安全策略分析器：基于已采集文件进行分析并写 JSON。"""

    default_analysis_filename = "nginx_security_analysis.json"

    def analysis_template(self) -> Dict[str, Any]:
        return {
            "nginx_status": {},
            "security_issues": [],
            "recommendations": [],
            "configuration_analysis": {},
            "ssl_analysis": {},
            "access_control_analysis": {},
        }

    def get_analyzer_steps(self) -> List[Any]:
        return [
            self._analyze_status,
            self._analyze_configuration,
            self._analyze_ssl,
            self._analyze_access_control,
        ]

    def _analyze_status(self, analysis: Dict[str, Any]) -> None:
        content = self.read_collected_file("status_info/version.txt")
        if not content:
            content = self.read_collected_file("status_info/nginx_version.txt")
        if "nginx" in content.lower():
            analysis["nginx_status"]["nginx_installed"] = True
            analysis["nginx_status"]["version"] = content.strip()
        else:
            analysis["nginx_status"]["nginx_installed"] = False
            self.append_issue(
                analysis,
                "Nginx未安装或不可用",
                severity="low",
                recommendation="如果系统需要Web服务器，请安装Nginx",
            )
        content = self.read_collected_file("status_info/service_status.txt")
        analysis["nginx_status"]["service_running"] = "active (running)" in content.lower()
        if not analysis["nginx_status"]["service_running"]:
            self.append_issue(
                analysis,
                "Nginx服务未运行",
                severity="medium",
                recommendation="启动Nginx服务以确保Web服务可用性",
            )
        content = self.read_collected_file("status_info/config_test.txt")
        analysis["nginx_status"]["config_valid"] = "test is successful" in content.lower()
        if not analysis["nginx_status"]["config_valid"] and content.strip():
            self.append_issue(
                analysis,
                "Nginx配置文件测试失败",
                severity="high",
                recommendation="修复Nginx配置文件错误",
            )

    def _analyze_configuration(self, analysis: Dict[str, Any]) -> None:
        config_content = self.read_collected_file("config_files/nginx.conf")
        if not config_content:
            analysis["configuration_analysis"]["config_file_exists"] = False
            self.append_issue(
                analysis,
                "Nginx配置文件不存在",
                severity="high",
                recommendation="创建Nginx配置文件以进行Web服务配置",
            )
            return
        analysis["configuration_analysis"]["config_file_exists"] = True
        analysis["configuration_analysis"]["config_content"] = config_content
        c = config_content.lower()
        checks = [
            "server_tokens off", "user", "client_max_body_size", "client_body_timeout",
            "client_header_timeout", "keepalive_timeout", "send_timeout", "access_log",
            "error_log", "limit_req", "limit_conn", "add_header", "ssl_protocols",
            "ssl_ciphers", "ssl_prefer_server_ciphers", "deny", "allow", "location",
        ]
        for item in checks:
            analysis["configuration_analysis"][f"has_{item.replace(' ', '_')}"] = item in c
        if "server_tokens off" not in c:
            self.append_issue(
                analysis,
                "未隐藏Nginx版本信息",
                severity="medium",
                recommendation="在配置中添加 'server_tokens off;' 以隐藏版本信息",
            )
        if "user nginx" in c or "user www-data" in c:
            analysis["configuration_analysis"]["proper_user_set"] = True
        else:
            analysis["configuration_analysis"]["proper_user_set"] = False
            self.append_issue(
                analysis,
                "Nginx用户配置可能不安全",
                severity="medium",
                recommendation="确保Nginx以非特权用户运行",
            )
        if "client_max_body_size" not in c:
            self.append_issue(
                analysis,
                "未设置客户端请求体大小限制",
                severity="medium",
                recommendation="设置 client_max_body_size 防止大文件上传攻击",
            )
        if "limit_req" not in c:
            self.append_issue(
                analysis,
                "未设置请求频率限制",
                severity="high",
                recommendation="配置 limit_req 防止DDoS攻击",
            )
        if "add_header" not in c:
            self.append_issue(
                analysis,
                "未配置安全响应头",
                severity="medium",
                recommendation="添加安全响应头如 X-Frame-Options、X-XSS-Protection 等",
            )
        if "ssl_protocols" not in c:
            self.append_issue(
                analysis,
                "未配置SSL协议版本",
                severity="high",
                recommendation="配置现代SSL/TLS协议版本，禁用不安全的协议",
            )

    def _analyze_ssl(self, analysis: Dict[str, Any]) -> None:
        content = self.read_collected_file("status_info/ssl_certificates.txt")
        analysis["ssl_analysis"]["ssl_certificates"] = content
        analysis["ssl_analysis"]["has_ssl_certs"] = bool(content.strip())
        if not analysis["ssl_analysis"]["has_ssl_certs"]:
            self.append_issue(
                analysis,
                "未检测到SSL证书",
                severity="medium",
                recommendation="配置SSL证书以启用HTTPS",
            )
        content = self.read_collected_file("status_info/ssl_private_keys.txt")
        analysis["ssl_analysis"]["ssl_private_keys"] = content
        analysis["ssl_analysis"]["has_ssl_keys"] = bool(content.strip())
        if not analysis["ssl_analysis"]["has_ssl_keys"]:
            self.append_issue(
                analysis,
                "未检测到SSL私钥",
                severity="high",
                recommendation="配置SSL私钥以启用HTTPS",
            )
        analysis["ssl_analysis"]["ssl_connections"] = self.read_collected_file("status_info/nginx_ssl_connections.txt")

    def _analyze_access_control(self, analysis: Dict[str, Any]) -> None:
        analysis["access_control_analysis"]["config_permissions"] = self.read_collected_file("status_info/nginx_config_permissions.txt")
        analysis["access_control_analysis"]["log_permissions"] = self.read_collected_file("status_info/nginx_log_permissions.txt")
