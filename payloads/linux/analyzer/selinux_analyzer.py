# -*- coding: utf-8 -*-
"""
SELinux 采集结果的安全分析封装。

对已采集的 SELinux 配置与状态信息进行分析，产出 security_issues、各维度分析结果，
并写入 selinux_security_analysis.json。
"""

from pathlib import Path
from typing import Any, Dict, List

from .base import SecurityAnalyzerBase


class SelinuxSecurityAnalyzer(SecurityAnalyzerBase):
    """SELinux 安全策略分析器：基于已采集文件进行分析并写 JSON。"""

    default_analysis_filename = "selinux_security_analysis.json"

    def analysis_template(self) -> Dict[str, Any]:
        return {
            "selinux_status": {},
            "security_issues": [],
            "recommendations": [],
            "policy_analysis": {},
            "configuration_analysis": {},
        }

    def get_analyzer_steps(self) -> List[Any]:
        return [
            self._analyze_status,
            self._analyze_configuration,
            self._analyze_policy,
        ]

    def _analyze_status(self, analysis: Dict[str, Any]) -> None:
        content = self.read_collected_file("status_info/selinux_status.txt")
        analysis["selinux_status"]["status_output"] = content
        if "SELinux status: enabled" in content:
            analysis["selinux_status"]["enabled"] = True
        else:
            analysis["selinux_status"]["enabled"] = False
            self.append_issue(
                analysis,
                "SELinux未启用",
                severity="high",
                recommendation="启用SELinux以增强系统安全",
            )
        mode_content = self.read_collected_file("status_info/selinux_mode.txt")
        current_mode = mode_content.strip().split("\n")[-1].strip() if mode_content else ""
        analysis["selinux_status"]["current_mode"] = current_mode
        if current_mode.lower() == "disabled":
            self.append_issue(
                analysis,
                f"SELinux模式为{current_mode}",
                severity="high",
                recommendation="将SELinux模式设置为enforcing或permissive",
            )
        elif current_mode.lower() == "permissive":
            self.append_issue(
                analysis,
                f"SELinux模式为{current_mode}",
                severity="medium",
                recommendation="考虑将SELinux模式设置为enforcing",
            )
        for line in content.split("\n"):
            if "Policy from config file:" in line:
                analysis["selinux_status"]["policy_type"] = line.split(":", 1)[1].strip()
                break

    def _analyze_configuration(self, analysis: Dict[str, Any]) -> None:
        config_content = self.read_collected_file("config_files/config")
        if config_content:
            analysis["configuration_analysis"]["config_exists"] = True
            analysis["configuration_analysis"]["config_content"] = config_content
            for line in config_content.split("\n"):
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    key, value = key.strip(), value.strip()
                    if key == "SELINUX":
                        analysis["configuration_analysis"]["selinux_mode"] = value
                        if value.lower() == "disabled":
                            self.append_issue(
                                analysis,
                                "SELinux在配置文件中被禁用",
                                severity="high",
                                recommendation="将SELINUX设置为enforcing或permissive",
                            )
                    elif key == "SELINUXTYPE":
                        analysis["configuration_analysis"]["policy_type"] = value
        else:
            analysis["configuration_analysis"]["config_exists"] = False
            self.append_issue(
                analysis,
                "SELinux配置文件不存在",
                severity="high",
                recommendation="创建SELinux配置文件",
            )

    def _analyze_policy(self, analysis: Dict[str, Any]) -> None:
        modules_content = self.read_collected_file("status_info/selinux_modules.txt")
        analysis["policy_analysis"]["modules_output"] = modules_content
        module_lines = [l for l in modules_content.split("\n") if l.strip()]
        analysis["policy_analysis"]["module_count"] = len(module_lines)
        key_modules = ["corenetwork", "ssh", "httpd", "ftp", "telnet"]
        found = [m for m in key_modules if m in modules_content]
        analysis["policy_analysis"]["key_modules_found"] = found
        if len(found) < 3:
            self.append_issue(
                analysis,
                "关键SELinux策略模块缺失",
                severity="medium",
                recommendation="安装完整的SELinux策略模块",
            )
        boolean_content = self.read_collected_file("status_info/boolean_settings.txt")
        analysis["policy_analysis"]["boolean_settings"] = boolean_content
        critical_booleans = {
            "allow_ptrace": False,
            "allow_user_exec_content": False,
            "allow_unconfined_execmem": False,
        }
        for line in boolean_content.split("\n"):
            for name in critical_booleans:
                if name in line and "on" in line:
                    critical_booleans[name] = True
                    self.append_issue(
                        analysis,
                        f"关键布尔值{name}已启用",
                        severity="medium",
                        recommendation=f"评估是否需要启用{name}",
                    )
        analysis["policy_analysis"]["critical_booleans"] = critical_booleans
