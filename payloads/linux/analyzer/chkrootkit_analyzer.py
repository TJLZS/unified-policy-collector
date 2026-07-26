# -*- coding: utf-8 -*-
"""
chkrootkit 采集结果的安全分析封装。

对已采集的 chkrootkit 配置与状态信息进行分析，产出 security_issues、
configuration_analysis 等，并写入 chkrootkit_security_analysis.json。
"""

from pathlib import Path
from typing import Any, Dict, List

from .base import SecurityAnalyzerBase


class ChkrootkitSecurityAnalyzer(SecurityAnalyzerBase):
    """chkrootkit 安全策略分析器：基于已采集文件进行分析并写 JSON。"""

    default_analysis_filename = "chkrootkit_security_analysis.json"

    def analysis_template(self) -> Dict[str, Any]:
        return {
            "chkrootkit_status": {},
            "security_issues": [],
            "recommendations": [],
            "detection_analysis": {},
            "configuration_analysis": {},
        }

    def get_analyzer_steps(self) -> List[Any]:
        return [self._analyze_status, self._analyze_configuration]

    def _analyze_status(self, analysis: Dict[str, Any]) -> None:
        content = self.read_collected_file("status_info/location.txt")
        if content and content.strip():
            analysis["chkrootkit_status"]["installed"] = True
            analysis["chkrootkit_status"]["path"] = content.strip().split("\n")[0].strip()
        else:
            content = self.read_collected_file("status_info/chkrootkit_version.txt")
            if content and "chkrootkit" in content.lower():
                analysis["chkrootkit_status"]["installed"] = True
                analysis["chkrootkit_status"]["version"] = content.strip()
            else:
                analysis["chkrootkit_status"]["installed"] = False
                self.append_issue(
                    analysis,
                    "chkrootkit未安装",
                    severity="high",
                    recommendation="安装chkrootkit以检测rootkit",
                )

    def _analyze_configuration(self, analysis: Dict[str, Any]) -> None:
        config_content = self.read_collected_file("config_files/chkrootkit.conf")
        if not config_content:
            config_content = self.read_collected_file("status_info/config_file.txt")
        if not config_content:
            analysis["configuration_analysis"]["config_exists"] = False
            self.append_issue(
                analysis,
                "chkrootkit配置文件不存在",
                severity="medium",
                recommendation="创建chkrootkit配置文件",
            )
            return
        analysis["configuration_analysis"]["config_exists"] = True
        analysis["configuration_analysis"]["config_content"] = config_content
        c = config_content.lower()
        for line in config_content.split("\n"):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                key, value = key.strip().lower(), value.strip().lower()
                if key == "quiet":
                    analysis["configuration_analysis"]["quiet_mode"] = value == "true"
                elif key == "verbose":
                    analysis["configuration_analysis"]["verbose_mode"] = value == "true"
                elif key == "update":
                    analysis["configuration_analysis"]["auto_update"] = value == "true"
