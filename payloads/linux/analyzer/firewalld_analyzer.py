# -*- coding: utf-8 -*-
"""
firewalld 采集结果的安全分析封装。

对已采集的 firewalld 配置与状态信息进行分析，产出 security_issues、
firewalld_status 等，并写入 firewalld_security_analysis.json。
"""

from pathlib import Path
from typing import Any, Dict, List

from .base import SecurityAnalyzerBase


class FirewalldSecurityAnalyzer(SecurityAnalyzerBase):
    """firewalld 安全策略分析器：基于已采集文件进行分析并写 JSON。"""

    default_analysis_filename = "firewalld_security_analysis.json"

    def analysis_template(self) -> Dict[str, Any]:
        return {
            "firewalld_status": {},
            "security_issues": [],
            "recommendations": [],
        }

    def get_analyzer_steps(self) -> List[Any]:
        return [self._analyze_status, self._analyze_config]

    def _analyze_status(self, analysis: Dict[str, Any]) -> None:
        content = self.read_collected_file("status_info/firewalld_state.txt")
        if content and "running" in content.lower():
            analysis["firewalld_status"]["active"] = True
        else:
            analysis["firewalld_status"]["active"] = False
            self.append_issue(
                analysis,
                "firewalld防火墙未运行",
                severity="high",
                recommendation="启用firewalld防火墙保护",
            )

    def _analyze_config(self, analysis: Dict[str, Any]) -> None:
        if not analysis["firewalld_status"].get("active"):
            return
        content = self.read_collected_file("status_info/firewalld_default_zone.txt")
        if content:
            default_zone = content.strip()
            analysis["firewalld_status"]["default_zone"] = default_zone
            if default_zone not in ("public", "dmz"):
                self.append_issue(
                    analysis,
                    f"默认区域设置为{default_zone}",
                    severity="medium",
                    recommendation="建议使用public或dmz作为默认区域",
                )
        content = self.read_collected_file("status_info/firewalld_active_zones.txt")
        if content:
            analysis["firewalld_status"]["active_zones"] = content.strip()
            if not content.strip() or "no zones" in content.lower():
                self.append_issue(
                    analysis,
                    "没有活动的防火墙区域",
                    severity="high",
                    recommendation="配置防火墙区域以保护网络接口",
                )
