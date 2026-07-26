# -*- coding: utf-8 -*-
"""
TCP_Wrappers 采集结果的安全分析封装。

对已采集的 hosts.allow、hosts.deny 等配置进行分析，产出 security_issues、
access_rules 等，并写入 tcp_wrappers_security_analysis.json。
"""

from pathlib import Path
from typing import Any, Dict, List

from .base import SecurityAnalyzerBase


class TcpWrappersSecurityAnalyzer(SecurityAnalyzerBase):
    """TCP_Wrappers 安全策略分析器：基于已采集文件进行分析并写 JSON。"""

    default_analysis_filename = "tcp_wrappers_security_analysis.json"

    def analysis_template(self) -> Dict[str, Any]:
        return {
            "tcp_wrappers_status": {},
            "security_issues": [],
            "recommendations": [],
            "access_rules": {
                "hosts_allow": [],
                "hosts_deny": [],
            },
        }

    def get_analyzer_steps(self) -> List[Any]:
        return [
            self._analyze_hosts_allow,
            self._analyze_hosts_deny,
        ]

    def _analyze_hosts_file(self, rel_path: str, rules_list: List, analysis: Dict[str, Any]) -> None:
        content = self.read_collected_file(rel_path)
        if not content:
            self.append_issue(
                analysis,
                f"文件不存在: {rel_path}",
                severity="medium",
                recommendation=f"创建{rel_path}文件以控制访问",
            )
            return
        for line_num, line in enumerate(content.split("\n"), 1):
            line = line.strip()
            if line and not line.startswith("#"):
                rules_list.append({"line": line_num, "content": line})
                if "ALL:ALL" in line.upper() or "ALL:ALLOW" in line.upper():
                    self.append_issue(
                        analysis,
                        f"规则过于宽松: {line[:50]}...",
                        severity="high",
                        recommendation="限制ALL规则以缩小访问范围",
                    )

    def _analyze_hosts_allow(self, analysis: Dict[str, Any]) -> None:
        self._analyze_hosts_file("config_files/hosts.allow", analysis["access_rules"]["hosts_allow"], analysis)

    def _analyze_hosts_deny(self, analysis: Dict[str, Any]) -> None:
        self._analyze_hosts_file("config_files/hosts.deny", analysis["access_rules"]["hosts_deny"], analysis)
