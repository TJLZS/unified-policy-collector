# -*- coding: utf-8 -*-
"""
Auditd 采集结果的安全分析封装。

对已采集的 Audit 配置与状态信息进行分析，产出 security_issues、rule_check 等，
并写入 audit_security_analysis.json。
注：Auditd 脚本使用 runtime_info 子目录（非 status_info）。
"""

from pathlib import Path
from typing import Any, Dict, List

from .base import SecurityAnalyzerBase


class AuditdSecurityAnalyzer(SecurityAnalyzerBase):
    """Auditd 安全策略分析器：基于已采集文件进行分析并写 JSON。"""

    default_analysis_filename = "audit_security_analysis.json"

    def analysis_template(self) -> Dict[str, Any]:
        return {
            "timestamp": "",
            "status_check": {},
            "rule_check": {
                "immutable": False,
                "monitor_passwd": False,
                "monitor_execve": False,
                "issues": [],
            },
        }

    def get_analyzer_steps(self) -> List[Any]:
        return [self._analyze_status, self._analyze_rules]

    def _analyze_status(self, analysis: Dict[str, Any]) -> None:
        content = self.read_collected_file("runtime_info/status.txt")
        if not content:
            content = self.read_collected_file("status_info/status.txt")
        if "enabled=1" in content:
            analysis["status_check"]["enabled"] = True
        else:
            analysis["status_check"]["enabled"] = False
            if "issues" not in analysis["rule_check"]:
                analysis["rule_check"]["issues"] = []
            analysis["rule_check"]["issues"].append("Auditd 服务未处于启用状态 (enabled!=1)")

    def _analyze_rules(self, analysis: Dict[str, Any]) -> None:
        content = self.read_collected_file("runtime_info/active_rules.txt")
        if not content:
            content = self.read_collected_file("status_info/active_rules.txt")
        if not content:
            if "issues" not in analysis["rule_check"]:
                analysis["rule_check"]["issues"] = []
            analysis["rule_check"]["issues"].append("未找到生效规则文件")
            return
        if "-e 2" in content or "locked" in content.lower():
            analysis["rule_check"]["immutable"] = True
        if "/etc/passwd" in content:
            analysis["rule_check"]["monitor_passwd"] = True
        else:
            if "issues" not in analysis["rule_check"]:
                analysis["rule_check"]["issues"] = []
            analysis["rule_check"]["issues"].append("未发现针对 /etc/passwd 的监控规则")
        if "execve" in content:
            analysis["rule_check"]["monitor_execve"] = True
        if "No rules" in content:
            if "issues" not in analysis["rule_check"]:
                analysis["rule_check"]["issues"] = []
            analysis["rule_check"]["issues"].append("当前内核未加载任何审计规则")
