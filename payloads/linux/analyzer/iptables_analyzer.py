# -*- coding: utf-8 -*-
"""
iptables 采集结果的安全分析封装。

对已采集的 iptables 规则与状态信息进行分析，产出 security_issues、
iptables_status 等，并写入 iptables_security_analysis.json。
"""

from pathlib import Path
from typing import Any, Dict, List

from .base import SecurityAnalyzerBase


class IptablesSecurityAnalyzer(SecurityAnalyzerBase):
    """iptables 安全策略分析器：基于已采集文件进行分析并写 JSON。"""

    default_analysis_filename = "iptables_security_analysis.json"

    def analysis_template(self) -> Dict[str, Any]:
        return {
            "iptables_status": {},
            "security_issues": [],
            "recommendations": [],
        }

    def get_analyzer_steps(self) -> List[Any]:
        return [self._analyze_status, self._analyze_rules]

    def _analyze_status(self, analysis: Dict[str, Any]) -> None:
        content = self.read_collected_file("status_info/iptables_rules_ipv4.txt")
        if not content:
            content = self.read_collected_file("status_info/iptables_rule_count.txt")
        if content and "Chain" in content:
            analysis["iptables_status"]["active"] = True
        else:
            analysis["iptables_status"]["active"] = False
            self.append_issue(
                analysis,
                "iptables防火墙未运行或未安装",
                severity="high",
                recommendation="启用iptables防火墙保护",
            )

    def _analyze_rules(self, analysis: Dict[str, Any]) -> None:
        if not analysis["iptables_status"].get("active"):
            return
        content = self.read_collected_file("status_info/iptables_rules_ipv4.txt")
        if not content:
            return
        lines = content.split("\n")
        rule_count = 0
        default_policies = {}
        for line in lines:
            line = line.strip()
            if line.startswith("Chain") and "policy" in line:
                parts = line.split()
                if len(parts) >= 4:
                    chain_name = parts[1]
                    policy = parts[3]
                    default_policies[chain_name] = policy
                    if chain_name in ("INPUT", "FORWARD") and policy == "ACCEPT":
                        self.append_issue(
                            analysis,
                            f"{chain_name}链默认策略为ACCEPT",
                            severity="high",
                            recommendation=f"建议将{chain_name}链默认策略设置为DROP",
                        )
            elif line and not line.startswith("target") and not line.startswith("Chain"):
                rule_count += 1
        analysis["iptables_status"]["rule_count"] = rule_count
        analysis["iptables_status"]["default_policies"] = default_policies
        if rule_count < 5:
            self.append_issue(
                analysis,
                "iptables规则数量较少",
                severity="medium",
                recommendation="建议配置更详细的防火墙规则",
            )
