# -*- coding: utf-8 -*-
"""
AppArmor 采集结果的安全分析封装。

对已采集的 AppArmor 配置与策略信息进行分析，产出 security_issues、
policy_analysis、configuration_analysis 等，并写入 apparmor_security_analysis.json。
"""

import re
from pathlib import Path
from typing import Any, Dict, List

from .base import SecurityAnalyzerBase


class ApparmorSecurityAnalyzer(SecurityAnalyzerBase):
    """AppArmor 安全策略分析器：基于已采集文件进行分析并写 JSON。"""

    default_analysis_filename = "apparmor_security_analysis.json"

    def analysis_template(self) -> Dict[str, Any]:
        return {
            "apparmor_status": {},
            "security_issues": [],
            "recommendations": [],
            "policy_analysis": {},
            "configuration_analysis": {},
        }

    def get_analyzer_steps(self) -> List[Any]:
        return [
            self._analyze_status,
            self._analyze_configuration,
            self._analyze_policy_files,
        ]

    def _analyze_status(self, analysis: Dict[str, Any]) -> None:
        content = self.read_collected_file("status_info/status.txt")
        if not content:
            content = self.read_collected_file("status_info/aa_status.txt")
        if content:
            analysis["apparmor_status"]["status_output"] = content.splitlines()[:10]
            if "0 profiles are loaded" in content:
                self.append_issue(
                    analysis,
                    "AppArmor已启用但未加载任何策略",
                    severity="high",
                    recommendation="加载AppArmor策略以提供安全保护",
                )
            elif "profiles are loaded" in content:
                m = re.search(r"(\d+) profiles are loaded", content)
                if m:
                    count = int(m.group(1))
                    analysis["apparmor_status"]["loaded_profiles"] = count
                    if count < 5:
                        self.append_issue(
                            analysis,
                            f"AppArmor只加载了{count}个策略，可能保护不足",
                            severity="medium",
                            recommendation="考虑加载更多AppArmor策略以增强系统安全",
                        )
            analysis["apparmor_status"]["enabled"] = True
        else:
            analysis["apparmor_status"]["enabled"] = False
            self.append_issue(
                analysis,
                "AppArmor未启用",
                severity="critical",
                recommendation="启用AppArmor以提供强制访问控制",
            )

    def _analyze_configuration(self, analysis: Dict[str, Any]) -> None:
        content = self.read_collected_file("config_files/parser.conf")
        if content:
            analysis["configuration_analysis"]["parser_config_exists"] = True
            analysis["configuration_analysis"]["parser_config_content"] = content
            analysis["configuration_analysis"]["enforce_mode"] = "enforce" in content.lower()
            if not analysis["configuration_analysis"]["enforce_mode"]:
                self.append_issue(
                    analysis,
                    "AppArmor解析器配置中未明确设置enforce模式",
                    severity="medium",
                    recommendation="确保AppArmor配置为enforce模式",
                )
        else:
            analysis["configuration_analysis"]["parser_config_exists"] = False
            self.append_issue(
                analysis,
                "AppArmor解析器配置文件不存在",
                severity="medium",
                recommendation="创建AppArmor解析器配置文件",
            )

    def _analyze_policy_files(self, analysis: Dict[str, Any]) -> None:
        # 策略文件已统一放入 config_files（如 etc_apparmor.d、apparmor_extra-profiles）
        config_dir = self.output_dir / "config_files"
        if not config_dir.exists():
            analysis["policy_analysis"]["policy_files_available"] = False
            self.append_issue(
                analysis,
                "未找到AppArmor策略文件",
                severity="high",
                recommendation="安装或创建AppArmor策略文件",
            )
            return
        policy_files = list(config_dir.rglob("*"))
        policy_files = [f for f in policy_files if f.is_file() and f.suffix in (".conf", "") and "abstractions" not in str(f)]
        # 排除主配置文件（非策略 profile）
        skip_names = {"parser.conf", "logprof.conf", "notify.conf"}
        policy_files = [f for f in policy_files if f.name not in skip_names]
        analysis["policy_analysis"]["policy_files_available"] = len(policy_files) > 0
        analysis["policy_analysis"]["total_policy_files"] = len(policy_files)
        analysis["policy_analysis"]["policy_files"] = [str(f.relative_to(config_dir)) for f in policy_files[:50]]
        if len(policy_files) == 0:
            self.append_issue(
                analysis,
                "未找到AppArmor策略文件",
                severity="high",
                recommendation="安装或创建AppArmor策略文件",
            )
        elif len(policy_files) < 10:
            self.append_issue(
                analysis,
                f"只找到{len(policy_files)}个AppArmor策略文件，可能保护不足",
                severity="medium",
                recommendation="考虑安装更多AppArmor策略文件",
            )
        security_patterns = {"capability_net_admin": 0, "capability_sys_admin": 0}
        for pf in policy_files[:5]:
            try:
                c = pf.read_text(encoding="utf-8", errors="ignore")
                if re.search(r"capability\s+net_admin", c, re.I):
                    security_patterns["capability_net_admin"] += 1
                if re.search(r"capability\s+sys_admin", c, re.I):
                    security_patterns["capability_sys_admin"] += 1
            except Exception:
                pass
        analysis["policy_analysis"]["security_patterns"] = security_patterns
        if security_patterns["capability_net_admin"] > 0:
            self.append_issue(
                analysis,
                "策略文件中包含net_admin能力，存在网络管理风险",
                severity="medium",
                recommendation="审查net_admin能力的使用是否必要",
            )
        if security_patterns["capability_sys_admin"] > 0:
            self.append_issue(
                analysis,
                "策略文件中包含sys_admin能力，存在系统管理风险",
                severity="high",
                recommendation="审查sys_admin能力的使用是否必要",
            )
