# -*- coding: utf-8 -*-
"""
Docker 采集结果的安全分析封装。

对已采集的 Docker 配置与状态信息进行分析，产出 security_issues、
security_config 等，并写入 docker_security_analysis.json。
"""

import json
import re
from pathlib import Path
from typing import Any, Dict, List

from .base import SecurityAnalyzerBase


class DockerSecurityAnalyzer(SecurityAnalyzerBase):
    """Docker 安全策略分析器：基于已采集文件进行分析并写 JSON。"""

    default_analysis_filename = "docker_security_analysis.json"

    def analysis_template(self) -> Dict[str, Any]:
        return {
            "docker_status": {},
            "security_issues": [],
            "recommendations": [],
            "security_config": {},
        }

    def get_analyzer_steps(self) -> List[Any]:
        return [
            self._analyze_status,
            self._analyze_config,
            self._analyze_security_settings,
        ]

    def _analyze_status(self, analysis: Dict[str, Any]) -> None:
        content = self.read_collected_file("status_info/docker_version.txt")
        if not content:
            content = self.read_collected_file("status_info/docker_version_detailed.txt")
        if content and "docker" in content.lower():
            analysis["docker_status"]["installed"] = True
            analysis["docker_status"]["version"] = content.strip().split("\n")[0]
        else:
            analysis["docker_status"]["installed"] = False
            self.append_issue(
                analysis,
                "Docker未安装或无法访问",
                severity="low",
                recommendation="如果不需要Docker，此警告可以忽略",
            )
        content = self.read_collected_file("status_info/service_status.txt")
        analysis["docker_status"]["running"] = "active (running)" in content.lower()

    def _analyze_config(self, analysis: Dict[str, Any]) -> None:
        config_content = self.read_collected_file("config_files/daemon.json")
        if not config_content:
            return
        try:
            config = json.loads(config_content)
            analysis["security_config"]["daemon.json"] = config
            checks = {
                "tls": config.get("tls", False),
                "tlsverify": config.get("tlsverify", False),
                "userns-remap": config.get("userns-remap", ""),
                "icc": config.get("icc", True),
                "no-new-privileges": config.get("no-new-privileges", False),
            }
            analysis["security_config"]["security_settings"] = checks
            if not checks.get("tls") and not checks.get("tlsverify"):
                self.append_issue(
                    analysis,
                    "Docker守护进程未启用TLS加密",
                    severity="high",
                    recommendation="启用TLS加密以保护Docker API通信",
                )
            if not checks.get("userns-remap"):
                self.append_issue(
                    analysis,
                    "Docker未启用用户命名空间隔离",
                    severity="medium",
                    recommendation="考虑启用用户命名空间以提高安全性",
                )
            if checks.get("icc"):
                self.append_issue(
                    analysis,
                    "Docker容器间通信（ICC）已启用",
                    severity="medium",
                    recommendation="如果不需要容器间直接通信，建议禁用ICC",
                )
            if not checks.get("no-new-privileges"):
                self.append_issue(
                    analysis,
                    "Docker未启用no-new-privileges",
                    severity="medium",
                    recommendation="启用no-new-privileges以防止权限提升",
                )
        except (json.JSONDecodeError, TypeError):
            analysis["security_config"]["daemon.json"] = config_content

    def _analyze_security_settings(self, analysis: Dict[str, Any]) -> None:
        content = self.read_collected_file("status_info/docker_info.txt")
        if content:
            analysis["security_config"]["userns_enabled"] = "userns" in content.lower()
            if not analysis["security_config"].get("userns_enabled"):
                self.append_issue(
                    analysis,
                    "用户命名空间未启用",
                    severity="medium",
                    recommendation="考虑启用用户命名空间以提高容器隔离性",
                )
            m = re.search(r"Storage Driver:\s*(\w+)", content)
            if m:
                analysis["security_config"]["storage_driver"] = m.group(1)
