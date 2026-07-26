# -*- coding: utf-8 -*-
"""
K8S 采集结果的安全分析封装。

对已采集的 Kubernetes 资源（NetworkPolicy、RBAC 等）进行分析，
产出 findings，并写入 k8s_security_analysis.json。
"""

from pathlib import Path
from typing import Any, Dict, List

from datetime import datetime

from .base import SecurityAnalyzerBase


class K8sSecurityAnalyzer(SecurityAnalyzerBase):
    """K8S 安全策略分析器：基于已采集文件进行分析并写 JSON。"""

    default_analysis_filename = "k8s_security_analysis.json"

    def analysis_template(self) -> Dict[str, Any]:
        return {
            "analysis_time": "",
            "cluster_type": "kind",
            "findings": [],
        }

    def get_analyzer_steps(self) -> List[Any]:
        return [self._set_timestamp, self._analyze_network_policies, self._analyze_rbac]

    def _set_timestamp(self, analysis: Dict[str, Any]) -> None:
        analysis["analysis_time"] = datetime.now().isoformat()

    def _analyze_network_policies(self, analysis: Dict[str, Any]) -> None:
        content = self.read_collected_file("k8s_resources/network_policies.yaml")
        if not content:
            content = self.read_collected_file("status_info/network_policies.txt")
        if content:
            np_count = content.count("kind: NetworkPolicy")
            if np_count == 0:
                analysis["findings"].append({
                    "category": "network",
                    "level": "warning",
                    "message": "未发现任何 NetworkPolicy，Pod 间网络默认为全通",
                })
            else:
                analysis["findings"].append({
                    "category": "network",
                    "level": "info",
                    "message": f"发现 {np_count} 个 NetworkPolicy",
                })

    def _analyze_rbac(self, analysis: Dict[str, Any]) -> None:
        content = self.read_collected_file("k8s_resources/cluster_roles.yaml")
        if not content:
            content = self.read_collected_file("status_info/cluster_roles.txt")
        if content and "cluster-admin" in content:
            analysis["findings"].append({
                "category": "rbac",
                "level": "info",
                "message": "检测到 cluster-admin 集群角色",
            })
