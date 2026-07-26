# -*- coding: utf-8 -*-
"""
LUKS 采集结果的安全分析封装。

对已采集的 LUKS 配置与设备信息进行分析，产出 security_issues、configuration_analysis、
device_analysis 等，并写入 luks_security_analysis.json。
"""

from pathlib import Path
from typing import Any, Dict, List

from .base import SecurityAnalyzerBase


class LuksSecurityAnalyzer(SecurityAnalyzerBase):
    """LUKS 安全策略分析器：基于已采集文件进行分析并写 JSON。"""

    default_analysis_filename = "luks_security_analysis.json"

    def analysis_template(self) -> Dict[str, Any]:
        return {
            "luks_status": {},
            "security_issues": [],
            "recommendations": [],
            "configuration_analysis": {},
            "device_analysis": {},
        }

    def get_analyzer_steps(self) -> List[Any]:
        return [
            self._analyze_status,
            self._analyze_configuration,
            self._analyze_devices,
        ]

    def _analyze_status(self, analysis: Dict[str, Any]) -> None:
        content = self.read_collected_file("status_info/luks_version.txt")
        if not content:
            content = self.read_collected_file("status_info/version.txt")
        if "cryptsetup" in content.lower():
            analysis["luks_status"]["cryptsetup_installed"] = True
            analysis["luks_status"]["version"] = content.strip()
        else:
            analysis["luks_status"]["cryptsetup_installed"] = False
            self.append_issue(
                analysis,
                "cryptsetup未安装或不可用",
                severity="high",
                recommendation="安装cryptsetup工具",
            )

    def _analyze_configuration(self, analysis: Dict[str, Any]) -> None:
        config_content = self.read_collected_file("config_files/crypttab")
        if not config_content:
            config_content = self.read_collected_file("status_info/crypttab.txt")
        if not config_content:
            analysis["configuration_analysis"]["crypttab_exists"] = False
            self.append_issue(
                analysis,
                "crypttab配置文件不存在",
                severity="low",
                recommendation="如果系统使用LUKS加密，应创建crypttab文件",
            )
            return
        analysis["configuration_analysis"]["crypttab_exists"] = True
        analysis["configuration_analysis"]["crypttab_content"] = config_content
        lines = [l.strip() for l in config_content.split("\n") if l.strip() and not l.strip().startswith("#")]
        analysis["configuration_analysis"]["encrypted_devices_count"] = len(lines)
        for line in lines:
            parts = line.split()
            if len(parts) >= 3:
                device_name = parts[0]
                key_file = parts[2].lower() if len(parts) > 2 else "none"
                options = parts[3].lower() if len(parts) > 3 else "none"
                if "none" in key_file or key_file == "none":
                    self.append_issue(
                        analysis,
                        f"加密设备 {device_name} 未指定密钥文件，可能使用密码",
                        severity="medium",
                        recommendation="考虑使用密钥文件替代密码以提高安全性",
                    )
                if "nofail" in options:
                    self.append_issue(
                        analysis,
                        f"加密设备 {device_name} 配置了nofail选项，启动失败可能被忽略",
                        severity="low",
                        recommendation="审查nofail选项是否必要",
                    )

    def _analyze_devices(self, analysis: Dict[str, Any]) -> None:
        content = self.read_collected_file("status_info/lsblk_crypto.txt")
        if content:
            crypto_devices = [l for l in content.split("\n") if "crypto_luks" in l.lower() or "crypt" in l.lower()]
            analysis["device_analysis"]["encrypted_devices_count"] = len(crypto_devices)
            analysis["device_analysis"]["encrypted_devices"] = crypto_devices[:20]
            if len(crypto_devices) == 0:
                self.append_issue(
                    analysis,
                    "未检测到加密设备",
                    severity="high",
                    recommendation="考虑配置磁盘加密以保护数据安全",
                )
            elif len(crypto_devices) > 5:
                self.append_issue(
                    analysis,
                    f"检测到{len(crypto_devices)}个加密设备，可能过于复杂",
                    severity="low",
                    recommendation="审查加密设备配置的合理性",
                )
        content = self.read_collected_file("status_info/dmsetup_status.txt")
        if content:
            analysis["device_analysis"]["dmsetup_output"] = content.splitlines()[:10]
            if "inactive" in content.lower():
                self.append_issue(
                    analysis,
                    "检测到非活跃的加密设备",
                    severity="medium",
                    recommendation="审查非活跃加密设备的必要性",
                )
