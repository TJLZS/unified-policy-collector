# -*- coding: utf-8 -*-
"""
采集结果的安全分析逻辑封装。

将各脚本中「对采集到的策略文件/命令输出做安全分析」的函数统一为「分析器」：
- 基类定义分析流程（构建结果结构 -> 执行多个分析步骤 -> 写 JSON）
- 子类只实现具体分析步骤（如 _analyze_status、_analyze_configuration），
  步骤接收统一的 analysis 字典并对其读写，可读 self.output_dir 下已采集文件。
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class AnalysisResult:
    """一次安全分析的结果与元信息."""

    analysis: Dict[str, Any]
    output_path: Optional[Path] = None
    success: bool = True
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "analysis": self.analysis,
            "output_path": str(self.output_path) if self.output_path else None,
            "success": self.success,
            "error": self.error,
        }


class SecurityAnalyzerBase:
    """
    安全分析器基类。

    用法：
    1. 子类实现 analysis_template() 返回初始 analysis 结构（含 security_issues 等）。
    2. 子类实现 get_analyzer_steps() 返回 [self._analyze_xxx, ...]，每个步骤签名为 (analysis: dict) -> None。
    3. 步骤内通过 self.output_dir 读取已采集的文件（如 status_info/xxx.txt），并修改 analysis。
    4. 调用 run() 执行全部步骤并保存 JSON。
    """

    default_analysis_filename: str = "security_analysis.json"

    def __init__(
        self,
        output_dir: Path,
        analysis_filename: Optional[str] = None,
    ):
        self.output_dir = Path(output_dir)
        self.analysis_filename = analysis_filename or self.default_analysis_filename
        self._log = logger

    def analysis_template(self) -> Dict[str, Any]:
        return {
            "security_issues": [],
            "recommendations": [],
        }

    def get_analyzer_steps(self) -> List[Callable[[Dict[str, Any]], None]]:
        return []

    def run(
        self,
        *,
        save: bool = True,
        add_to_manifest: Optional[Callable[[Path, str], None]] = None,
    ) -> AnalysisResult:
        analysis = self.analysis_template()
        steps = self.get_analyzer_steps()
        output_path = self.output_dir / self.analysis_filename

        try:
            for step in steps:
                step(analysis)
        except Exception as e:
            self._log.exception("安全分析步骤执行失败: %s", e)
            return AnalysisResult(
                analysis=analysis,
                output_path=output_path if save else None,
                success=False,
                error=str(e),
            )

        if save:
            try:
                self.output_dir.mkdir(parents=True, exist_ok=True)
                with open(output_path, "w", encoding="utf-8") as f:
                    json.dump(analysis, f, indent=2, ensure_ascii=False)
                if add_to_manifest:
                    add_to_manifest(output_path, "generated")
            except Exception as e:
                self._log.exception("保存分析结果失败: %s", e)
                return AnalysisResult(
                    analysis=analysis,
                    output_path=output_path,
                    success=False,
                    error=str(e),
                )

        return AnalysisResult(
            analysis=analysis,
            output_path=output_path if save else None,
            success=True,
        )

    def read_collected_file(
        self,
        relative_path: str,
        default: str = "",
    ) -> str:
        path = self.output_dir / relative_path
        if not path.is_file():
            return default
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            self._log.warning("读取采集文件失败 %s: %s", path, e)
            return default

    def append_issue(
        self,
        analysis: Dict[str, Any],
        issue: str,
        severity: str = "medium",
        recommendation: str = "",
    ) -> None:
        if "security_issues" not in analysis:
            analysis["security_issues"] = []
        analysis["security_issues"].append(
            {
                "issue": issue,
                "severity": severity,
                "recommendation": recommendation or ("请检查: " + issue),
            }
        )
