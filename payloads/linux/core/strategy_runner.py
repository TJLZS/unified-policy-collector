# -*- coding: utf-8 -*-
"""采集器基类：按模块循环执行，带进度条与断点恢复，可选报告生成。"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, List, Optional

from .checkpoint import CheckpointManager
from .progress import create_progress_bar, update_progress, close_progress_bar
from .logging_utils import setup_collection_logging
from .collector_base import CollectorModuleBase

logger = logging.getLogger(__name__)


class StrategyCollectorBase:
    """
    策略采集器基类：维护 base_dir、checkpoint、模块列表，
    执行「遍历模块 → 断点判断 → 保存检查点 → collect → 再保存 → 进度条」，
    并可选调用子类的报告生成方法。
    """

    # 子类覆盖：策略名称（用于日志与报告）
    strategy_name: str = "策略"
    # 子类覆盖：日志文件名
    log_filename: str = "collection.log"
    # 子类覆盖：检查点文件名
    checkpoint_filename: str = "collection_checkpoint.json"

    def __init__(
        self,
        base_dir: Path,
        modules: Optional[List[CollectorModuleBase]] = None,
        log_filename: Optional[str] = None,
        checkpoint_filename: Optional[str] = None,
    ):
        self.base_dir = Path(base_dir)
        self.modules = list(modules or [])
        self.log_file = self.base_dir / (log_filename or self.log_filename)
        self.checkpoint_file = self.base_dir / (checkpoint_filename or self.checkpoint_filename)
        self.checkpoint_manager = CheckpointManager(self.checkpoint_file)
        self._setup_logging()
        self.logger = logging.getLogger(self.__class__.__name__)

    def _setup_logging(self) -> None:
        """初始化日志：文件 + 控制台。"""
        self.base_dir.mkdir(parents=True, exist_ok=True)
        setup_collection_logging(
            self.base_dir,
            log_filename=self.log_file.name,
        )

    def run(self) -> bool:
        """
        执行采集：遍历各模块，断点跳过已完成，执行 collect，保存检查点，更新进度条，
        最后调用 on_after_collect 生成报告。返回是否全部成功。
        """
        self.logger.info("开始 %s 采集...", self.strategy_name)
        self.logger.info("输出目录: %s", self.base_dir)
        self.logger.info("系统类型: %s", self.checkpoint_manager.checkpoint_data.get("system_type", "unknown"))

        if hasattr(os, "geteuid") and os.geteuid() != 0:
            self.logger.warning("未使用 root 权限运行，部分文件可能无法访问")

        progress_bar = create_progress_bar(
            total=len(self.modules),
            desc=f"采集{self.strategy_name}",
            unit="模块",
        )
        success_count = 0
        failed_modules: List[str] = []

        try:
            for module in self.modules:
                if self.checkpoint_manager.is_module_completed(module.name):
                    self.logger.info("跳过已完成模块: %s", module.name)
                    update_progress(progress_bar)
                    success_count += 1
                    continue

                self.logger.info("开始采集模块: %s", module.name)
                self.checkpoint_manager.save_checkpoint(module.name)

                try:
                    if module.collect():
                        self.checkpoint_manager.save_checkpoint(module.name, completed=True)
                        success_count += 1
                        self.logger.info("模块采集成功: %s", module.name)
                    else:
                        failed_modules.append(module.name)
                        self.logger.error("模块采集失败: %s", module.name)
                except Exception as e:
                    failed_modules.append(module.name)
                    self.logger.exception("模块采集异常 %s: %s", module.name, e)
                    self._log_exception_details(e, module.name)

                update_progress(progress_bar)

            close_progress_bar(progress_bar)
            self.on_after_collect(success_count, failed_modules)

            if failed_modules:
                self.logger.warning("采集完成，但有 %d 个模块失败: %s", len(failed_modules), failed_modules)
                return False
            self.logger.info("所有 %s 采集完成", self.strategy_name)
            return True

        except KeyboardInterrupt:
            self.logger.info("采集被用户中断")
            close_progress_bar(progress_bar)
            return False
        except Exception as e:
            self.logger.exception("采集过程发生未预期错误: %s", e)
            close_progress_bar(progress_bar)
            return False

    def on_after_collect(self, success_count: int, failed_modules: List[str]) -> None:
        """采集结束后调用，子类可覆盖以生成详细报告、摘要等。"""
        pass

    def _log_exception_details(self, exception: Exception, module_name: str) -> None:
        """记录异常详情，子类可覆盖以写入 error_details.json 等。"""
        self.logger.debug("异常详情: %s - %s", type(exception).__name__, exception)
