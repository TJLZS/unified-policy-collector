# -*- coding: utf-8 -*-
"""
策略收集脚本公共核心：断点恢复、进度条、文件校验、日志、系统检测、采集基类。

- CheckpointManager: 断点恢复
- progress_bar / update_progress: 进度条（可选 tqdm）
- file_checksum / has_file_changed: 文件校验
- setup_collection_logging: 日志配置
- detect_system_type: 系统类型检测
- CollectorModuleBase: 采集模块基类（复制、执行命令、清单、校验）
- StrategyCollectorBase: 采集器基类（模块循环 + 进度条 + 断点）
"""

from .checkpoint import CheckpointManager
from .progress import create_progress_bar, update_progress, close_progress_bar, progress_iterator, TQDM_AVAILABLE
from .checksum import file_checksum, FileChecksumHelper
from .logging_utils import setup_collection_logging
from .system_info import detect_system_type
from .collector_base import CollectorModuleBase
from .strategy_runner import StrategyCollectorBase

__all__ = [
    "CheckpointManager",
    "create_progress_bar",
    "update_progress",
    "close_progress_bar",
    "progress_iterator",
    "TQDM_AVAILABLE",
    "file_checksum",
    "FileChecksumHelper",
    "setup_collection_logging",
    "detect_system_type",
    "CollectorModuleBase",
    "StrategyCollectorBase",
]
