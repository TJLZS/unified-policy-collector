# -*- coding: utf-8 -*-
"""采集脚本统一日志配置：文件 + 控制台，按输出目录与日志文件名设置。"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional


def setup_collection_logging(
    base_dir: Path,
    log_filename: str = "collection.log",
    level: int = logging.INFO,
    format_string: Optional[str] = None,
) -> logging.Logger:
    """
    配置采集用日志：同时写入 base_dir/log_filename 与控制台。
    返回 root logger 或可指定名称的 logger。
    """
    base_dir = Path(base_dir)
    base_dir.mkdir(parents=True, exist_ok=True)
    log_file = base_dir / log_filename

    if format_string is None:
        format_string = "%(asctime)s - %(levelname)s - [%(name)s] - %(message)s"

    formatter = logging.Formatter(format_string)

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(formatter)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)

    root = logging.getLogger()
    root.setLevel(level)
    # 避免重复添加
    if not root.handlers:
        root.addHandler(file_handler)
        root.addHandler(stream_handler)
    else:
        # 若已有 handler，可为当前项目单独加一个 file handler
        for h in list(root.handlers):
            if getattr(h, "baseFilename", None) == str(log_file):
                break
        else:
            root.addHandler(file_handler)
            root.addHandler(stream_handler)

    return root
