# -*- coding: utf-8 -*-
"""进度条：可选 tqdm，统一 create/update/close 与迭代包装。"""

from __future__ import annotations

import logging
from typing import Any, Iterator, List, Optional

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    tqdm = None
    TQDM_AVAILABLE = False

logger = logging.getLogger(__name__)

if not TQDM_AVAILABLE:
    logger.debug("tqdm 未安装，进度条将不显示。安装: pip install tqdm")


def create_progress_bar(
    total: int,
    desc: str = "进度",
    unit: str = "项",
) -> Any:
    """创建进度条。无 tqdm 时返回 None，调用方需兼容 None。"""
    if TQDM_AVAILABLE and tqdm is not None:
        return tqdm(total=total, desc=desc, unit=unit)
    return None


def update_progress(progress_bar: Any, advance: int = 1) -> None:
    """更新进度条。progress_bar 为 None 时无操作。"""
    if progress_bar is not None:
        try:
            progress_bar.update(advance)
        except Exception:
            pass


def close_progress_bar(progress_bar: Any) -> None:
    """关闭进度条。"""
    if progress_bar is not None:
        try:
            progress_bar.close()
        except Exception:
            pass


def progress_iterator(
    iterable: List[Any],
    desc: str = "进度",
    unit: str = "项",
):
    """对可迭代对象包装进度条；无 tqdm 时直接返回原可迭代对象。"""
    if TQDM_AVAILABLE and tqdm is not None:
        return tqdm(iterable, desc=desc, unit=unit)
    return iterable
