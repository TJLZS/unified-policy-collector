# -*- coding: utf-8 -*-
"""文件校验：计算校验和、与断点/采集清单比对以判断是否变化。"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

COLLECTION_CHECKSUMS_FILE = "collection_checksums.json"


def file_checksum(file_path: Path, algorithm: str = "md5") -> Optional[str]:
    """计算文件校验和。algorithm 支持 md5、sha256 等。"""
    path = Path(file_path)
    if not path.exists() or not path.is_file():
        return None
    try:
        h = hashlib.new(algorithm)
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        logger.warning("计算文件校验和失败 %s: %s", path, e)
        return None


def content_checksum(content: bytes, algorithm: str = "md5") -> str:
    """计算字节内容的校验和。"""
    h = hashlib.new(algorithm)
    h.update(content)
    return h.hexdigest()


def load_collection_checksums(output_dir: Path) -> Dict[str, str]:
    """
    从模块输出目录加载上次采集的校验和清单。
    返回 { 相对路径(as_posix): 校验和 }，不存在或读失败时返回 {}。
    """
    path = Path(output_dir) / COLLECTION_CHECKSUMS_FILE
    if not path.exists() or not path.is_file():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("files", {})
    except Exception as e:
        logger.warning("加载采集校验和清单失败 %s: %s", path, e)
        return {}


def save_collection_checksums(output_dir: Path, files_checksums: Dict[str, str]) -> None:
    """
    将本次采集的文件校验和保存到模块输出目录。
    files_checksums: { 相对路径(as_posix): 校验和 }
    """
    path = Path(output_dir) / COLLECTION_CHECKSUMS_FILE
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        data = {"version": "1.0", "files": files_checksums}
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        logger.info("已保存采集校验和清单: %d 个文件", len(files_checksums))
    except Exception as e:
        logger.warning("保存采集校验和清单失败 %s: %s", path, e)


class FileChecksumHelper:
    """结合 CheckpointManager 判断文件是否变化，并更新断点中的校验和。"""

    def __init__(self, checkpoint_manager: Any):
        self._checkpoint = checkpoint_manager
        self._algorithm = "md5"

    def calculate(self, file_path: Path) -> Optional[str]:
        return file_checksum(file_path, self._algorithm)

    def get_saved(self, file_path: Path) -> Optional[str]:
        return self._checkpoint.get_file_checksum(file_path)

    def has_file_changed(self, file_path: Path) -> bool:
        """若当前校验和与断点中不一致，则视为已变化并更新断点，返回 True。"""
        current = self.calculate(file_path)
        saved = self.get_saved(file_path)
        if current is not None and current != saved:
            self._checkpoint.update_file_checksum(file_path, current)
            return True
        return False
