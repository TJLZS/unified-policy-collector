# -*- coding: utf-8 -*-
"""断点恢复：加载/保存检查点、已完成模块、文件校验和、系统类型。"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from .system_info import detect_system_type

logger = logging.getLogger(__name__)

DEFAULT_CHECKPOINT = {
    "version": "1.0",
    "created_time": None,
    "last_updated": None,
    "completed_modules": [],
    "current_module": None,
    "file_checksums": {},
    "file_statistics": {},
    "system_type": "unknown",
}


class CheckpointManager:
    """断点恢复管理器：持久化 completed_modules、file_checksums、system_type 等。"""

    def __init__(self, checkpoint_file: Path):
        self.checkpoint_file = Path(checkpoint_file)
        self.checkpoint_data = self._load_checkpoint()

    def _load_checkpoint(self) -> Dict[str, Any]:
        if self.checkpoint_file.exists():
            try:
                with open(self.checkpoint_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                # 补全缺失键
                for k, v in DEFAULT_CHECKPOINT.items():
                    if k not in data:
                        data[k] = v if v is not None else (datetime.now().isoformat() if k in ("created_time", "last_updated") else v)
                if "system_type" not in data or data["system_type"] == "unknown":
                    data["system_type"] = detect_system_type()
                return data
            except Exception as e:
                logger.warning("加载检查点文件失败: %s", e)
        now = datetime.now().isoformat()
        return {
            **DEFAULT_CHECKPOINT,
            "created_time": now,
            "last_updated": now,
            "system_type": detect_system_type(),
        }

    def save_checkpoint(self, module_name: str, completed: bool = False) -> None:
        try:
            self.checkpoint_data["last_updated"] = datetime.now().isoformat()
            self.checkpoint_data["current_module"] = module_name
            if completed and module_name not in self.checkpoint_data["completed_modules"]:
                self.checkpoint_data["completed_modules"].append(module_name)
            self.checkpoint_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.checkpoint_file, "w", encoding="utf-8") as f:
                json.dump(self.checkpoint_data, f, indent=2, ensure_ascii=False)
            logger.info("检查点已保存: %s", module_name)
        except Exception as e:
            logger.error("保存检查点失败: %s", e)

    def is_module_completed(self, module_name: str) -> bool:
        return module_name in self.checkpoint_data.get("completed_modules", [])

    def get_file_checksum(self, file_path: Path) -> Optional[str]:
        return self.checkpoint_data.get("file_checksums", {}).get(str(file_path))

    def update_file_checksum(self, file_path: Path, checksum: str) -> None:
        if "file_checksums" not in self.checkpoint_data:
            self.checkpoint_data["file_checksums"] = {}
        self.checkpoint_data["file_checksums"][str(file_path)] = checksum

    def update_file_statistics(self, module_name: str, stats: Dict[str, Any]) -> None:
        if "file_statistics" not in self.checkpoint_data:
            self.checkpoint_data["file_statistics"] = {}
        self.checkpoint_data["file_statistics"][module_name] = stats
