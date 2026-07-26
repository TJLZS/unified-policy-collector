# -*- coding: utf-8 -*-
"""采集模块基类：复制文件/目录、执行命令、文件清单、文件校验与统计。"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .checkpoint import CheckpointManager
from .checksum import FileChecksumHelper, file_checksum, content_checksum

logger = logging.getLogger(__name__)


class CollectorModuleBase(ABC):
    """
    采集模块基类：提供 _copy_file、_copy_directory、_run_command、_add_to_manifest、
    _generate_file_statistics、_format_size，以及基于断点的 _has_file_changed。
    子类实现 collect() -> bool。
    """

    def __init__(self, name: str, output_dir: Path, checkpoint_manager: CheckpointManager):
        self.name = name
        self.output_dir = Path(output_dir) / name
        self.checkpoint_manager = checkpoint_manager
        self.checksum_helper = FileChecksumHelper(checkpoint_manager)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.file_manifest: List[Dict[str, Any]] = []

    @abstractmethod
    def collect(self) -> bool:
        """执行采集逻辑。"""
        pass

    def _has_file_changed(self, file_path: Path) -> bool:
        """是否相对断点中记录已变化（并更新断点）。"""
        return self.checksum_helper.has_file_changed(Path(file_path))

    def _copy_file(
        self,
        source_path: Path,
        target_name: Optional[str] = None,
        skip_unchanged: bool = True,
        previous_checksums: Optional[Dict[str, str]] = None,
    ) -> bool:
        """
        复制文件到 output_dir，并加入清单。
        skip_unchanged: 若 True，根据校验和跳过未变化文件。
        previous_checksums: 若提供，优先用其判断（相对路径 as_posix -> 校验和）；否则用断点。
        """
        source_path = Path(source_path)
        if not source_path.exists() or not source_path.is_file():
            logger.warning("源文件不存在: %s", source_path)
            return False
        target_name = target_name or source_path.name
        target_path = self.output_dir / target_name
        target_rel = str(Path(target_name).as_posix())
        try:
            if skip_unchanged:
                skip = False
                if previous_checksums is not None:
                    current_cs = file_checksum(source_path)
                    if current_cs and current_cs == previous_checksums.get(target_rel):
                        skip = target_path.exists()
                else:
                    skip = not self._has_file_changed(source_path) and target_path.exists()
                if skip:
                    self._add_to_manifest(target_path, "cached")
                    return True
            target_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_path, target_path)
            logger.info("复制文件: %s -> %s", source_path, target_path)
            self._add_to_manifest(target_path, "copied")
            return True
        except Exception as e:
            logger.error("复制文件失败 %s: %s", source_path, e)
            return False

    def _copy_directory(
        self,
        source_dir: Path,
        target_name: Optional[str] = None,
    ) -> bool:
        """复制目录到 output_dir，并登记所有文件到清单。"""
        source_dir = Path(source_dir)
        if not source_dir.exists() or not source_dir.is_dir():
            logger.warning("源目录不存在: %s", source_dir)
            return False
        target_name = target_name or source_dir.name
        target_path = self.output_dir / target_name
        try:
            if target_path.exists():
                shutil.rmtree(target_path)
            shutil.copytree(source_dir, target_path, dirs_exist_ok=True)
            logger.info("复制目录: %s -> %s", source_dir, target_path)
            for fp in target_path.rglob("*"):
                if fp.is_file():
                    self._add_to_manifest(fp, "copied")
            return True
        except Exception as e:
            logger.error("复制目录失败 %s: %s", source_dir, e)
            return False

    def _copy_directory_incremental(
        self,
        source_dir: Path,
        target_subdir: str,
        previous_checksums: Optional[Dict[str, str]] = None,
    ) -> bool:
        """
        按文件增量复制目录：仅复制新增或内容变化的文件，保留未变文件。
        target_subdir: 目标子目录相对 output_dir，如 config_files/etc_apparmor_d。
        """
        source_dir = Path(source_dir)
        if not source_dir.exists() or not source_dir.is_dir():
            logger.warning("源目录不存在: %s", source_dir)
            return False
        prev = previous_checksums or {}
        target_base = self.output_dir / target_subdir
        target_base.mkdir(parents=True, exist_ok=True)
        copied = 0
        cached = 0
        for src_file in source_dir.rglob("*"):
            if not src_file.is_file():
                continue
            rel = src_file.relative_to(source_dir)
            target_file = target_base / rel
            target_rel = str((Path(target_subdir) / rel).as_posix())
            current_cs = file_checksum(src_file)
            if not current_cs:
                continue
            if current_cs == prev.get(target_rel) and target_file.exists():
                self._add_to_manifest(target_file, "cached")
                cached += 1
                continue
            try:
                target_file.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src_file, target_file)
                self._add_to_manifest(target_file, "copied")
                copied += 1
            except Exception as e:
                logger.warning("复制文件失败 %s: %s", src_file, e)
        logger.info("增量复制目录: %s -> %s (新增/更新 %d, 未变 %d)", source_dir, target_subdir, copied, cached)
        return True

    def _run_command(
        self,
        command: str,
        output_file: Optional[str] = None,
        timeout: int = 30,
        previous_checksum: Optional[str] = None,
    ) -> bool:
        """
        执行 shell 命令，可选将 stdout/stderr 写入 output_dir/output_file。
        previous_checksum: 若提供且输出内容校验和与之相同，则跳过写入（保留旧文件），并加入 manifest。
        """
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            if output_file:
                output_path = self.output_dir / output_file
                content_lines = [
                    f"命令: {command}\n",
                    f"返回码: {result.returncode}\n",
                    "输出:\n",
                    result.stdout or "",
                ]
                if result.stderr:
                    content_lines.extend(["\n错误输出:\n", result.stderr])
                content_str = "".join(content_lines)
                content_bytes = content_str.encode("utf-8")
                current_checksum = content_checksum(content_bytes)
                if previous_checksum is not None and current_checksum == previous_checksum:
                    if output_path.exists():
                        self._add_to_manifest(output_path, "cached")
                        logger.debug("命令输出未变化，跳过写入: %s", output_file)
                        return result.returncode == 0
                output_path.parent.mkdir(parents=True, exist_ok=True)
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(content_str)
                self._add_to_manifest(output_path, "generated")
                logger.info("命令输出已保存: %s", output_file)
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            logger.warning("命令执行超时: %s", command)
            return False
        except Exception as e:
            logger.error("执行命令时出错 %s: %s", command, e)
            return False

    def _add_to_manifest(self, file_path: Path, action: str) -> None:
        """将文件加入 file_manifest。"""
        try:
            stat = file_path.stat()
            try:
                rel = file_path.relative_to(self.output_dir)
            except ValueError:
                rel = file_path.name
            self.file_manifest.append({
                "name": file_path.name,
                "relative_path": str(rel),
                "size_bytes": stat.st_size,
                "modified_time": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "action": action,
            })
        except Exception as e:
            logger.warning("记录文件到清单失败 %s: %s", file_path, e)

    def _format_size(self, size_bytes: int) -> str:
        """格式化字节数为可读字符串。"""
        size = float(size_bytes)
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} TB"

    def _generate_file_statistics(self) -> Dict[str, Any]:
        """根据 file_manifest 生成统计并写入 file_statistics.json、file_count.txt。"""
        total_size = sum(m["size_bytes"] for m in self.file_manifest)
        file_types: Dict[str, int] = {}
        for m in self.file_manifest:
            ext = Path(m["name"]).suffix.lower()
            file_types[ext] = file_types.get(ext, 0) + 1
        stats = {
            "module_name": self.name,
            "total_files": len(self.file_manifest),
            "total_size_bytes": total_size,
            "file_types": file_types,
            "files": self.file_manifest,
        }
        try:
            stats_path = self.output_dir / "file_statistics.json"
            with open(stats_path, "w", encoding="utf-8") as f:
                json.dump(stats, f, indent=2, ensure_ascii=False)
            count_path = self.output_dir / "file_count.txt"
            with open(count_path, "w", encoding="utf-8") as f:
                f.write(f"模块: {self.name}\n")
                f.write(f"文件总数: {len(self.file_manifest)}\n")
                f.write(f"总大小: {self._format_size(total_size)}\n")
                f.write(f"采集时间: {datetime.now().isoformat()}\n\n")
                f.write("文件类型统计:\n")
                for ext, count in sorted(file_types.items()):
                    f.write(f"  {ext if ext else '无扩展名'}: {count} 个文件\n")
            self._add_to_manifest(stats_path, "generated")
            self._add_to_manifest(count_path, "generated")
        except Exception as e:
            logger.error("生成文件统计失败: %s", e)
        return stats
