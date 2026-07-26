# -*- coding: utf-8 -*-
"""
策略文件路径与采集命令的封装。

将各策略收集脚本中散落的「路径列表」和「命令字典」统一为可配置、可复用的数据结构，
便于集中维护、按策略扩展，并支持分组（如：配置文件路径、日志路径、状态命令等）。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

# 路径项：可以是单个路径字符串，或 (路径, 说明)
PathItem = Union[str, Tuple[str, str]]


@dataclass
class StrategyPathsConfig:
    """
    策略相关文件/目录路径配置。

    按用途分组，便于脚本中「收集配置文件」「收集日志」等步骤分别使用。
    路径为字符串，脚本中会用 Path(path) 判断存在性并复制。
    """

    # 配置文件/目录路径（主配置、策略目录等，采集时统一放入 config_files）
    config_paths: List[str] = field(default_factory=list)
    # 日志文件/目录路径（可只采集片段）
    log_paths: List[str] = field(default_factory=list)
    # 其他路径（如证书、运行时配置等），可带简短说明
    extra_paths: List[Union[str, Tuple[str, str]]] = field(default_factory=list)

    def all_config_paths(self) -> List[str]:
        """返回所有用于「配置」收集的路径，便于一次遍历."""
        return list(self.config_paths)

    def iter_all_paths(self):
        """迭代所有路径（仅路径字符串，不含 extra 的说明）."""
        for p in self.config_paths:
            yield p
        for p in self.log_paths:
            yield p
        for item in self.extra_paths:
            yield item[0] if isinstance(item, tuple) else item

    def to_dict(self) -> dict:
        """便于序列化或调试."""
        return {
            "config_paths": self.config_paths,
            "log_paths": self.log_paths,
            "extra_paths": [
                {"path": p[0], "desc": p[1]} if isinstance(p, tuple) else p
                for p in self.extra_paths
            ],
        }


@dataclass
class CommandGroup:
    """
    一组命名命令，用于「状态信息」「日志命令」等分组。

    name: 组名，如 "status_info", "logs"
    commands: 命令名 -> 命令字符串
    """

    name: str
    commands: Dict[str, str] = field(default_factory=dict)

    def items(self):
        return self.commands.items()


class StrategyCommandsConfig:
    """
    策略采集相关命令的封装。

    将脚本中的 xxx_commands 字典及多组 status_commands / log_commands 等
    统一为「多组命令」，每组有名称和 name -> command 映射。
    脚本可按组执行并保存到对应子目录（如 status_info/xxx.txt, logs/xxx.txt）。
    """

    def __init__(
        self,
        all_commands: Optional[Dict[str, str]] = None,
        groups: Optional[Dict[str, Dict[str, str]]] = None,
    ):
        """
        :param all_commands: 单一命令字典（名 -> 命令），可作为默认全集
        :param groups: 分组名 -> { 命令名 -> 命令 }，用于按组执行并落盘到不同子目录
        """
        self._all: Dict[str, str] = dict(all_commands or {})
        self._groups: Dict[str, Dict[str, str]] = dict(groups or {})

    def add_command(self, name: str, command: str) -> None:
        self._all[name] = command

    def add_commands(self, commands: Dict[str, str]) -> None:
        self._all.update(commands)

    def add_group(self, group_name: str, commands: Dict[str, str]) -> None:
        self._groups[group_name] = dict(commands)
        self._all.update(commands)

    def get_command(self, name: str) -> Optional[str]:
        return self._all.get(name)

    def get_all_commands(self) -> Dict[str, str]:
        return dict(self._all)

    def get_group(self, group_name: str) -> Dict[str, str]:
        return dict(self._groups.get(group_name, {}))

    def group_names(self) -> List[str]:
        return list(self._groups.keys())

    def iter_groups(self):
        """迭代 (组名, { 命令名: 命令 })"""
        for name, cmds in self._groups.items():
            yield name, cmds

    def to_dict(self) -> dict:
        return {
            "all_commands": self._all,
            "groups": self._groups,
        }


def build_paths_config(
    config_paths: Optional[List[str]] = None,
    log_paths: Optional[List[str]] = None,
    extra_paths: Optional[List[Union[str, Tuple[str, str]]]] = None,
) -> StrategyPathsConfig:
    """工厂方法：从各列表构建 StrategyPathsConfig。策略文件路径也放入 config_paths，采集时统一到 config_files。"""
    return StrategyPathsConfig(
        config_paths=config_paths or [],
        log_paths=log_paths or [],
        extra_paths=extra_paths or [],
    )


def build_commands_config(
    commands: Dict[str, str],
    status_group: Optional[Dict[str, str]] = None,
    log_group: Optional[Dict[str, str]] = None,
    extra_groups: Optional[Dict[str, Dict[str, str]]] = None,
) -> StrategyCommandsConfig:
    """
    工厂方法：从「全集命令」和可选分组构建 StrategyCommandsConfig。

    - commands: 全集（名 -> 命令）
    - status_group: 若提供，则建一组 "status_info" -> 使用 status_group 或从 commands 取
    - log_group: 若提供，则建一组 "logs" -> 同上
    - extra_groups: 其它组，组名 -> { 命令名 -> 命令 }
    """
    cfg = StrategyCommandsConfig(all_commands=dict(commands))
    if status_group is not None:
        cfg.add_group("status_info", status_group)
    if log_group is not None:
        cfg.add_group("logs", log_group)
    for gname, gcmds in (extra_groups or {}).items():
        cfg.add_group(gname, gcmds)
    return cfg
