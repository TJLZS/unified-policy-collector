#!/usr/bin/env python3
"""在安全设备或Docker宿主机上执行的只读规则采集载荷。"""

import argparse
import glob
import json
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path


SEARCH_ROOTS = (
    Path("/etc"),
    Path("/opt"),
    Path("/usr/local"),
    Path("/usr/share"),
    Path("/var/lib"),
    Path("/home"),
    Path("/root"),
)
MAX_MATCHES_PER_PATTERN = 100
RULE_FILE_TYPE_PATTERN = re.compile(r"^\.[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")


def safe_name(value):
    result = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._")
    return result or "item"


def run(command, timeout=30):
    return subprocess.run(
        command,
        shell=True,
        text=True,
        capture_output=True,
        timeout=timeout,
    )


def find_paths(pattern):
    path = Path(pattern)
    if path.is_absolute() and not glob.has_magic(pattern):
        return [path] if path.exists() else []
    candidates = []
    patterns = []
    if path.is_absolute():
        patterns.append(pattern)
    else:
        relative = pattern
        if relative.startswith("**/"):
            relative = relative[3:]
        for root in SEARCH_ROOTS:
            patterns.append(str(root / "**" / relative))
    for expanded in patterns:
        for match in glob.iglob(expanded, recursive=True):
            candidate = Path(match)
            if candidate.exists() and candidate not in candidates:
                candidates.append(candidate)
                if len(candidates) >= MAX_MATCHES_PER_PATTERN:
                    return candidates
    return candidates


def normalize_rule_file_type(value):
    if not value:
        return None
    normalized = str(value).strip().lower()
    if not RULE_FILE_TYPE_PATTERN.fullmatch(normalized):
        raise ValueError("无效的规则文件类型: {}".format(value))
    return normalized


def matches_rule_file_type(path, rule_file_type):
    return (
        not rule_file_type
        or path.name.casefold().endswith(rule_file_type.casefold())
    )


def copy_match(source, destination, rule_file_type=None):
    if source.is_symlink():
        raise RuntimeError("跳过符号链接: {}".format(source))
    if source.is_dir():
        if rule_file_type:
            copied_files = 0
            for child in source.rglob("*"):
                if child.is_symlink() or not child.is_file():
                    continue
                if not matches_rule_file_type(child, rule_file_type):
                    continue
                target = destination / child.relative_to(source)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(child, target)
                copied_files += 1
            if copied_files == 0:
                raise RuntimeError(
                    "目录中未找到{}类型的规则文件: {}".format(
                        rule_file_type,
                        source,
                    )
                )
            return

        def ignore_symlinks(directory, names):
            return [
                name
                for name in names
                if (Path(directory) / name).is_symlink()
            ]

        shutil.copytree(
            source,
            destination,
            dirs_exist_ok=True,
            symlinks=False,
            ignore=ignore_symlinks,
        )
    else:
        if not matches_rule_file_type(source, rule_file_type):
            raise RuntimeError(
                "文件类型与{}不匹配: {}".format(rule_file_type, source)
            )
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def sanitize_docker_copy(destination, rule_file_type=None):
    if destination.is_symlink():
        destination.unlink()
        raise RuntimeError("拒绝采集容器中的符号链接")
    if not destination.exists():
        raise RuntimeError("docker cp未生成本地临时副本")
    if destination.is_file():
        if not matches_rule_file_type(destination, rule_file_type):
            destination.unlink()
            raise RuntimeError("容器规则文件类型与{}不匹配".format(rule_file_type))
        return
    if not destination.is_dir():
        destination.unlink()
        raise RuntimeError("拒绝采集容器中的特殊文件")

    matched = 0
    for child in destination.rglob("*"):
        if child.is_symlink():
            child.unlink()
        elif child.is_file():
            if matches_rule_file_type(child, rule_file_type):
                matched += 1
            else:
                child.unlink()
        elif not child.is_dir():
            child.unlink()
    if rule_file_type and matched == 0:
        raise RuntimeError(
            "容器规则目录中未找到{}类型的文件".format(rule_file_type)
        )


def collect_filesystem(config, output):
    copied = []
    errors = []
    data_dir = output / "rules"
    data_dir.mkdir(parents=True, exist_ok=True)
    rule_file_type = config.get("rule_file_type")
    for pattern_index, pattern in enumerate(config["paths"], 1):
        matches = find_paths(pattern)
        if not matches:
            errors.append("未找到路径: {}".format(pattern))
            continue
        for match_index, match in enumerate(matches, 1):
            destination = data_dir / "{}_{}_{}".format(
                pattern_index,
                match_index,
                safe_name(match.name),
            )
            try:
                copy_match(match, destination, rule_file_type)
                copied.append(str(match))
            except Exception as exc:
                errors.append("复制失败 {}: {}".format(match, exc))

    status_dir = output / "status"
    status_dir.mkdir(parents=True, exist_ok=True)
    for index, command in enumerate(config.get("status_commands", []), 1):
        try:
            result = run(command)
            content = (
                "命令: {}\n返回码: {}\n\nSTDOUT:\n{}\n\nSTDERR:\n{}\n".format(
                    command,
                    result.returncode,
                    result.stdout,
                    result.stderr,
                )
            )
        except Exception as exc:
            content = "命令: {}\n执行异常: {}\n".format(command, exc)
        (status_dir / "command_{:02d}.txt".format(index)).write_text(
            content,
            encoding="utf-8",
        )
    return copied, errors


def select_container(config):
    result = run("docker ps --format '{{.ID}}\\t{{.Names}}\\t{{.Image}}'")
    if result.returncode != 0:
        raise RuntimeError("docker ps失败: {}".format(result.stderr.strip()))
    containers = []
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3:
            containers.append(
                {"id": parts[0], "name": parts[1], "image": parts[2]}
            )
    override = config.get("container_name")
    if override:
        if config.get("key") == "custom":
            matches = [
                item for item in containers if item["name"] == override
            ]
        else:
            matches = [
                item
                for item in containers
                if item["name"] == override or item["id"].startswith(override)
            ]
    else:
        patterns = [item.casefold() for item in config["container_patterns"]]
        matches = [
            item
            for item in containers
            if any(
                pattern in (item["name"] + " " + item["image"]).casefold()
                for pattern in patterns
            )
        ]
    if not matches:
        available = ", ".join(item["name"] for item in containers) or "无运行容器"
        if config.get("key") == "custom":
            raise RuntimeError(
                "未找到指定的安全设备容器；当前容器: {}".format(available)
            )
        raise RuntimeError(
            "未找到匹配的WAF容器；当前容器: {}".format(available)
        )
    if len(matches) > 1:
        names = ", ".join(item["name"] for item in matches)
        raise RuntimeError("匹配到多个WAF容器，请显式指定容器名称: {}".format(names))
    return matches[0]


def collect_docker(config, output):
    container = select_container(config)
    copied = []
    errors = []
    data_dir = output / "rules"
    data_dir.mkdir(parents=True, exist_ok=True)
    rule_file_type = config.get("rule_file_type")
    for index, path in enumerate(config["paths"], 1):
        destination = data_dir / "{}_{}".format(index, safe_name(Path(path).name))
        command = "docker cp {}:{} {}".format(
            container["id"],
            shlex.quote(path),
            shlex.quote(str(destination)),
        )
        result = run(command, timeout=300)
        if result.returncode == 0:
            try:
                sanitize_docker_copy(destination, rule_file_type)
                copied.append("{}:{}".format(container["name"], path))
            except Exception as exc:
                errors.append("容器规则过滤失败 {}: {}".format(path, exc))
        else:
            errors.append(
                "容器路径采集失败 {}: {}".format(path, result.stderr.strip())
            )
    (output / "container.json").write_text(
        json.dumps(container, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return copied, errors


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    path_mode = config.get("path_mode", "default")
    rule_file_type = config.get("rule_file_type")
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    try:
        rule_file_type = normalize_rule_file_type(rule_file_type)
        config["rule_file_type"] = rule_file_type
        if config.get("docker"):
            copied, errors = collect_docker(config, output)
        else:
            copied, errors = collect_filesystem(config, output)
        manifest = []
        if copied:
            manifest.append(
                {
                    "name": "{}:rules".format(config["key"]),
                    "success": True,
                    "return_code": 0,
                    "message": "已采集{}个路径".format(len(copied)),
                    "copied_paths": copied,
                    "path_mode": path_mode,
                    "output_dir": "rules",
                    "rule_file_type": rule_file_type,
                }
            )
        for index, error in enumerate(errors, 1):
            manifest.append(
                {
                    "name": "{}:path_error_{}".format(config["key"], index),
                    "success": False,
                    "return_code": 2,
                    "message": error,
                    "copied_paths": [],
                    "path_mode": path_mode,
                    "output_dir": "status",
                    "rule_file_type": rule_file_type,
                }
            )
        if not manifest:
            manifest.append(
                {
                    "name": config["key"],
                    "success": False,
                    "return_code": 2,
                    "message": "未采集到任何规则路径",
                    "copied_paths": [],
                    "path_mode": path_mode,
                    "output_dir": "status",
                    "rule_file_type": rule_file_type,
                }
            )
        return_code = 0 if copied and not errors else 2
        message = "；".join(item["message"] for item in manifest)
    except Exception as exc:
        return_code = 2
        message = str(exc)
        manifest = [
            {
                "name": config["key"],
                "success": False,
                "return_code": return_code,
                "message": message,
                "copied_paths": [],
                "path_mode": path_mode,
                "output_dir": "status",
                "rule_file_type": rule_file_type,
            }
        ]
    (output / "collection_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(message)
    return return_code


if __name__ == "__main__":
    sys.exit(main())
