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


def copy_match(source, destination):
    if source.is_symlink():
        raise RuntimeError("跳过符号链接: {}".format(source))
    if source.is_dir():
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
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def collect_filesystem(config, output):
    copied = []
    errors = []
    data_dir = output / "rules"
    data_dir.mkdir(parents=True, exist_ok=True)
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
                copy_match(match, destination)
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
        raise RuntimeError("未找到匹配的WAF容器；当前容器: {}".format(available))
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
    for index, path in enumerate(config["paths"], 1):
        destination = data_dir / "{}_{}".format(index, safe_name(Path(path).name))
        command = "docker cp {}:{} {}".format(
            container["id"],
            shlex.quote(path),
            shlex.quote(str(destination)),
        )
        result = run(command, timeout=300)
        if result.returncode == 0:
            if destination.exists():
                for child in destination.rglob("*"):
                    if child.is_symlink():
                        child.unlink()
            copied.append("{}:{}".format(container["name"], path))
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
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    try:
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
