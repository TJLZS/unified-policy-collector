from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

from .adapters import AdapterRegistry, default_registry
from .config import (
    configured_paths_from_mapping,
    load_yaml_config,
    target_from_mapping,
)
from .factory import create_collector
from .models import (
    CollectionStatus,
    Credential,
    TargetConfig,
    TargetType,
)
from .orchestrator import CollectionOrchestrator


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _yes_no(prompt: str, *, default: bool) -> bool:
    suffix = " [Y/n] " if default else " [y/N] "
    answer = input(prompt + suffix).strip().lower()
    if not answer:
        return default
    if answer in {"y", "yes", "是"}:
        return True
    if answer in {"n", "no", "否"}:
        return False
    print("请输入 y 或 n。")
    return _yes_no(prompt, default=default)


def _choose_target_type() -> TargetType:
    options = {
        "1": TargetType.LINUX,
        "2": TargetType.WINDOWS,
        "3": TargetType.SECURITY,
    }
    while True:
        print("请选择设备类型：")
        print("  1. Linux")
        print("  2. Windows")
        print("  3. 安全设备")
        choice = input("选择：").strip()
        if choice in options:
            return options[choice]
        print("无效选择，请重试。")


def _choose_security_device(registry: AdapterRegistry) -> str:
    adapters = registry.all()
    while True:
        print("请选择安全设备：")
        for index, adapter in enumerate(adapters, 1):
            mode = "Docker宿主机" if adapter.docker else "SSH文件采集"
            print(f"  {index}. {adapter.display_name}（{mode}）")
        choice = input("选择：").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(adapters):
            return adapters[int(choice) - 1].key
        print("无效选择，请重试。")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="统一安全策略远程采集工具",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("collect", "check"):
        subparser = subparsers.add_parser(
            command,
            help="执行采集" if command == "collect" else "仅检查连接与能力",
        )
        subparser.add_argument(
            "--type",
            choices=[item.value for item in TargetType],
            dest="target_type",
        )
        subparser.add_argument("--host", help="目标IP或主机名")
        subparser.add_argument("--port", type=int)
        subparser.add_argument("--username")
        subparser.add_argument("--security-device")
        subparser.add_argument(
            "--path",
            action="append",
            default=[],
            help="本次覆盖安全设备规则路径，可重复指定",
        )
        subparser.add_argument("--container-name")
        sudo_group = subparser.add_mutually_exclusive_group()
        sudo_group.add_argument("--sudo", action="store_true", dest="use_sudo")
        sudo_group.add_argument("--no-sudo", action="store_false", dest="use_sudo")
        subparser.set_defaults(use_sudo=None)
        subparser.add_argument(
            "--https",
            action="store_true",
            default=None,
            help="Windows使用HTTPS WinRM",
        )
        subparser.add_argument(
            "--insecure",
            action="store_true",
            default=None,
            help="显式允许HTTPS WinRM忽略证书校验",
        )
        subparser.add_argument("--config", type=Path, help="非敏感YAML配置")
        subparser.add_argument(
            "--output-root",
            type=Path,
            default=PROJECT_ROOT / "outputs",
        )
    return parser


def _resolve_target(
    args: argparse.Namespace,
    registry: AdapterRegistry,
) -> tuple[TargetConfig, tuple[str, ...]]:
    mapping = load_yaml_config(args.config) if args.config else {}
    base_target = None
    if mapping.get("target"):
        base_target, _ = target_from_mapping(mapping)

    if args.target_type:
        target_type = TargetType(args.target_type)
    elif base_target:
        target_type = base_target.target_type
    else:
        target_type = _choose_target_type()

    host = args.host or (base_target.host if base_target else None)
    if not host:
        host = input("目标IP或主机名：").strip()
    username = args.username or (base_target.username if base_target else None)
    if not username:
        username = input("用户名：").strip()
    default_port = 5985 if target_type is TargetType.WINDOWS else 22
    port = (
        args.port
        if args.port is not None
        else (base_target.port if base_target else default_port)
    )

    security_device = args.security_device
    if not security_device and base_target:
        security_device = base_target.security_device
    if target_type is TargetType.SECURITY and not security_device:
        security_device = _choose_security_device(registry)
    if security_device:
        security_device = registry.resolve(security_device).key

    use_sudo = args.use_sudo
    if use_sudo is None and base_target:
        use_sudo = base_target.use_sudo
    if use_sudo is None and target_type in {TargetType.LINUX, TargetType.SECURITY}:
        use_sudo = _yes_no("是否需要sudo提权？", default=False)
    use_sudo = bool(use_sudo)

    runtime_paths = tuple(args.path)
    configured_paths: tuple[str, ...] = ()
    if security_device:
        configured_paths = configured_paths_from_mapping(mapping, security_device)
        if args.command == "collect" and not runtime_paths and sys.stdin.isatty():
            adapter = registry.resolve(
                security_device,
                configured_paths=configured_paths,
            )
            print("采集路径：")
            for path in adapter.paths:
                print(f"  - {path}")
            if not _yes_no("是否使用以上默认/配置路径？", default=True):
                entered = input("输入自定义路径，多个路径用逗号分隔：").strip()
                runtime_paths = tuple(
                    item.strip() for item in entered.split(",") if item.strip()
                )
                if not runtime_paths:
                    raise ValueError("选择自定义路径后至少需要输入一个路径")

    https = (
        args.https
        if args.https is not None
        else (base_target.winrm_https if base_target else port == 5986)
    )
    insecure = (
        args.insecure
        if args.insecure is not None
        else (base_target.winrm_insecure if base_target else False)
    )
    if insecure and not https:
        raise ValueError("--insecure只能与HTTPS WinRM一起使用")

    container_name = args.container_name or (
        base_target.container_name if base_target else None
    )
    target = TargetConfig(
        target_type=target_type,
        host=host,
        port=port,
        username=username,
        use_sudo=use_sudo,
        security_device=security_device,
        custom_paths=runtime_paths,
        container_name=container_name,
        winrm_https=bool(https),
        winrm_insecure=bool(insecure),
    )
    return target, configured_paths


def _read_credentials(target: TargetConfig) -> Credential:
    password = getpass.getpass("登录密码：")
    sudo_password = None
    if target.use_sudo:
        if _yes_no("sudo密码与登录密码相同？", default=True):
            sudo_password = password
        else:
            sudo_password = getpass.getpass("sudo密码：")
    return Credential(password=password, sudo_password=sudo_password)


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    registry = default_registry()
    try:
        target, configured_paths = _resolve_target(args, registry)
        credential = _read_credentials(target)
        factory = lambda selected_target, selected_credential: create_collector(
            selected_target,
            selected_credential,
            configured_paths=configured_paths,
            registry=registry,
        )
        orchestrator = CollectionOrchestrator(factory)
        if args.command == "check":
            result = orchestrator.check(target, credential)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            print("连接与能力检查成功。")
            return 0

        report = orchestrator.collect(
            target,
            credential,
            output_root=args.output_root,
        )
        print(f"采集状态：{report.status.value}")
        print(f"结果目录：{report.run_dir}")
        if report.error:
            print(f"错误：{report.error}")
        if report.status is CollectionStatus.SUCCESS:
            return 0
        if report.status is CollectionStatus.PARTIAL:
            return 2
        return 1
    except KeyboardInterrupt:
        print("\n用户取消。", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"执行失败：{exc}", file=sys.stderr)
        return 1
