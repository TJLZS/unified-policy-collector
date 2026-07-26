#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Linux 安全策略收集 - 统一测试主入口 (main.py)

按模块收集所有策略信息，集成断点恢复、进度条、采集日志记录等功能。
使用 core 公共组件与 strategy_config 配置，统一执行各策略采集。
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Type

# 确保 Scripts 目录在路径中
_scripts_dir = Path(__file__).resolve().parent
if str(_scripts_dir) not in sys.path:
    sys.path.insert(0, str(_scripts_dir))

import shutil
from core import (
    CheckpointManager,
    CollectorModuleBase,
    StrategyCollectorBase,
    create_progress_bar,
    update_progress,
    close_progress_bar,
    setup_collection_logging,
)
from core.checksum import (
    file_checksum,
    load_collection_checksums,
    save_collection_checksums,
)
from core.strategy_runner import StrategyCollectorBase as _StrategyCollectorBase


# ============== 通用采集模块（基于 strategy_config） ==============


class GenericStrategyModule(CollectorModuleBase):
    """
    通用策略采集模块：基于 paths_config + commands_config + 可选 analyzer 执行采集。
    """

    def __init__(
        self,
        name: str,
        output_dir: Path,
        checkpoint_manager: CheckpointManager,
        paths_config: Any,
        commands_config: Any,
        analyzer_class: Optional[Type] = None,
        status_subdir: str = "status_info",
    ):
        super().__init__(name, output_dir, checkpoint_manager)
        self.paths_config = paths_config
        self.commands_config = commands_config
        self.analyzer_class = analyzer_class
        self.status_subdir = status_subdir

    def collect(self) -> bool:
        try:
            prev_checksums = load_collection_checksums(self.output_dir) if getattr(self, "use_refresh", True) else {}
            # 1. 复制 config_paths -> config_files/（按校验和增量更新）
            self._collect_config_paths(prev_checksums)
            # 2. 复制 log_paths -> logs/
            self._collect_log_paths(prev_checksums)
            # 3. 执行 status_group -> status_info/ 或 status_subdir（按校验和跳过未变输出）
            self._collect_status_commands(prev_checksums)
            # 4. 执行 log_group -> logs/
            self._collect_log_commands(prev_checksums)
            # 5. 运行 analyzer（若有）
            if self.analyzer_class:
                analyzer = self.analyzer_class(self.output_dir)
                result = analyzer.run(save=True, add_to_manifest=self._add_to_manifest)
                if not result.success:
                    import logging
                    logging.warning("安全分析完成但有异常: %s", result.error)
            # 6. 生成文件统计
            self._generate_file_statistics()
            # 7. 删除本次未采集到的旧文件
            self._remove_stale_outputs()
            # 8. 保存本次采集的校验和清单
            self._save_collection_checksums()
            return True
        except Exception as e:
            import logging
            logging.error("策略采集失败 %s: %s", self.name, e)
            return False

    def _collect_config_paths(self, prev_checksums: Dict[str, str]) -> None:
        config_dir = self.output_dir / "config_files"
        config_dir.mkdir(exist_ok=True)
        for p in self.paths_config.config_paths:
            path = Path(p)
            if path.exists():
                if path.is_dir():
                    part = path.parent.name + ("_" + path.name if path.name else "")
                    target_subdir = f"config_files/{part}"
                    try:
                        self._copy_directory_incremental(path, target_subdir, prev_checksums)
                    except Exception as e:
                        import logging
                        logging.warning("无法复制目录 %s: %s", p, e)
                else:
                    self._copy_file(
                        path, f"config_files/{path.name}",
                        previous_checksums=prev_checksums,
                    )

    def _collect_log_paths(self, prev_checksums: Dict[str, str]) -> None:
        log_dir = self.output_dir / "logs"
        log_dir.mkdir(exist_ok=True)
        for p in self.paths_config.log_paths:
            path = Path(p)
            if path.exists() and path.is_file():
                try:
                    self._copy_file(
                        path, f"logs/{path.name}.txt",
                        skip_unchanged=True,
                        previous_checksums=prev_checksums,
                    )
                except Exception:
                    pass

    def _collect_status_commands(self, prev_checksums: Dict[str, str]) -> None:
        group = self.commands_config.get_group("status_info")
        if not group:
            group = self.commands_config.get_all_commands()
        for name, cmd in group.items():
            out_rel = f"{self.status_subdir}/{name}.txt"
            self._run_command(cmd, out_rel, previous_checksum=prev_checksums.get(out_rel))

    def _collect_log_commands(self, prev_checksums: Dict[str, str]) -> None:
        group = self.commands_config.get_group("logs")
        if group:
            for name, cmd in group.items():
                out_rel = f"logs/{name}.txt"
                self._run_command(cmd, out_rel, previous_checksum=prev_checksums.get(out_rel))

    def _save_collection_checksums(self) -> None:
        """根据 file_manifest 计算各文件校验和并保存到 collection_checksums.json。"""
        files_checksums = {}
        for m in self.file_manifest:
            rel = Path(m["relative_path"]).as_posix()
            fp = self.output_dir / rel
            if fp.exists() and fp.is_file():
                cs = file_checksum(fp)
                if cs:
                    files_checksums[rel] = cs
        save_collection_checksums(self.output_dir, files_checksums)
        cs_path = self.output_dir / "collection_checksums.json"
        if cs_path.exists():
            self._add_to_manifest(cs_path, "generated")

    def _remove_stale_outputs(self) -> None:
        """删除本次未采集到的旧文件，使输出目录与当前配置一致（更新由校验码在 _copy_file 中决定）。"""
        if not self.output_dir.exists():
            return
        manifest_rel = {Path(m["relative_path"]).as_posix() for m in self.file_manifest}
        to_remove = []
        for fp in self.output_dir.rglob("*"):
            if fp.is_file():
                try:
                    rel = fp.relative_to(self.output_dir).as_posix()
                except ValueError:
                    continue
                if rel not in manifest_rel:
                    to_remove.append(fp)
        for fp in to_remove:
            try:
                fp.unlink()
            except Exception as e:
                import logging
                logging.warning("删除过期输出文件失败 %s: %s", fp, e)
        for d in sorted(self.output_dir.rglob("*"), key=lambda p: len(p.parts), reverse=True):
            if d.is_dir() and not any(d.iterdir()):
                try:
                    d.rmdir()
                except Exception:
                    pass


# ============== 策略采集器（带报告生成） ==============


class StrategyCollectorWithReport(_StrategyCollectorBase):
    """带报告生成的策略采集器"""

    strategy_name = "策略"  # 默认，运行时覆盖

    def __init__(
        self,
        strategy_name: str,
        base_dir: Path,
        modules: List[CollectorModuleBase],
        log_filename: str,
        checkpoint_filename: str,
        summary_title: str,
    ):
        self.strategy_name = strategy_name
        self.summary_title = summary_title
        super().__init__(
            base_dir=base_dir,
            modules=modules,
            log_filename=log_filename,
            checkpoint_filename=checkpoint_filename,
        )
        self.strategy_name = strategy_name

    def on_after_collect(self, success_count: int, failed_modules: List[str]) -> None:
        self._generate_summary(success_count, failed_modules)

    def _generate_summary(self, success_count: int, failed_modules: List[str]) -> None:
        try:
            total = len(self.modules)
            summary_path = self.base_dir / f"{self.strategy_name}策略采集摘要.txt"
            with open(summary_path, "w", encoding="utf-8") as f:
                f.write("=" * 60 + "\n")
                f.write(f"{self.summary_title}\n")
                f.write("=" * 60 + "\n\n")
                f.write(f"采集时间: {datetime.now().isoformat()}\n")
                f.write(f"系统类型: {self.checkpoint_manager.checkpoint_data.get('system_type', 'unknown')}\n")
                f.write(f"成功模块: {success_count}/{total}\n")
                if failed_modules:
                    f.write(f"失败模块: {', '.join(failed_modules)}\n")
                f.write(f"输出目录: {self.base_dir}\n\n")
                f.write("各模块输出:\n" + "-" * 40 + "\n")
                for m in self.modules:
                    mod_dir = self.base_dir / m.name
                    fc = sum(1 for _ in mod_dir.rglob("*") if _.is_file()) if mod_dir.exists() else 0
                    f.write(f"  {m.name}: {fc} 个文件\n")
                f.write("\n" + "=" * 60 + "\n")
        except Exception as e:
            self.logger.error("生成摘要失败: %s", e)


# ============== 策略注册与运行 ==============


def _register_strategies() -> List[Dict[str, Any]]:
    """注册所有策略：返回 (strategy_id, output_subdir, modules_factory) 列表"""
    strategies = []

    def add(
        sid: str,
        output_subdir: str,
        module_name: str,
        paths_getter: Callable,
        commands_getter: Callable,
        analyzer_class: Optional[Type] = None,
        status_subdir: str = "status_info",
    ):
        def factory(base: Path, cp: CheckpointManager):
            paths = paths_getter()
            commands = commands_getter()
            mod = GenericStrategyModule(
                module_name, base, cp, paths, commands, analyzer_class, status_subdir
            )
            return [mod]

        strategies.append({
            "id": sid,
            "output_subdir": output_subdir,
            "title": sid,
            "factory": factory,
        })

    # Apache
    from strategy_config.apache_config import get_apache_paths_config, get_apache_commands_config
    from analyzer.apache_analyzer import ApacheSecurityAnalyzer
    add("Apache", "Linux_apache_config", "Apache", get_apache_paths_config, get_apache_commands_config, ApacheSecurityAnalyzer)

    # SELinux
    from strategy_config.selinux_config import get_selinux_paths_config, get_selinux_commands_config
    from analyzer.selinux_analyzer import SelinuxSecurityAnalyzer
    add("SELinux", "Linux_selinux_config", "SELinux", get_selinux_paths_config, get_selinux_commands_config, SelinuxSecurityAnalyzer)

    # Nginx
    from strategy_config.nginx_config import get_nginx_paths_config, get_nginx_commands_config
    from analyzer.nginx_analyzer import NginxSecurityAnalyzer
    add("Nginx", "Linux_nginx_config", "Nginx", get_nginx_paths_config, get_nginx_commands_config, NginxSecurityAnalyzer)

    # MySQL
    from strategy_config.mysql_config import get_mysql_paths_config, get_mysql_commands_config
    from analyzer.mysql_analyzer import MysqlSecurityAnalyzer
    add("MySQL", "Linux_mysql_config", "MySQL", get_mysql_paths_config, get_mysql_commands_config, MysqlSecurityAnalyzer)

    # Auditd
    from strategy_config.auditd_config import get_auditd_paths_config, get_auditd_commands_config
    from analyzer.auditd_analyzer import AuditdSecurityAnalyzer
    add("Auditd", "Linux_audit_config", "Audit", get_auditd_paths_config, get_auditd_commands_config, AuditdSecurityAnalyzer, status_subdir="runtime_info")

    # LUKS
    from strategy_config.luks_config import get_luks_paths_config, get_luks_commands_config
    from analyzer.luks_analyzer import LuksSecurityAnalyzer
    add("LUKS", "Linux_luks_config", "LUKS", get_luks_paths_config, get_luks_commands_config, LuksSecurityAnalyzer)

    # chkrootkit
    from strategy_config.chkrootkit_config import get_chkrootkit_paths_config, get_chkrootkit_commands_config
    from analyzer.chkrootkit_analyzer import ChkrootkitSecurityAnalyzer
    add("chkrootkit", "Linux_chkrootkit_config", "chkrootkit", get_chkrootkit_paths_config, get_chkrootkit_commands_config, ChkrootkitSecurityAnalyzer)

    # Docker
    from strategy_config.docker_config import get_docker_paths_config, get_docker_commands_config
    from analyzer.docker_analyzer import DockerSecurityAnalyzer
    add("Docker", "Linux_docker_config", "Docker", get_docker_paths_config, get_docker_commands_config, DockerSecurityAnalyzer)

    # AppArmor
    from strategy_config.apparmor_config import get_apparmor_paths_config, get_apparmor_commands_config
    from analyzer.apparmor_analyzer import ApparmorSecurityAnalyzer
    add("AppArmor", "Linux_apparmor_config", "AppArmor", get_apparmor_paths_config, get_apparmor_commands_config, ApparmorSecurityAnalyzer)

    # Firewall - iptables 与 firewalld 合并为一个策略，两套路径+命令
    from strategy_config.firewall_config import get_iptables_paths_config, get_firewalld_paths_config, get_firewall_commands_config
    from analyzer.iptables_analyzer import IptablesSecurityAnalyzer
    from analyzer.firewalld_analyzer import FirewalldSecurityAnalyzer
    def firewall_factory(base: Path, cp: CheckpointManager):
        ipt_paths = get_iptables_paths_config()
        fw_paths = get_firewalld_paths_config()
        fw_cmds = get_firewall_commands_config()
        # 合并路径，分两个模块采集
        mod_ipt = GenericStrategyModule("Iptables", base, cp, ipt_paths, fw_cmds, IptablesSecurityAnalyzer)
        mod_fw = GenericStrategyModule("Firewalld", base, cp, fw_paths, fw_cmds, FirewalldSecurityAnalyzer)
        return [mod_ipt, mod_fw]
    strategies.append({
        "id": "Firewall",
        "output_subdir": "Linux_firewall_config",
        "title": "防火墙(iptables/firewalld)",
        "factory": firewall_factory,
    })

    # TCP_Wrappers
    from strategy_config.tcp_wrappers_config import get_tcp_wrappers_paths_config, get_tcp_wrappers_commands_config
    from analyzer.tcp_wrappers_analyzer import TcpWrappersSecurityAnalyzer
    add("TCP_Wrappers", "Linux_tcp_wrappers_config", "TCP_Wrappers", get_tcp_wrappers_paths_config, get_tcp_wrappers_commands_config, TcpWrappersSecurityAnalyzer)

    # ACL（按模块输出：FileACL、Namespace、Seccomp、Capability）
    from strategy_config.acl_config import (
        get_acl_file_acl_paths_config,
        get_acl_file_acl_commands_config,
        get_acl_namespace_paths_config,
        get_acl_namespace_commands_config,
        get_acl_seccomp_paths_config,
        get_acl_seccomp_commands_config,
        get_acl_capability_paths_config,
        get_acl_capability_commands_config,
    )

    def acl_factory(base: Path, cp: CheckpointManager):
        return [
            GenericStrategyModule(
                "FileACL", base, cp,
                get_acl_file_acl_paths_config(), get_acl_file_acl_commands_config(),
            ),
            GenericStrategyModule(
                "Namespace", base, cp,
                get_acl_namespace_paths_config(), get_acl_namespace_commands_config(),
            ),
            GenericStrategyModule(
                "Seccomp", base, cp,
                get_acl_seccomp_paths_config(), get_acl_seccomp_commands_config(),
            ),
            GenericStrategyModule(
                "Capability", base, cp,
                get_acl_capability_paths_config(), get_acl_capability_commands_config(),
            ),
        ]

    strategies.append({
        "id": "ACL",
        "output_subdir": "Linux_acl_config",
        "title": "ACL(FileACL/Namespace/Seccomp/Capability)",
        "factory": acl_factory,
    })

    # StartupItems
    from strategy_config.startup_config import get_startup_paths_config, get_startup_commands_config
    add("StartupItems", "Linux_startup_config", "StartupItems", get_startup_paths_config, get_startup_commands_config)

    # K8S
    from strategy_config.k8s_config import get_k8s_paths_config, get_k8s_commands_config
    from analyzer.k8s_analyzer import K8sSecurityAnalyzer
    add("K8S", "Linux_k8s_security_config", "Kubernetes", get_k8s_paths_config, get_k8s_commands_config, K8sSecurityAnalyzer)

    # User_identity（聚合）
    from strategy_config.user_identity_config import get_user_identity_paths_config, get_user_identity_commands_config
    add("User_identity", "Linux_user_identity_config", "User_identity", get_user_identity_paths_config, get_user_identity_commands_config)

    # 日志分析工具
    from strategy_config.logtools_config import get_logtools_paths_config, get_logtools_commands_config
    add("Logtools", "Linux_logtools_config", "Logwatch", get_logtools_paths_config, get_logtools_commands_config)

    return strategies


def run_all_strategies(
    base_output: Path,
    strategies: Optional[List[str]] = None,
    resume: bool = False,
    force_strategies: Optional[List[str]] = None,
    refresh: bool = True,
) -> bool:
    """执行所有（或指定）策略采集。resume：从断点跳过已完成；refresh：按校验和增量更新（默认开启）。"""
    all_reg = _register_strategies()
    if strategies:
        reg = [r for r in all_reg if r["id"] in strategies]
        if not reg:
            print("未找到指定策略，可用: " + ", ".join(r["id"] for r in all_reg))
            return False
    else:
        reg = all_reg

    base_output = Path(base_output)
    base_output.mkdir(parents=True, exist_ok=True)
    test_checkpoint = base_output / "test_collection_checkpoint.json"
    test_log = base_output / "test_collection.log"

    setup_collection_logging(base_output, log_filename=test_log.name)
    import logging
    logger = logging.getLogger("test_main")

    # 加载顶层断点
    if test_checkpoint.exists():
        with open(test_checkpoint, "r", encoding="utf-8") as f:
            cp_data = json.load(f)
        completed_ids = set(cp_data.get("completed_strategies", []))
    else:
        completed_ids = set()
        cp_data = {"completed_strategies": [], "last_updated": datetime.now().isoformat()}

    if not resume:
        completed_ids.clear()
        cp_data["completed_strategies"] = []
    elif force_strategies:
        for sid in force_strategies:
            completed_ids.discard(sid)
        cp_data["completed_strategies"] = list(completed_ids)

    def write_manifest(failed_ids=None):
        failed_set = set(failed_ids or [])
        manifest = []
        for item in reg:
            strategy_id = item["id"]
            success = strategy_id in completed_ids and strategy_id not in failed_set
            if success:
                message = "策略采集成功"
            elif strategy_id in failed_set:
                message = "策略采集失败，详情请查看对应日志"
            else:
                message = "策略未完成"
            manifest.append(
                {
                    "name": strategy_id,
                    "success": success,
                    "return_code": 0 if success else 1,
                    "message": message,
                    "output_dir": str(item["output_subdir"]),
                }
            )
        with open(
            base_output / "collection_manifest.json",
            "w",
            encoding="utf-8",
        ) as stream:
            json.dump(manifest, stream, indent=2, ensure_ascii=False)

    remaining = [r for r in reg if r["id"] not in completed_ids]
    if not remaining:
        write_manifest()
        logger.info("所有策略已采集完成")
        print("所有策略已采集完成")
        return True

    logger.info("开始采集，共 %d 个策略，待执行 %d 个", len(reg), len(remaining))
    print(f"\n开始采集: 共 {len(reg)} 个策略，待执行 {len(remaining)} 个\n")

    progress_bar = create_progress_bar(total=len(remaining), desc="策略采集", unit="策略")
    failed = []

    try:
        for s in remaining:
            sid = s["id"]
            out_sub = s["output_subdir"]
            base_dir = base_output / out_sub
            base_dir.mkdir(parents=True, exist_ok=True)
            cp_file = base_dir / "collection_checkpoint.json"
            # 清除策略级断点：--force 指定策略时，或 --refresh/--no-resume 全量重采时
            if cp_file.exists() and (not resume or (force_strategies and sid in force_strategies)):
                try:
                    cp_file.unlink()
                    logger.info("已清除策略 %s 的断点，将重新采集", sid)
                except Exception as e:
                    logger.warning("清除策略 %s 断点失败: %s", sid, e)
            cp_manager = CheckpointManager(cp_file)
            modules = s["factory"](base_dir, cp_manager)
            for m in modules:
                m.use_refresh = refresh

            collector = StrategyCollectorWithReport(
                strategy_name=sid,
                base_dir=base_dir,
                modules=modules,
                log_filename=f"{sid.lower().replace(' ', '_')}_collection.log",
                checkpoint_filename="collection_checkpoint.json",
                summary_title=f"Linux {s['title']} 策略采集",
            )

            try:
                ok = collector.run()
                if ok:
                    completed_ids.add(sid)
                    cp_data["completed_strategies"] = list(completed_ids)
                    cp_data["last_updated"] = datetime.now().isoformat()
                    with open(test_checkpoint, "w", encoding="utf-8") as f:
                        json.dump(cp_data, f, indent=2, ensure_ascii=False)
                    logger.info("策略 %s 采集完成", sid)
                else:
                    failed.append(sid)
            except Exception as e:
                failed.append(sid)
                logger.exception("策略 %s 采集异常: %s", sid, e)

            update_progress(progress_bar)

        close_progress_bar(progress_bar)
        write_manifest(failed)

        if failed:
            logger.warning("采集完成，失败策略: %s", failed)
            print(f"\n采集完成，失败策略: {failed}")
            return False
        logger.info("所有策略采集完成")
        print("\n所有策略采集完成")
        return True

    except KeyboardInterrupt:
        close_progress_bar(progress_bar)
        cp_data["completed_strategies"] = list(completed_ids)
        cp_data["last_updated"] = datetime.now().isoformat()
        with open(test_checkpoint, "w", encoding="utf-8") as f:
            json.dump(cp_data, f, indent=2, ensure_ascii=False)
        write_manifest(failed)
        logger.info("用户中断，断点已保存")
        print("\n用户中断，断点已保存")
        return False


def main():
    """主函数"""
    import argparse
    parser = argparse.ArgumentParser(description="Linux 安全策略统一采集（按模块）")
    parser.add_argument("--all", action="store_true", help="从头开始执行所有策略模块（默认）")
    parser.add_argument("--select", nargs="+", help="选择某个/某些策略模块执行")
    parser.add_argument("--resume", action="store_true", help="从断点开始，跳过已完成策略")
    parser.add_argument("--refresh", action="store_true", default=True, help="检查文件更新，按校验和增量更新（默认开启）")
    parser.add_argument("--no-refresh", dest="refresh", action="store_false", help="禁用文件更新检查，强制全量覆盖")
    parser.add_argument("--output", "-o", default=None, help="输出目录，默认 Collected_files")
    parser.add_argument("--list", "-l", action="store_true", help="列出所有可用策略")

    args = parser.parse_args()

    script_dir = Path(__file__).resolve().parent
    base_output = Path(args.output) if args.output else script_dir.parent / "Collected_files"

    if args.list:
        reg = _register_strategies()
        print("可用策略:")
        for i, r in enumerate(reg, 1):
            print(f"  {i}. {r['id']} - {r['output_subdir']}")
        return

    strategies = args.select if args.select else None
    resume = args.resume
    refresh = args.refresh

    print("=" * 60)
    print("Linux 安全策略统一采集工具 (main.py)")
    print("=" * 60)
    print(f"输出目录: {base_output}")
    print(f"断点恢复: {'启用' if resume else '禁用（从头执行）'}")
    print(f"文件更新检查: {'启用' if refresh else '禁用'}")
    print("=" * 60)

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("提示: 未使用 root 权限，部分文件可能无法访问\n")

    try:
        ok = run_all_strategies(
            base_output,
            strategies=strategies,
            resume=resume,
            force_strategies=None,
            refresh=refresh,
        )
        sys.exit(0 if ok else 1)
    except KeyboardInterrupt:
        print("\n用户中断")
        sys.exit(1)
    except Exception as e:
        print(f"\n执行异常: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
