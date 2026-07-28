from __future__ import annotations

import hashlib
import json
import re
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .adapters import default_registry
from .security import redact_text


ANALYZER_VERSION = 2
REPORT_NAME = "analysis_report.json"
HISTORY_INDEX_NAME = ".history_index.json"
HISTORY_INDEX_VERSION = 1
HISTORY_SAMPLE_BYTES = 4096
MAX_EVIDENCE_BYTES = 256 * 1024
MAX_EVIDENCE_CHARS = 1200

WINDOWS_CONDITIONAL_MODULES = {
    "Get-BitLockerStatus",
    "Get-LAPSOperationalLogs",
    "Get-LAPSSettings",
    "Get-WindowsDefenderStatus",
    "Get-GPOs",
    "Get-PasswordPolicy-Domain",
}

LINUX_BASELINE_MODULES = {
    "Firewall",
    "ACL",
    "StartupItems",
    "User_identity",
}

LINUX_OUTPUT_DIRS = {
    "Apache": "Linux_apache_config",
    "SELinux": "Linux_selinux_config",
    "Nginx": "Linux_nginx_config",
    "MySQL": "Linux_mysql_config",
    "Auditd": "Linux_audit_config",
    "LUKS": "Linux_luks_config",
    "chkrootkit": "Linux_chkrootkit_config",
    "Docker": "Linux_docker_config",
    "AppArmor": "Linux_apparmor_config",
    "Firewall": "Linux_firewall_config",
    "TCP_Wrappers": "Linux_tcp_wrappers_config",
    "ACL": "Linux_acl_config",
    "StartupItems": "Linux_startup_config",
    "K8S": "Linux_k8s_security_config",
    "User_identity": "Linux_user_identity_config",
    "Logtools": "Linux_logtools_config",
}

PERMISSION_MARKERS = (
    "access is denied",
    "access denied",
    "permission denied",
    "unauthorized",
    "拒绝访问",
    "权限不足",
)
NOT_DOMAIN_MARKERS = (
    "not joined to a domain",
    "not domain joined",
    "could not find domain",
    "no domain controller",
    "system error 1355",
    "error 1355",
    "the specified domain either does not exist or could not be contacted",
    "找不到域",
    "未加入域",
    "域控制器不可用",
)
ABSENT_MARKERS = (
    "not recognized as the name of a cmdlet",
    "specified channel could not be found",
    "cannot find",
    "not found",
    "not installed",
    "no such file or directory",
    "command not found",
    "未找到",
    "找不到",
    "不存在",
    "未安装",
)

RECOMMENDATIONS = {
    "permission_denied": [
        "使用具备读取该策略权限的管理员或专用只读采集账号重新采集。",
        "核对目标日志、注册表、Docker或文件路径的访问控制。",
    ],
    "dependency_missing": [
        "确认目标是否应安装对应命令、PowerShell模块或安全产品组件。",
        "安装或启用依赖后重新执行连接检查和采集。",
    ],
    "not_domain_joined": [
        "独立服务器无需采集域策略，可将该项视为不适用。",
        "如目标应加入域，请先核对域成员关系和域控制器连通性。",
    ],
    "feature_absent": [
        "确认目标是否计划启用该功能；未部署时无需修改目标。",
        "如该功能属于验收要求，部署后重新采集。",
    ],
    "path_missing": [
        "核对安全设备实际规则目录，并在高级选项中填写正确路径。",
        "确认采集账号对规则目录具有只读权限。",
    ],
    "container_not_found": [
        "在宿主机执行 docker ps，核对安全设备容器名称和镜像。",
        "在采集表单中填写准确且唯一的容器名称。",
    ],
    "container_ambiguous": [
        "在采集表单中填写准确且唯一的容器名称。",
    ],
    "transport_failed": [
        "重新执行连接检查，核对端口、认证、路由及主机指纹。",
    ],
    "archive_failed": [
        "核对目标临时目录空间以及tar、ZIP或Compress-Archive能力。",
    ],
    "cleanup_failed": [
        "人工检查本次UUID临时目录，确认内容后再执行清理。",
        "核对采集账号对临时目录的删除权限。",
    ],
    "command_failed": [
        "查看证据片段和对应原始输出，确认命令返回非零的具体原因。",
    ],
    "unknown_failure": [
        "当前证据不足，需查看对应原始输出文件进行人工核查。",
    ],
}

REASON_EXPLANATIONS = {
    "permission_denied": "采集账号没有读取该策略所需的权限。",
    "dependency_missing": "目标缺少执行该模块所需的命令、组件或依赖。",
    "not_domain_joined": "目标未加入域，域相关策略不适用。",
    "feature_absent": "目标未安装或未启用该条件功能。",
    "path_missing": "未找到要求采集的规则路径。",
    "container_not_found": "未找到指定的安全设备容器。",
    "container_ambiguous": "匹配到多个安全设备容器，无法唯一确定采集目标。",
    "transport_failed": "连接、认证、上传或下载等传输流程失败。",
    "archive_failed": "远程采集结果打包失败。",
    "cleanup_failed": "远程临时目录未能成功清理。",
    "command_failed": "采集命令执行失败或返回非零状态。",
    "unknown_failure": "现有证据不足，原因待人工核查。",
}


class RunNotFoundError(KeyError):
    pass


class ResultAnalysisService:
    """隐藏结果发现、安全解析、原因归类和报告缓存的深模块。"""

    def __init__(self, output_root: Path) -> None:
        self.output_root = Path(output_root)
        self._history_index_lock = threading.RLock()

    def list_runs(self, limit: int = 20) -> list[dict[str, object]]:
        return [
            self._run_list_item(run_id, run_dir, summary)
            for run_id, run_dir, summary in self._discover_runs()[:limit]
        ]

    def query_runs(
        self,
        *,
        page: int,
        page_size: int,
        target_type: str | None = None,
        target_ip: str | None = None,
        status: str | None = None,
    ) -> dict[str, object]:
        with self._history_index_lock:
            normalized_ip = (target_ip or "").strip().casefold()
            discovered = self._discover_runs()
            candidates: list[tuple[str, Path, dict[str, Any]]] = []
            for run_id, run_dir, summary in discovered:
                if target_type and summary.get("target_type") != target_type:
                    continue
                if normalized_ip and normalized_ip not in str(
                    summary.get("target_ip", "")
                ).casefold():
                    continue
                candidates.append((run_id, run_dir, summary))

            index_entries = self._load_history_index()
            discovered_ids = {run_id for run_id, _, _ in discovered}
            stale_ids = set(index_entries) - discovered_ids
            for stale_id in stale_ids:
                del index_entries[stale_id]
            index_changed = bool(stale_ids)

            if status:
                records: list[dict[str, object]] = []
                for run_id, run_dir, summary in candidates:
                    item, changed = self._indexed_history_item(
                        run_id,
                        run_dir,
                        summary,
                        index_entries,
                    )
                    index_changed = index_changed or changed
                    if item["assessment_status"] == status:
                        records.append(item)
                total = len(records)
                pages = (total + page_size - 1) // page_size
                normalized_page = min(page, pages) if pages else 1
                start = (normalized_page - 1) * page_size
                items = records[start : start + page_size]
            else:
                total = len(candidates)
                pages = (total + page_size - 1) // page_size
                normalized_page = min(page, pages) if pages else 1
                start = (normalized_page - 1) * page_size
                items = []
                for run_id, run_dir, summary in candidates[
                    start : start + page_size
                ]:
                    item, changed = self._indexed_history_item(
                        run_id,
                        run_dir,
                        summary,
                        index_entries,
                    )
                    index_changed = index_changed or changed
                    items.append(item)
            if index_changed:
                self._save_history_index(index_entries)
            return {
                "items": items,
                "page": normalized_page,
                "page_size": page_size,
                "total": total,
                "pages": pages,
            }

    def _indexed_history_item(
        self,
        run_id: str,
        run_dir: Path,
        summary: dict[str, Any],
        index_entries: dict[str, dict[str, object]],
    ) -> tuple[dict[str, object], bool]:
        marker = self._history_source_marker(run_dir)
        cached = index_entries.get(run_id)
        if cached and cached.get("source_marker") == marker:
            item = cached.get("item")
            if isinstance(item, dict) and self._valid_history_index_item(
                item,
                run_id,
            ):
                sanitized_item = dict(item)
                sanitized_item.pop("run_dir", None)
                return sanitized_item, False

        item = self._history_list_item(run_id, run_dir, summary)
        index_entries[run_id] = {
            "source_marker": self._history_source_marker(run_dir),
            "item": item,
        }
        return item, True

    def _history_source_marker(self, run_dir: Path) -> str:
        root = run_dir.resolve()
        records: list[str] = []
        for path in sorted(run_dir.rglob("*")):
            try:
                resolved = path.resolve()
                resolved.relative_to(root)
                if (
                    not resolved.is_file()
                    or resolved.name == REPORT_NAME
                    or resolved.suffix.lower() not in {".json", ".txt", ".log"}
                ):
                    continue
                stat = resolved.stat()
            except (OSError, ValueError):
                continue
            records.append(
                f"{resolved.relative_to(root).as_posix()}:"
                f"{stat.st_size}:{stat.st_mtime_ns}:{stat.st_ctime_ns}:"
                f"{self._bounded_file_fingerprint(resolved, stat.st_size)}"
            )
        return hashlib.sha256("\n".join(records).encode("utf-8")).hexdigest()

    def _bounded_file_fingerprint(self, path: Path, size: int) -> str:
        digest = hashlib.sha256()
        try:
            with path.open("rb") as stream:
                offsets = {0}
                if size > HISTORY_SAMPLE_BYTES:
                    offsets.add(max(0, size // 2 - HISTORY_SAMPLE_BYTES // 2))
                    offsets.add(max(0, size - HISTORY_SAMPLE_BYTES))
                for offset in sorted(offsets):
                    stream.seek(offset)
                    digest.update(str(offset).encode("ascii"))
                    digest.update(stream.read(HISTORY_SAMPLE_BYTES))
        except OSError:
            return "unreadable"
        return digest.hexdigest()

    def _valid_history_index_item(
        self,
        item: object,
        run_id: str,
    ) -> bool:
        if not isinstance(item, dict) or item.get("run_id") != run_id:
            return False
        if item.get("assessment_status") not in {
            "success",
            "partial",
            "failed",
        }:
            return False
        if item.get("collection_status") not in {
            "success",
            "partial",
            "failed",
        }:
            return False
        counts = item.get("counts")
        if not isinstance(counts, dict):
            return False
        if any(
            not isinstance(counts.get(status), int)
            for status in ("success", "failed", "not_applicable", "skipped")
        ):
            return False
        return all(
            isinstance(item.get(field), list)
            for field in ("successful_modules", "failed_modules")
        )

    def _load_history_index(self) -> dict[str, dict[str, object]]:
        index_path = self.output_root / HISTORY_INDEX_NAME
        try:
            document = json.loads(index_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        if (
            not isinstance(document, dict)
            or document.get("schema_version") != HISTORY_INDEX_VERSION
            or document.get("analyzer_version") != ANALYZER_VERSION
        ):
            return {}
        entries = document.get("entries")
        if not isinstance(entries, dict):
            return {}
        return {
            str(run_id): entry
            for run_id, entry in entries.items()
            if isinstance(entry, dict)
        }

    def _save_history_index(
        self,
        entries: dict[str, dict[str, object]],
    ) -> None:
        temporary_path: Path | None = None
        try:
            self.output_root.mkdir(parents=True, exist_ok=True)
            index_path = self.output_root / HISTORY_INDEX_NAME
            temporary_path = index_path.with_name(
                f".{HISTORY_INDEX_NAME.lstrip('.')}.{uuid.uuid4().hex}.tmp"
            )
            temporary_path.write_text(
                json.dumps(
                    {
                        "schema_version": HISTORY_INDEX_VERSION,
                        "analyzer_version": ANALYZER_VERSION,
                        "entries": entries,
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )
            temporary_path.replace(index_path)
        except OSError:
            return
        finally:
            if temporary_path is not None:
                try:
                    temporary_path.unlink(missing_ok=True)
                except OSError:
                    pass

    def _history_list_item(
        self,
        run_id: str,
        run_dir: Path,
        summary: dict[str, Any],
    ) -> dict[str, object]:
        item = self._run_list_item(run_id, run_dir, summary)
        item.pop("run_dir", None)
        return item

    def _run_list_item(
        self,
        run_id: str,
        run_dir: Path,
        summary: dict[str, Any],
    ) -> dict[str, object]:
        analysis = self._analyze_path(run_id, run_dir, summary)
        return {
            "run_id": run_id,
            "target_type": summary.get("target_type"),
            "target_ip": summary.get("target_ip"),
            "security_device": summary.get("security_device"),
            "custom_device_name": summary.get("custom_device_name"),
            "started_at": summary.get("started_at"),
            "collection_status": summary.get("status", "failed"),
            "assessment_status": analysis["assessment_status"],
            "counts": analysis["counts"],
            "successful_modules": summary.get("successful_modules", []),
            "failed_modules": summary.get("failed_modules", []),
            "run_dir": str(run_dir),
        }

    def analyze(self, run_id: str) -> dict[str, object]:
        for candidate_id, run_dir, summary in self._discover_runs():
            if candidate_id == run_id:
                return self._analyze_path(candidate_id, run_dir, summary)
        raise RunNotFoundError(run_id)

    def _discover_runs(self) -> list[tuple[str, Path, dict[str, Any]]]:
        if not self.output_root.exists():
            return []
        root = self.output_root.resolve()
        discovered: list[tuple[int, str, Path, dict[str, Any]]] = []
        for summary_path in self.output_root.rglob("collection_summary.json"):
            try:
                resolved = summary_path.resolve()
                resolved.relative_to(root)
                summary = json.loads(resolved.read_text(encoding="utf-8-sig"))
                if not isinstance(summary, dict):
                    continue
                relative = resolved.parent.relative_to(root).as_posix()
                run_id = hashlib.sha256(relative.encode("utf-8")).hexdigest()
                discovered.append(
                    (resolved.stat().st_mtime_ns, run_id, resolved.parent, summary)
                )
            except (OSError, ValueError, json.JSONDecodeError):
                continue
        discovered.sort(key=lambda item: item[0], reverse=True)
        return [
            (run_id, run_dir, summary)
            for _, run_id, run_dir, summary in discovered
        ]

    def _analyze_path(
        self,
        run_id: str,
        run_dir: Path,
        summary: dict[str, Any],
    ) -> dict[str, object]:
        fingerprint = self._source_fingerprint(run_dir)
        report_path = run_dir / REPORT_NAME
        if report_path.exists():
            try:
                cached = json.loads(report_path.read_text(encoding="utf-8"))
                if (
                    cached.get("analyzer_version") == ANALYZER_VERSION
                    and cached.get("source_fingerprint") == fingerprint
                ):
                    return cached
            except (OSError, json.JSONDecodeError):
                pass

        manifest = self._read_manifest(run_dir)
        manifest_by_name = {
            str(item.get("name")): item
            for item in manifest
            if isinstance(item, dict) and item.get("name")
        }
        raw_modules = summary.get("modules", [])
        items: list[dict[str, object]] = []
        if isinstance(raw_modules, list):
            for raw in raw_modules:
                if not isinstance(raw, dict):
                    continue
                name = str(raw.get("name", "unknown"))
                source = {**raw, **manifest_by_name.get(name, {})}
                items.append(
                    self._analyze_item(
                        str(summary.get("target_type", "")),
                        str(summary.get("security_device", "")),
                        run_dir,
                        source,
                        manifest,
                    )
                )
        cleanup_succeeded = summary.get("cleanup_succeeded")
        if cleanup_succeeded is not True and not any(
            item["name"] == "remote_cleanup" for item in items
        ):
            items.append(
                self._failure_item(
                    "remote_cleanup",
                    (
                        "远端临时目录清理失败"
                        if cleanup_succeeded is False
                        else "未记录远端临时目录清理结果"
                    ),
                    None,
                    "cleanup_failed",
                    evidence="",
                )
            )
        if summary.get("error") and not any(
            item["name"] == "collection_pipeline" for item in items
        ):
            pipeline_error = str(summary["error"])
            items.append(
                self._failure_item(
                    "collection_pipeline",
                    pipeline_error,
                    None,
                    self._pipeline_reason_code(pipeline_error.casefold()),
                    evidence="",
                )
            )

        counts = {
            status: sum(1 for item in items if item["status"] == status)
            for status in ("success", "failed", "not_applicable", "skipped")
        }
        applicable_successes = counts["success"]
        applicable_failures = counts["failed"]
        pipeline_failed = any(
            item["name"] == "collection_pipeline"
            and item["status"] == "failed"
            for item in items
        )
        if pipeline_failed:
            assessment_status = "failed"
        elif applicable_successes and not applicable_failures:
            assessment_status = "success"
        elif applicable_successes:
            assessment_status = "partial"
        else:
            assessment_status = "failed"

        report: dict[str, object] = {
            "schema_version": 1,
            "analyzer_version": ANALYZER_VERSION,
            "source_fingerprint": fingerprint,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "run_id": run_id,
            "target": {
                "target_type": summary.get("target_type"),
                "target_ip": summary.get("target_ip"),
                "port": summary.get("port"),
                "username": summary.get("username"),
                "security_device": summary.get("security_device"),
                "custom_device_name": summary.get("custom_device_name"),
                "rule_file_type": summary.get("rule_file_type"),
                "deployment_mode": summary.get("deployment_mode"),
            },
            "started_at": summary.get("started_at"),
            "finished_at": summary.get("finished_at"),
            "collection_status": summary.get("status", "failed"),
            "assessment_status": assessment_status,
            "counts": counts,
            "cleanup_succeeded": summary.get("cleanup_succeeded"),
            "error": redact_text(str(summary.get("error") or "")),
            "items": sorted(
                items,
                key=lambda item: (
                    {"failed": 0, "not_applicable": 1, "skipped": 2, "success": 3}[
                        str(item["status"])
                    ],
                    str(item["name"]),
                ),
            ),
        }
        temporary_report = report_path.with_name(
            f".{REPORT_NAME}.{uuid.uuid4().hex}.tmp"
        )
        try:
            temporary_report.write_text(
                json.dumps(report, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            temporary_report.replace(report_path)
        except OSError:
            pass
        finally:
            try:
                temporary_report.unlink(missing_ok=True)
            except OSError:
                pass
        return report

    def _analyze_item(
        self,
        target_type: str,
        security_device: str,
        run_dir: Path,
        source: dict[str, Any],
        manifest: list[dict[str, Any]],
    ) -> dict[str, object]:
        name = str(source.get("name", "unknown"))
        return_code = source.get("return_code")
        message = str(source.get("message") or "")
        evidence_path = self._evidence_path(target_type, name, source)
        evidence = self._read_evidence(run_dir, evidence_path)
        combined = f"{message}\n{evidence}".casefold()

        if bool(source.get("success")):
            return {
                "name": name,
                "status": "success",
                "applicable": True,
                "reason_code": "collected",
                "reason": "策略数据已成功采集。",
                "return_code": return_code,
                "evidence_excerpt": evidence,
                "evidence_file": evidence_path,
                "recommendations": [],
            }
        if bool(source.get("skipped")):
            return {
                "name": name,
                "status": "skipped",
                "applicable": False,
                "reason_code": "skipped",
                "reason": "该模块未在本次采集范围内。",
                "return_code": return_code,
                "evidence_excerpt": self._combined_evidence(message, evidence),
                "evidence_file": evidence_path,
                "recommendations": [],
            }
        if name == "remote_cleanup":
            return self._failure_item(
                name,
                message,
                return_code,
                "cleanup_failed",
                evidence=evidence,
                evidence_file=evidence_path,
            )
        if any(marker in combined for marker in PERMISSION_MARKERS):
            return self._failure_item(
                name,
                message,
                return_code,
                "permission_denied",
                evidence=evidence,
                evidence_file=evidence_path,
            )
        if target_type == "windows" and name in WINDOWS_CONDITIONAL_MODULES:
            if any(marker in combined for marker in NOT_DOMAIN_MARKERS):
                return self._not_applicable_item(
                    name,
                    message or "目标未加入域，域相关策略不适用。",
                    return_code,
                    "not_domain_joined",
                    evidence,
                    evidence_path,
                )
            if any(marker in combined for marker in ABSENT_MARKERS):
                return self._not_applicable_item(
                    name,
                    message or "目标未安装或未启用对应功能。",
                    return_code,
                    "feature_absent",
                    evidence,
                    evidence_path,
                )
        if target_type == "linux" and name not in LINUX_BASELINE_MODULES:
            if any(marker in combined for marker in ABSENT_MARKERS):
                return self._not_applicable_item(
                    name,
                    message or "目标未安装对应软件或功能。",
                    return_code,
                    "feature_absent",
                    evidence,
                    evidence_path,
                )
        if target_type == "security":
            security_item = self._analyze_security_failure(
                security_device,
                name,
                message,
                return_code,
                evidence,
                evidence_path,
                source,
                manifest,
            )
            if security_item is not None:
                return security_item
        return self._failure_item(
            name,
            message,
            return_code,
            self._generic_reason_code(combined),
            evidence=evidence,
            evidence_file=evidence_path,
        )

    def _analyze_security_failure(
        self,
        security_device: str,
        name: str,
        message: str,
        return_code: Any,
        evidence: str,
        evidence_path: str | None,
        source: dict[str, Any],
        manifest: list[dict[str, Any]],
    ) -> dict[str, object] | None:
        combined = f"{message}\n{evidence}".casefold()
        if "匹配到多个" in combined:
            code = "container_ambiguous"
        elif (
            "未找到匹配的waf容器" in combined
            or "未找到指定的安全设备容器" in combined
            or "no such container" in combined
        ):
            code = "container_not_found"
        elif (
            str(source.get("path_mode") or "")
            or ":path:" in name.casefold()
            or "路径" in combined
        ) and (
            any(marker in combined for marker in ABSENT_MARKERS)
            or "失败" in combined
        ):
            path_mode = str(source.get("path_mode") or "")
            has_rule_success = any(
                bool(item.get("success"))
                and str(item.get("name", "")).endswith(":rules")
                for item in manifest
            )
            is_default_candidate = path_mode == "default"
            if not path_mode and security_device:
                try:
                    defaults = default_registry().resolve(security_device).paths
                    is_default_candidate = any(path in message for path in defaults)
                except ValueError:
                    is_default_candidate = False
            is_docker = False
            if security_device:
                try:
                    is_docker = default_registry().resolve(security_device).docker
                except ValueError:
                    pass
            if is_default_candidate and has_rule_success and not is_docker:
                return self._not_applicable_item(
                    name,
                    message,
                    return_code,
                    "path_missing",
                    evidence,
                    evidence_path,
                )
            code = "path_missing"
        else:
            return None
        return self._failure_item(
            name,
            message,
            return_code,
            code,
            evidence=evidence,
            evidence_file=evidence_path,
        )

    def _failure_item(
        self,
        name: str,
        message: Any,
        return_code: Any,
        reason_code: str,
        *,
        evidence: str,
        evidence_file: str | None = None,
    ) -> dict[str, object]:
        reason = REASON_EXPLANATIONS.get(
            reason_code,
            REASON_EXPLANATIONS["unknown_failure"],
        )
        return {
            "name": name,
            "status": "failed",
            "applicable": True,
            "reason_code": reason_code,
            "reason": reason,
            "return_code": return_code,
            "evidence_excerpt": self._combined_evidence(message, evidence),
            "evidence_file": evidence_file,
            "recommendations": RECOMMENDATIONS.get(
                reason_code,
                RECOMMENDATIONS["unknown_failure"],
            ),
        }

    def _not_applicable_item(
        self,
        name: str,
        message: str,
        return_code: Any,
        reason_code: str,
        evidence: str,
        evidence_file: str | None,
    ) -> dict[str, object]:
        return {
            "name": name,
            "status": "not_applicable",
            "applicable": False,
            "reason_code": reason_code,
            "reason": REASON_EXPLANATIONS.get(
                reason_code,
                REASON_EXPLANATIONS["unknown_failure"],
            ),
            "return_code": return_code,
            "evidence_excerpt": self._combined_evidence(message, evidence),
            "evidence_file": evidence_file,
            "recommendations": RECOMMENDATIONS.get(reason_code, []),
        }

    def _generic_reason_code(self, combined: str) -> str:
        if "compress-archive" in combined or "打包失败" in combined:
            return "archive_failed"
        if any(marker in combined for marker in ABSENT_MARKERS):
            return "dependency_missing"
        if "非零状态" in combined or "return_code" in combined:
            return "command_failed"
        if ("执行" in combined or "命令" in combined) and "失败" in combined:
            return "command_failed"
        return "unknown_failure"

    def _pipeline_reason_code(self, combined: str) -> str:
        if any(
            marker in combined
            for marker in (
                "compress-archive",
                "打包",
                "archive",
                "zip",
            )
        ):
            return "archive_failed"
        if any(
            marker in combined
            for marker in (
                "上传",
                "下载",
                "传输",
                "连接",
                "认证",
                "ssh",
                "winrm",
                "timeout",
                "timed out",
                "command line is too long",
            )
        ):
            return "transport_failed"
        return self._generic_reason_code(combined)

    def _evidence_path(
        self,
        target_type: str,
        name: str,
        source: dict[str, Any],
    ) -> str | None:
        output_file = source.get("output_file")
        if isinstance(output_file, str) and output_file.strip():
            return "data/" + output_file.replace("\\", "/").lstrip("/")
        output_dir = source.get("output_dir")
        if isinstance(output_dir, str) and output_dir.strip():
            return "data/" + output_dir.replace("\\", "/").lstrip("/")
        if target_type == "linux" and name in LINUX_OUTPUT_DIRS:
            return "data/" + LINUX_OUTPUT_DIRS[name]
        return None

    def _read_evidence(self, run_dir: Path, relative: str | None) -> str:
        if not relative:
            return ""
        root = run_dir.resolve()
        evidence_root = (run_dir / "data").resolve()
        candidate = (run_dir / relative).resolve()
        try:
            candidate.relative_to(root)
            if relative != "execution.log":
                candidate.relative_to(evidence_root)
        except ValueError:
            return ""
        if candidate.is_dir():
            safe_files: set[Path] = set()
            for path in candidate.rglob("*"):
                try:
                    resolved_path = path.resolve(strict=True)
                    resolved_path.relative_to(evidence_root)
                except (OSError, ValueError):
                    continue
                if (
                    resolved_path.is_file()
                    and resolved_path.suffix.lower() in {".txt", ".log", ".json"}
                ):
                    safe_files.add(resolved_path)
            files = sorted(safe_files)
        elif candidate.is_file() and candidate.suffix.lower() in {
            ".txt",
            ".log",
            ".json",
        }:
            files = [candidate]
        else:
            return ""
        excerpts: list[str] = []
        remaining = MAX_EVIDENCE_CHARS
        for path in files[:5]:
            try:
                if path.stat().st_size > MAX_EVIDENCE_BYTES:
                    continue
                text = path.read_text(encoding="utf-8-sig", errors="replace")
            except OSError:
                continue
            interesting = [
                line.strip()
                for line in text.splitlines()
                if line.strip()
                and (
                    "[ERROR]" in line
                    or "[WARN]" in line
                    or "RETURN_CODE=" in line
                    or any(marker in line.casefold() for marker in PERMISSION_MARKERS)
                    or any(marker in line.casefold() for marker in ABSENT_MARKERS)
                )
            ]
            selected = "\n".join(interesting[:8]) or text[:remaining]
            if selected:
                excerpts.append(selected[:remaining])
                remaining -= len(excerpts[-1])
            if remaining <= 0:
                break
        return redact_text("\n".join(excerpts))[:MAX_EVIDENCE_CHARS]

    def _combined_evidence(self, message: Any, evidence: str) -> str:
        parts: list[str] = []
        redacted_message = redact_text(str(message or "")).strip()
        if redacted_message:
            parts.append(redacted_message)
        if evidence and evidence not in parts:
            parts.append(evidence)
        return "\n".join(parts)[:MAX_EVIDENCE_CHARS]

    def _read_manifest(self, run_dir: Path) -> list[dict[str, Any]]:
        path = run_dir / "data" / "collection_manifest.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            return []
        if not isinstance(data, list):
            return []
        return [item for item in data if isinstance(item, dict)]

    def _source_fingerprint(self, run_dir: Path) -> str:
        root = run_dir.resolve()
        records: list[str] = []
        for path in sorted(run_dir.rglob("*")):
            try:
                resolved = path.resolve()
                resolved.relative_to(root)
            except (OSError, ValueError):
                continue
            if (
                not resolved.is_file()
                or resolved.name == REPORT_NAME
                or resolved.suffix.lower() not in {".json", ".txt", ".log"}
            ):
                continue
            stat = resolved.stat()
            content_hash = hashlib.sha256()
            try:
                with resolved.open("rb") as stream:
                    for chunk in iter(lambda: stream.read(64 * 1024), b""):
                        content_hash.update(chunk)
            except OSError:
                continue
            records.append(
                f"{resolved.relative_to(root).as_posix()}:"
                f"{stat.st_size}:{stat.st_mtime_ns}:{content_hash.hexdigest()}"
            )
        return hashlib.sha256("\n".join(records).encode("utf-8")).hexdigest()
