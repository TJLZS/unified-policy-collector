from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from .models import (
    CollectionReport,
    CollectionStatus,
    Credential,
    ModuleResult,
    TargetConfig,
)
from .results import ResultManager
from .security import configure_file_logger, redact_text


class Collector(Protocol):
    def check(self) -> dict[str, object]: ...

    def collect(self, output_dir: Path) -> list[ModuleResult]: ...

    def cleanup(self) -> bool: ...


CollectorFactory = Callable[[TargetConfig, Credential], Collector]


def _status_for(modules: list[ModuleResult]) -> CollectionStatus:
    if modules and all(item.success for item in modules):
        return CollectionStatus.SUCCESS
    if any(item.success for item in modules):
        return CollectionStatus.PARTIAL
    return CollectionStatus.FAILED


class CollectionOrchestrator:
    """隐藏生命周期、状态归并和结果持久化的深模块。"""

    def __init__(
        self,
        collector_factory: CollectorFactory,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.collector_factory = collector_factory
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def check(
        self,
        target: TargetConfig,
        credential: Credential,
    ) -> dict[str, object]:
        collector = self.collector_factory(target, credential)
        try:
            return collector.check()
        finally:
            collector.cleanup()

    def collect(
        self,
        target: TargetConfig,
        credential: Credential,
        *,
        output_root: Path,
    ) -> CollectionReport:
        started_at = self.clock()
        manager = ResultManager(output_root)
        run_dir = manager.create_run_dir(target, started_at)
        logger = configure_file_logger(
            run_dir / "execution.log",
            secrets=(credential.password, credential.sudo_password or ""),
        )
        logger.info(
            "开始采集 target_type=%s target=%s",
            target.target_type.value,
            target.host,
        )
        collector = self.collector_factory(target, credential)
        modules: list[ModuleResult] = []
        error: str | None = None
        check_details: dict[str, object] = {}
        cleanup_succeeded: bool | None = None
        try:
            check_details = collector.check()
            modules = collector.collect(run_dir / "data")
            modules = [
                replace(
                    item,
                    message=redact_text(
                        item.message,
                        secrets=(
                            credential.password,
                            credential.sudo_password or "",
                        ),
                    ),
                )
                for item in modules
            ]
            status = _status_for(modules)
        except Exception as exc:
            status = CollectionStatus.FAILED
            error = redact_text(
                str(exc),
                secrets=(credential.password, credential.sudo_password or ""),
            )
            logger.error("采集失败: %s", exc)
        finally:
            try:
                cleanup_succeeded = collector.cleanup()
            except Exception:
                cleanup_succeeded = False
            logger.info("远端清理结果: %s", cleanup_succeeded)

        report = CollectionReport(
            status=status,
            target=target,
            started_at=started_at,
            finished_at=self.clock(),
            run_dir=run_dir,
            modules=modules,
            error=error,
            cleanup_succeeded=cleanup_succeeded,
            check_details=check_details,
        )
        manager.write_summary(report)
        logger.info("采集完成 status=%s", report.status.value)
        for handler in tuple(logger.handlers):
            handler.close()
            logger.removeHandler(handler)
        return report
