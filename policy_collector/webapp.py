from __future__ import annotations

import re
import threading
import uuid
from collections.abc import Awaitable, Callable
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, SecretStr
from starlette.responses import Response

from .adapters import (
    CUSTOM_SECURITY_DEVICE_KEY,
    AdapterRegistry,
    default_registry,
    normalize_rule_file_type,
)
from .analysis import ResultAnalysisService, RunNotFoundError
from .factory import create_collector
from .models import Credential, TargetConfig, TargetType
from .orchestrator import CollectionOrchestrator, CollectorFactory
from .security import redact_text


PROJECT_ROOT = Path(__file__).resolve().parents[1]
WEB_ROOT = PROJECT_ROOT / "webui"
RUN_ID_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class JobRequest(BaseModel):
    action: Literal["check", "collect"]
    target_type: Literal["linux", "windows", "security"]
    host: str = Field(min_length=1, max_length=255)
    port: int | None = Field(default=None, ge=1, le=65535)
    username: str = Field(min_length=1, max_length=255)
    password: SecretStr
    use_sudo: bool = False
    sudo_password: SecretStr | None = None
    security_device: str | None = None
    custom_paths: list[str] = Field(default_factory=list, max_length=30)
    container_name: str | None = None
    custom_device_name: str | None = Field(default=None, max_length=80)
    rule_file_type: str | None = Field(default=None, max_length=40)
    deployment_mode: Literal["host", "docker"] | None = None
    winrm_https: bool = False
    winrm_insecure: bool = False
    trust_new_host_key: bool = False


@dataclass
class WebJob:
    id: str
    action: str
    target: dict[str, object]
    state: str = "queued"
    status: str = "pending"
    message: str = "任务已进入队列"
    created_at: str = field(default_factory=_now_iso)
    updated_at: str = field(default_factory=_now_iso)
    result: dict[str, object] | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "action": self.action,
            "target": dict(self.target),
            "state": self.state,
            "status": self.status,
            "message": self.message,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "result": self.result,
        }


class JobStore:
    def __init__(self) -> None:
        self._jobs: dict[str, WebJob] = {}
        self._lock = threading.RLock()

    def create(self, action: str, target: TargetConfig) -> WebJob:
        job = WebJob(
            id=uuid.uuid4().hex,
            action=action,
            target=target.public_description(),
        )
        with self._lock:
            self._jobs[job.id] = job
        return job

    def update(self, job_id: str, **changes: Any) -> WebJob:
        with self._lock:
            job = self._jobs[job_id]
            for name, value in changes.items():
                setattr(job, name, value)
            job.updated_at = _now_iso()
            return job

    def get(self, job_id: str) -> WebJob | None:
        with self._lock:
            return self._jobs.get(job_id)

    def latest(self, limit: int = 20) -> list[WebJob]:
        with self._lock:
            return list(reversed(tuple(self._jobs.values())))[:limit]


class JobService:
    def __init__(
        self,
        *,
        collector_factory: CollectorFactory | None = None,
        output_root: Path | None = None,
        registry: AdapterRegistry | None = None,
        max_workers: int = 1,
    ) -> None:
        self.registry = registry or default_registry()
        self.collector_factory = collector_factory or create_collector
        self.output_root = Path(output_root or PROJECT_ROOT / "outputs")
        self.analysis = ResultAnalysisService(self.output_root)
        self.store = JobStore()
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="policy-web",
        )

    def _target_from_request(self, request: JobRequest) -> TargetConfig:
        target_type = TargetType(request.target_type)
        if request.winrm_insecure and not request.winrm_https:
            raise ValueError("忽略证书校验只能与HTTPS WinRM同时启用")
        custom_paths = tuple(
            path.strip() for path in request.custom_paths if path.strip()
        )
        if target_type is TargetType.SECURITY:
            if not request.security_device:
                raise ValueError("安全设备目标必须选择设备类型")
            if request.security_device == CUSTOM_SECURITY_DEVICE_KEY:
                security_device = CUSTOM_SECURITY_DEVICE_KEY
                custom_device_name = (request.custom_device_name or "").strip()
                if not custom_device_name or any(
                    ord(character) < 32 for character in custom_device_name
                ):
                    raise ValueError("自定义安全设备必须填写有效的设备名称")
                rule_file_type = normalize_rule_file_type(
                    request.rule_file_type or ""
                )
                deployment_mode = request.deployment_mode
            else:
                security_device = self.registry.resolve(request.security_device).key
                custom_device_name = None
                rule_file_type = None
                deployment_mode = None
        else:
            security_device = None
            custom_device_name = None
            rule_file_type = None
            deployment_mode = None
        if target_type is not TargetType.SECURITY and custom_paths:
            raise ValueError("只有安全设备支持自定义规则路径")
        if request.port is not None:
            port = request.port
        elif target_type is TargetType.WINDOWS:
            port = 5986 if request.winrm_https else 5985
        else:
            port = 22
        return TargetConfig(
            target_type=target_type,
            host=request.host.strip(),
            port=port,
            username=request.username.strip(),
            use_sudo=request.use_sudo,
            security_device=security_device,
            custom_paths=custom_paths,
            container_name=(
                request.container_name.strip()
                if request.container_name and request.container_name.strip()
                else None
            ),
            custom_device_name=custom_device_name,
            rule_file_type=rule_file_type,
            deployment_mode=deployment_mode,
            winrm_https=request.winrm_https,
            winrm_insecure=request.winrm_insecure,
            trust_new_host_key=request.trust_new_host_key,
        )

    def submit(self, request: JobRequest) -> WebJob:
        target = self._target_from_request(request)
        password = request.password.get_secret_value()
        sudo_password = (
            request.sudo_password.get_secret_value()
            if request.sudo_password is not None
            else (password if target.use_sudo else None)
        )
        credential = Credential(
            password=password,
            sudo_password=sudo_password,
        )
        job = self.store.create(request.action, target)
        try:
            self._executor.submit(
                self._execute,
                job.id,
                request.action,
                target,
                credential,
            )
        except Exception:
            self.store.update(
                job.id,
                state="completed",
                status="failed",
                message="任务调度失败",
            )
            raise
        return job

    def _execute(
        self,
        job_id: str,
        action: str,
        target: TargetConfig,
        credential: Credential,
    ) -> None:
        self.store.update(
            job_id,
            state="running",
            status="running",
            message="正在检查连接与目标能力",
        )
        secrets = (credential.password, credential.sudo_password or "")
        try:
            orchestrator = CollectionOrchestrator(self.collector_factory)
            if action == "check":
                details = orchestrator.check(target, credential)
                self.store.update(
                    job_id,
                    state="completed",
                    status="success",
                    message="连接与能力检查通过",
                    result=details,
                )
                return
            self.store.update(
                job_id,
                message="正在远程采集并下载策略结果",
            )
            report = orchestrator.collect(
                target,
                credential,
                output_root=self.output_root,
            )
            result = report.to_dict()
            result["run_dir"] = str(report.run_dir)
            self.store.update(
                job_id,
                state="completed",
                status=report.status.value,
                message={
                    "success": "采集成功，远端临时目录已清理",
                    "partial": "采集部分完成，请查看失败项",
                    "failed": "采集失败，请查看错误信息",
                }[report.status.value],
                result=result,
            )
        except Exception as exc:
            self.store.update(
                job_id,
                state="completed",
                status="failed",
                message=redact_text(str(exc), secrets=secrets),
            )

    def recent_runs(self, limit: int = 20) -> list[dict[str, object]]:
        return self.analysis.list_runs(limit=limit)

    def analyze_run(self, run_id: str) -> dict[str, object]:
        if RUN_ID_PATTERN.fullmatch(run_id) is None:
            raise RunNotFoundError(run_id)
        return self.analysis.analyze(run_id)

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)


def create_app(service: JobService | None = None) -> FastAPI:
    active_service = service or JobService()

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        active_service.shutdown()

    app = FastAPI(
        title="统一安全策略采集",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.job_service = active_service

    @app.middleware("http")
    async def security_headers(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; object-src 'none'; frame-ancestors 'none'; "
            "base-uri 'self'; form-action 'self'"
        )
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.get("/")
    def home() -> FileResponse:
        return FileResponse(WEB_ROOT / "index.html")

    @app.get("/runs/{run_id}")
    def analysis_page(run_id: str) -> FileResponse:
        return FileResponse(WEB_ROOT / "analysis.html")

    @app.get("/api/meta")
    def meta() -> dict[str, object]:
        return {
            "target_types": [
                {"key": "linux", "name": "Linux", "default_port": 22},
                {"key": "windows", "name": "Windows", "default_port": 5985},
                {"key": "security", "name": "安全设备", "default_port": 22},
            ],
            "security_devices": [
                *[
                    {
                        "key": adapter.key,
                        "name": adapter.display_name,
                        "docker": adapter.docker,
                        "paths": list(adapter.paths),
                    }
                    for adapter in active_service.registry.all()
                ],
                {
                    "key": CUSTOM_SECURITY_DEVICE_KEY,
                    "name": "自定义安全设备",
                    "docker": False,
                    "paths": [],
                    "custom": True,
                },
            ],
        }

    @app.post("/api/jobs", status_code=202)
    def create_job(request: JobRequest) -> dict[str, object]:
        try:
            job = active_service.submit(request)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return job.to_dict()

    @app.get("/api/jobs")
    def list_jobs() -> list[dict[str, object]]:
        return [job.to_dict() for job in active_service.store.latest()]

    @app.get("/api/jobs/{job_id}")
    def get_job(job_id: str) -> dict[str, object]:
        job = active_service.store.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="任务不存在")
        return job.to_dict()

    @app.get("/api/runs")
    def recent_runs() -> list[dict[str, object]]:
        return active_service.recent_runs()

    @app.get("/api/runs/{run_id}/report")
    def download_report(run_id: str) -> JSONResponse:
        try:
            report = active_service.analyze_run(run_id)
        except RunNotFoundError as exc:
            raise HTTPException(status_code=404, detail="采集记录不存在") from exc
        return JSONResponse(
            report,
            headers={
                "Content-Disposition": 'attachment; filename="analysis_report.json"'
            },
        )

    @app.get("/api/runs/{run_id}")
    def run_detail(run_id: str) -> dict[str, object]:
        try:
            return active_service.analyze_run(run_id)
        except RunNotFoundError as exc:
            raise HTTPException(status_code=404, detail="采集记录不存在") from exc

    app.mount("/assets", StaticFiles(directory=WEB_ROOT), name="assets")
    return app


app = create_app()
