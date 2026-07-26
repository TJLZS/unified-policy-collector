from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path

from .models import CollectionReport, TargetConfig


_SAFE_SEGMENT = re.compile(r"[^A-Za-z0-9._-]+")


def safe_segment(value: str) -> str:
    cleaned = _SAFE_SEGMENT.sub("_", value).strip("._")
    if not cleaned or cleaned in {".", ".."}:
        raise ValueError("无法生成安全的结果目录名称")
    return cleaned


class ResultManager:
    def __init__(self, output_root: Path) -> None:
        self.output_root = Path(output_root)

    def create_run_dir(self, target: TargetConfig, now: datetime) -> Path:
        timestamp = now.strftime("%Y%m%d_%H%M%S_%f")
        run_dir = (
            self.output_root
            / target.target_type.value
            / safe_segment(target.host)
            / timestamp
        )
        (run_dir / "data").mkdir(parents=True, exist_ok=False)
        return run_dir

    @staticmethod
    def write_summary(report: CollectionReport) -> Path:
        path = report.run_dir / "collection_summary.json"
        path.write_text(
            json.dumps(report.to_dict(), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return path
