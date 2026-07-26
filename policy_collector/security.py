from __future__ import annotations

import logging
import re
from collections.abc import Iterable


_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|token|secret)\s*([:=])\s*[^\s,;]+"
)
_AUTHORIZATION = re.compile(r"(?im)^(Authorization\s*:)\s*.+$")


def redact_text(text: str, *, secrets: Iterable[str] = ()) -> str:
    redacted = text
    for secret in sorted((value for value in secrets if value), key=len, reverse=True):
        redacted = redacted.replace(secret, "***")
    redacted = _SENSITIVE_ASSIGNMENT.sub(
        lambda match: f"{match.group(1)}{match.group(2)}***",
        redacted,
    )
    return _AUTHORIZATION.sub(r"\1 ***", redacted)


class RedactingFilter(logging.Filter):
    def __init__(self, secrets: Iterable[str] = ()) -> None:
        super().__init__()
        self.secrets = tuple(secrets)

    def filter(self, record: logging.LogRecord) -> bool:
        rendered = record.getMessage()
        record.msg = redact_text(rendered, secrets=self.secrets)
        record.args = ()
        return True


def configure_file_logger(path, *, secrets: Iterable[str] = ()) -> logging.Logger:
    logger = logging.getLogger(f"policy_collector.{path}")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.handlers.clear()
    handler = logging.FileHandler(path, encoding="utf-8")
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    )
    handler.addFilter(RedactingFilter(secrets))
    logger.addHandler(handler)
    return logger
