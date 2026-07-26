from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable


_SENSITIVE_ASSIGNMENT = re.compile(
    r"""(?ix)
    (?P<key_quote>["']?)
    (?P<key>[a-z0-9_-]*(?:password|passwd|token|secret|authorization)[a-z0-9_-]*)
    (?P=key_quote)
    (?P<separator>\s*[:=]\s*)
    (?P<value>
        "(?:\\.|[^"\\\r\n])*"
        |
        '(?:\\.|[^'\\\r\n])*'
        |
        [^\r\n,;}\]]+
    )
    """
)
_AUTHORIZATION = re.compile(r"(?i)(Authorization\s*:)\s*[^\r\n]+")
_SENSITIVE_KEY = re.compile(
    r"(?i)(password|passwd|token|secret|authorization)"
)


def _redact_json_values(value):
    if isinstance(value, dict):
        return {
            key: (
                "***"
                if _SENSITIVE_KEY.search(str(key))
                else _redact_json_values(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_json_values(item) for item in value]
    return value


def _redact_assignment(match: re.Match[str]) -> str:
    value = match.group("value")
    if len(value) >= 2 and value[0] in {'"', "'"} and value[-1] == value[0]:
        masked_value = f"{value[0]}***{value[-1]}"
    else:
        masked_value = "***"
    return (
        f"{match.group('key_quote')}{match.group('key')}"
        f"{match.group('key_quote')}{match.group('separator')}{masked_value}"
    )


def redact_text(text: str, *, secrets: Iterable[str] = ()) -> str:
    redacted = text
    for secret in sorted((value for value in secrets if value), key=len, reverse=True):
        redacted = redacted.replace(secret, "***")
    if redacted.lstrip().startswith(("{", "[")):
        try:
            structured = json.loads(redacted)
        except (json.JSONDecodeError, TypeError):
            pass
        else:
            return json.dumps(
                _redact_json_values(structured),
                ensure_ascii=False,
            )
    redacted = _SENSITIVE_ASSIGNMENT.sub(_redact_assignment, redacted)
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
