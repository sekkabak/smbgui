"""Structured logging helpers for smbgui."""

from __future__ import annotations

import json
import logging
import sys
import time
from typing import Any


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": time.time(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key in ("host", "action", "source", "path", "job_id", "error"):
            if hasattr(record, key):
                payload[key] = getattr(record, key)
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def setup_logging(level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger("smbgui")
    if logger.handlers:
        return logger
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False
    return logger


def log_event(logger: logging.Logger, msg: str, **fields: Any) -> None:
    logger.info(msg, extra=fields)
