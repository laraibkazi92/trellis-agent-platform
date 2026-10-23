# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Keep agent tokens out of logs.

The hub's FastMCP client is a process-wide singleton shared by concurrent runs,
so the run's token rides the tool arguments as ``__agent_token`` (a header would
be shared by every caller). FastMCP logs a failed argument-validation record with
the offending input, and pydantic's "missing" errors echo the whole dict — which
would write a live credential to a WARNING line. This filter redacts any token
shape before a handler sees the record.
"""

import logging
import re

_TOKEN_RE = re.compile(r"t1\.[A-Za-z0-9_\-=.]+")


def _redact(value):
    if isinstance(value, str):
        return _TOKEN_RE.sub("t1.<redacted>", value)
    if isinstance(value, tuple):
        return tuple(_redact(item) for item in value)
    if isinstance(value, dict):
        return {key: _redact(item) for key, item in value.items()}
    return value


class RedactAgentTokens(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = _redact(record.msg)
            record.args = _redact(record.args)
        except Exception:  # never let logging break a request
            pass
        return True


_NOISY_LOGGERS = ("fastmcp", "mcp", "mcp.server", "mcp.client", "uvicorn.error")


def install() -> None:
    """Attach the filter to the loggers that can echo call arguments."""
    for name in _NOISY_LOGGERS:
        logger = logging.getLogger(name)
        if not any(isinstance(f, RedactAgentTokens) for f in logger.filters):
            logger.addFilter(RedactAgentTokens())
