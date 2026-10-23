# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Client for the runner control API.

The runner listens on a Unix socket (``RUNNER_SOCKET``) and speaks plain HTTP;
``RUNNER_URL`` is a compatibility escape hatch for a TCP deployment. One client
per call is deliberate: the socket round trip is cheaper than keeping a shared
httpx client bound to a particular event loop.
"""

import os
from typing import AsyncIterator, Optional

import httpx

from core.execution.contract import (
    ExecRequest,
    ExecResult,
    HealthInfo,
    RunnerError,
    SessionCreateRequest,
    SessionInfo,
)

DEFAULT_SOCKET = "/run/trellis/runner.sock"
# Structured states the hub maps onto its existing result shapes.
RETRYABLE_CODES = frozenset({"capacity_exhausted", "daemon_unavailable"})


class RunnerUnavailable(RuntimeError):
    """The runner could not be reached at all (socket/connection failure)."""

    def __init__(self, message: str) -> None:
        self.code = "runner_unavailable"
        self.message = message
        super().__init__(message)


class RunnerCallError(RuntimeError):
    """The runner refused or failed a structured request."""

    def __init__(self, code: str, message: str, status: int = 0) -> None:
        self.code = code
        self.message = message
        self.status = status
        super().__init__(f"{code}: {message}")

    @property
    def retryable(self) -> bool:
        return self.code in RETRYABLE_CODES


def socket_path() -> str:
    return os.getenv("RUNNER_SOCKET") or DEFAULT_SOCKET


def runner_url() -> Optional[str]:
    value = (os.getenv("RUNNER_URL") or "").strip()
    return value.rstrip("/") or None


def _error_from_response(response: httpx.Response) -> RunnerCallError:
    try:
        payload = response.json()
    except ValueError:
        payload = {}
    error = payload.get("detail") if isinstance(payload, dict) else None
    if not isinstance(error, dict):
        error = payload if isinstance(payload, dict) else {}
    code = str(error.get("code") or _code_for_status(response.status_code))
    message = str(error.get("message") or response.text[:300] or "runner error")
    return RunnerCallError(code, message, response.status_code)


def _code_for_status(status: int) -> str:
    return {
        400: "invalid_request",
        403: "access_denied",
        404: "unknown_target",
        409: "manifest_stale",
        429: "capacity_exhausted",
        503: "runtime_missing",
        504: "timeout",
    }.get(status, "internal")


class RunnerClient:
    def __init__(
        self,
        *,
        socket: Optional[str] = None,
        url: Optional[str] = None,
        token: Optional[str] = None,
        transport: Optional[httpx.AsyncBaseTransport] = None,
        timeout: float = 3600.0,
    ) -> None:
        self._socket = socket or socket_path()
        self._url = url or runner_url()
        self._token = token if token is not None else os.getenv("RUNNER_TOKEN", "")
        self._transport = transport
        self._client: Optional[httpx.AsyncClient] = None
        self._timeout = timeout

    def _headers(self) -> dict[str, str]:
        headers = {"content-type": "application/json"}
        if self._token:
            headers["authorization"] = f"Bearer {self._token}"
        return headers

    def _make_client(self) -> httpx.AsyncClient:
        if self._transport is not None:
            return httpx.AsyncClient(
                transport=self._transport,
                base_url=self._url or "http://runner",
                timeout=self._timeout,
            )
        if self._url:
            return httpx.AsyncClient(base_url=self._url, timeout=self._timeout)
        transport = httpx.AsyncHTTPTransport(uds=self._socket)
        return httpx.AsyncClient(
            transport=transport, base_url="http://runner", timeout=self._timeout
        )

    async def __aenter__(self) -> "RunnerClient":
        self._client = self._make_client()
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.close()

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _client_or_make(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = self._make_client()
        return self._client

    async def _request(
        self, method: str, path: str, **kwargs
    ) -> httpx.Response:
        client = await self._client_or_make()
        headers = {**self._headers(), **(kwargs.pop("headers", None) or {})}
        try:
            response = await client.request(method, path, headers=headers, **kwargs)
        except httpx.HTTPError as exc:
            raise RunnerUnavailable(
                f"runner is unreachable at {self._url or self._socket} "
                f"({type(exc).__name__}: {exc})"
            ) from exc
        if response.status_code >= 400:
            raise _error_from_response(response)
        return response

    # --- one-shot execution -------------------------------------------------

    async def exec(self, request: ExecRequest) -> ExecResult:
        budget = max(1.0, request.deadline_ms / 1000.0)
        client = await self._client_or_make()
        try:
            response = await client.post(
                "/v1/exec",
                json=request.model_dump(exclude_none=True),
                headers=self._headers(),
                timeout=budget + 10.0,
            )
        except httpx.TimeoutException as exc:
            raise RunnerCallError(
                "timeout", f"runner did not answer within {budget + 10:.0f}s"
            ) from exc
        except httpx.HTTPError as exc:
            raise RunnerUnavailable(
                f"runner is unreachable at {self._url or self._socket} "
                f"({type(exc).__name__}: {exc})"
            ) from exc
        if response.status_code >= 400:
            raise _error_from_response(response)
        return ExecResult.model_validate(response.json())

    # --- sessions (phase 2) -------------------------------------------------

    async def open_session(self, request: SessionCreateRequest) -> SessionInfo:
        response = await self._request(
            "POST", "/v1/sessions", json=request.model_dump(exclude_none=True)
        )
        return SessionInfo.model_validate(response.json())

    async def session_stdin(self, session_id: str, data: bytes) -> None:
        await self._request(
            "POST",
            f"/v1/sessions/{session_id}/stdin",
            content=data,
            headers={"content-type": "application/octet-stream"},
        )

    async def close_session_stdin(self, session_id: str) -> None:
        await self._request("POST", f"/v1/sessions/{session_id}/close")

    async def get_session(self, session_id: str) -> SessionInfo:
        response = await self._request("GET", f"/v1/sessions/{session_id}")
        return SessionInfo.model_validate(response.json())

    async def delete_session(self, session_id: str) -> None:
        await self._request("DELETE", f"/v1/sessions/{session_id}")

    async def session_stdout(self, session_id: str) -> AsyncIterator[bytes]:
        """Yield raw framed bytes from a session's stdout stream."""
        client = await self._client_or_make()
        try:
            async with client.stream(
                "GET",
                f"/v1/sessions/{session_id}/stdout",
                headers=self._headers(),
                timeout=None,
            ) as response:
                if response.status_code >= 400:
                    await response.aread()
                    raise _error_from_response(response)
                async for chunk in response.aiter_raw():
                    if chunk:
                        yield chunk
        except httpx.HTTPError as exc:
            raise RunnerUnavailable(
                f"runner stdout stream failed ({type(exc).__name__}: {exc})"
            ) from exc

    # --- health -------------------------------------------------------------

    async def healthz(self) -> HealthInfo:
        response = await self._request("GET", "/v1/healthz")
        return HealthInfo.model_validate(response.json())

    async def preflight(self) -> HealthInfo:
        response = await self._request("POST", "/v1/preflight")
        return HealthInfo.model_validate(response.json())
