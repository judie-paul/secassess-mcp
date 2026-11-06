"""HTTP client the MCP server uses to reach the FastAPI backend.

The MCP server never reads data files itself; everything goes through here.
Backend and transport failures are converted into BackendError with a clear,
agent-readable message.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

import httpx

import config


class BackendError(Exception):
    def __init__(self, message: str, status_code: Optional[int] = None, code: Optional[str] = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.code = code


def _clean(params: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Drop unset values and render booleans the way FastAPI expects."""
    cleaned = {}
    for key, value in (params or {}).items():
        if value is None:
            continue
        cleaned[key] = str(value).lower() if isinstance(value, bool) else value
    return cleaned


class BackendClient:
    def __init__(
        self,
        base_url: str = config.BACKEND_URL,
        timeout: float = config.BACKEND_TIMEOUT_SECONDS,
        transport: Optional[httpx.AsyncBaseTransport] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.transport = transport

    async def request(self, method: str, path: str, params=None, json=None) -> Any:
        try:
            async with httpx.AsyncClient(
                base_url=self.base_url, timeout=self.timeout, transport=self.transport
            ) as client:
                response = await client.request(method, path, params=_clean(params), json=json)
        except httpx.TimeoutException as exc:
            raise BackendError(f"Backend request timed out after {self.timeout:.0f}s", code="timeout") from exc
        except httpx.HTTPError as exc:
            raise BackendError(
                f"Could not reach the security backend at {self.base_url}: {exc.__class__.__name__}",
                code="backend_unavailable",
            ) from exc

        if response.is_success:
            return response.json()

        code, message = "backend_error", response.text[:300] or response.reason_phrase
        try:
            error = response.json().get("error", {})
            code = error.get("code", code)
            message = error.get("message", message)
        except (ValueError, AttributeError):
            pass
        raise BackendError(message, status_code=response.status_code, code=code)

    async def get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        return await self.request("GET", path, params=params)

    async def post(self, path: str, json: Any = None) -> Any:
        return await self.request("POST", path, json=json)
