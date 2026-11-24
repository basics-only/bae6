import hashlib
import inspect
import re
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Unpack

import httpx
from bae6_sdk_core import Options

from bae6_authz.client import Authz, AuthzAuthError, ExecutionContext

_BEARER = re.compile(r"^Bearer ([\x21-\x7e]{1,4096})$")
_MAX_CACHED_TOKENS = 1000
_REUSE_MARGIN_SECONDS = 30
_MAX_REUSE_SECONDS = 60


@dataclass(frozen=True)
class TenantResource:
    resource_type: str
    resource_id: str


@dataclass(frozen=True)
class ExchangedToken:
    access_token: str
    expires_in: int


@dataclass(frozen=True)
class Verdict:
    allowed: bool
    status: int = 200
    code: str = ""
    message: str = ""
    execution_context: ExecutionContext | None = None


_ALLOW = Verdict(True)


def _deny(status: int, code: str, message: str) -> Verdict:
    return Verdict(False, status, code, message)


class TenantGuard:
    """Only an explicit allow lets a request through; every failure denies.

    `exchange` turns the caller's token into one for the `bae6-authz` audience; an error
    with `status == 400` means the caller's token was refused.
    """

    def __init__(
        self,
        base_url: str,
        application: str,
        exchange: Callable[[str], Awaitable[ExchangedToken]],
        transport: httpx.AsyncBaseTransport | None = None,
        *,
        include_execution_context: bool = False,
        **options: Unpack[Options],
    ) -> None:
        self._exchange = exchange
        self._include_execution_context = include_execution_context
        self._current: ContextVar[str] = ContextVar("bae6_authz_guard_token")
        self._exchanged: OrderedDict[str, tuple[str, float]] = OrderedDict()
        self._authz = Authz(
            base_url,
            self._current.get,
            application,
            transport=transport,
            **options,
        )

    async def aclose(self) -> None:
        await self._authz.aclose()

    async def _authz_token(self, subject_token: str) -> str:
        key = hashlib.sha256(subject_token.encode()).hexdigest()
        hit = self._exchanged.get(key)
        if hit and hit[1] > time.monotonic():
            return hit[0]
        exchanged = await self._exchange(subject_token)
        reuse = min(exchanged.expires_in - _REUSE_MARGIN_SECONDS, _MAX_REUSE_SECONDS)
        self._exchanged.pop(key, None)
        self._exchanged[key] = (exchanged.access_token, time.monotonic() + reuse)
        if len(self._exchanged) > _MAX_CACHED_TOKENS:
            self._exchanged.popitem(last=False)
        return exchanged.access_token

    async def __call__(self, authorization: str | None, resource: TenantResource | None) -> Verdict:
        match = _BEARER.match(authorization or "")
        if not match:
            return _deny(401, "unauthenticated", "A bearer token is required.")
        if resource is None:
            return _deny(403, "forbidden", "No tenant resource maps to this request.")
        try:
            token = await self._authz_token(match.group(1))
        except Exception as err:
            if getattr(err, "status", None) == 400:
                return _deny(401, "unauthenticated", "The bearer token was refused.")
            return _deny(503, "unavailable", "Authorization is unavailable.")
        reset = self._current.set(token)
        try:
            if self._include_execution_context:
                context = await self._authz.tenant_check_with_context(
                    resource_type=resource.resource_type, resource_id=resource.resource_id
                )
                if context is not None:
                    return Verdict(True, execution_context=context)
                return _deny(403, "forbidden", "Not permitted.")
            allowed = await self._authz.tenant_check(
                resource_type=resource.resource_type,
                resource_id=resource.resource_id,
            )
        except AuthzAuthError:
            return _deny(403, "forbidden", "Not permitted.")
        except Exception:
            return _deny(503, "unavailable", "Authorization is unavailable.")
        finally:
            self._current.reset(reset)
        return _ALLOW if allowed else _deny(403, "forbidden", "Not permitted.")


def fastapi_dependency(
    guard: TenantGuard,
    resource_of: Callable[[Any], TenantResource | None | Awaitable[TenantResource | None]],
) -> Callable[..., Awaitable[ExecutionContext | None]]:
    """Use as `Depends(fastapi_dependency(...))`. An error from `resource_of` propagates as a 500."""
    from fastapi import HTTPException, Request

    async def dependency(request: Request) -> ExecutionContext | None:
        resource = resource_of(request)
        if inspect.isawaitable(resource):
            resource = await resource
        verdict = await guard(request.headers.get("authorization"), resource)
        if verdict.allowed:
            return verdict.execution_context
        raise HTTPException(
            verdict.status,
            detail={"code": verdict.code, "message": verdict.message},
            headers={"WWW-Authenticate": "Bearer"} if verdict.status == 401 else None,
        )

    return dependency
