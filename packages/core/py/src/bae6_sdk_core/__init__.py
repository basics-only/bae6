import asyncio
import json
import random
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any, TypedDict
from urllib.parse import urlencode

import httpx

MAX_RESPONSE_BYTES = 64 * 1024 * 1024
MAX_RETRIES = 5
RETRYABLE = {502, 503, 504}

Params = httpx.QueryParams | Mapping[str, str] | None
Credentials = str | Callable[[], str | Awaitable[str]]


@dataclass
class RequestInfo:
    method: str
    url: str
    attempt: int
    headers: dict[str, str]


@dataclass(frozen=True)
class ResponseInfo:
    method: str
    url: str
    attempt: int
    status: int
    headers: httpx.Headers
    duration_ms: float


OnRequest = Callable[[RequestInfo], Awaitable[None] | None]
OnResponse = Callable[[ResponseInfo], Awaitable[None] | None]


class Options(TypedDict, total=False):
    max_retries: int
    on_request: OnRequest
    on_response: OnResponse


@dataclass(frozen=True)
class Errors:
    """How a service SDK words what went wrong; `api` may return an error with `retry_after_seconds`."""

    timeout: Callable[[float], Exception]
    unreachable: Callable[[str], Exception]
    too_large: Callable[[], Exception]
    api: Callable[[int, bytes], Exception]


def parse_json(content: bytes) -> Any:
    try:
        return json.loads(content)
    except (ValueError, RecursionError):
        return None


class _Network(Exception):
    def __init__(self, error: Exception) -> None:
        self.error = error


class Transport:
    """Per-attempt timeout, no redirects, bounded retries of idempotent requests only.

    `credentials` may be a function, called before every attempt. `transport` swaps the
    httpx transport (proxies, mTLS, test doubles).
    """

    def __init__(
        self,
        base_url: str,
        credentials: Credentials,
        *,
        timeout: float,
        errors: Errors,
        max_retries: int = 2,
        transport: httpx.AsyncBaseTransport | None = None,
        on_request: OnRequest | None = None,
        on_response: OnResponse | None = None,
    ) -> None:
        if not 0 <= max_retries <= MAX_RETRIES:
            raise ValueError(f"max_retries must be an integer from 0 to {MAX_RETRIES}")
        if credentials == "":
            raise ValueError("credentials must not be empty")
        self._credentials = credentials
        self._timeout = timeout
        self._errors = errors
        self._max_retries = max_retries
        self._on_request = on_request
        self._on_response = on_response
        self._http = httpx.AsyncClient(
            base_url=base_url,
            timeout=None,
            # Credentials must not follow a redirect to another host.
            follow_redirects=False,
            transport=transport,
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    async def json(
        self,
        method: str,
        path: str,
        *,
        body: Any = None,
        form: Mapping[str, str] | None = None,
        headers: dict[str, str] | None = None,
        params: Params = None,
        idempotency_key: str | None = None,
    ) -> Any:
        """The parsed JSON of a 2xx response, or None when the body is not JSON."""
        response = await self.raw(
            method,
            path,
            body=body,
            form=form,
            headers=headers,
            params=params,
            idempotency_key=idempotency_key,
        )
        return parse_json(response.content)

    async def raw(
        self,
        method: str,
        path: str,
        *,
        body: Any = None,
        form: Mapping[str, str] | None = None,
        headers: dict[str, str] | None = None,
        params: Params = None,
        idempotency_key: str | None = None,
    ) -> httpx.Response:
        """Any 2xx response; retries idempotent requests on 502/503/504, timeouts and dropped connections.

        `form` is sent as application/x-www-form-urlencoded instead of a JSON `body`.
        """
        idempotent = method == "GET" or idempotency_key is not None
        attempts = self._max_retries + 1 if idempotent else 1
        extra = dict(headers or {})
        if idempotency_key is not None:
            extra["idempotency-key"] = idempotency_key
        attempt = 0
        while True:
            attempt += 1
            last = attempt == attempts
            try:
                response = await self._once(method, path, body, extra, params, attempt, form)
            except _Network as e:
                if last:
                    raise e.error from None
                await _backoff(attempt)
                continue
            if 200 <= response.status_code < 300:
                return response
            error = self._errors.api(response.status_code, response.content)
            retry_after = getattr(error, "retry_after_seconds", None) or 0
            if last or response.status_code not in RETRYABLE or retry_after > 1:
                raise error
            await _backoff(attempt)

    async def stream(
        self,
        method: str,
        path: str,
        *,
        body: Any = None,
        headers: dict[str, str] | None = None,
        params: Params = None,
    ) -> httpx.Response:
        """The response as soon as headers arrive, any status, for the caller to read and close.

        No retries; `timeout` bounds connecting, the wait for headers and each gap between chunks.
        """
        request, info = await self._prepare(method, path, body, headers or {}, params, 1)
        request.extensions["timeout"] = httpx.Timeout(self._timeout).as_dict()
        started = time.perf_counter()
        try:
            response = await self._http.send(request, stream=True)
        except httpx.TimeoutException:
            raise self._errors.timeout(self._timeout) from None
        except httpx.HTTPError as e:
            # Raised `from None`: the cause can quote a header value, i.e. a token.
            raise self._errors.unreachable(type(e).__name__) from None
        await self._respond(info, response.status_code, response.headers, started)
        return response

    async def _prepare(
        self,
        method: str,
        path: str,
        body: Any,
        extra: dict[str, str],
        params: Params,
        attempt: int,
        form: Mapping[str, str] | None = None,
    ) -> tuple[httpx.Request, RequestInfo]:
        token = self._credentials() if callable(self._credentials) else self._credentials
        if isinstance(token, Awaitable):
            token = await token
        if token == "":
            raise ValueError("credentials must not be empty")
        content = (
            urlencode(form).encode()
            if form is not None
            else None
            if body is None
            else json.dumps(body).encode()
        )
        request = self._http.build_request(method, path, content=content, params=params)
        request.headers["authorization"] = f"Bearer {token}"
        if form is not None:
            request.headers["content-type"] = "application/x-www-form-urlencoded"
        elif body is not None:
            request.headers["content-type"] = "application/json"
        for key, value in extra.items():
            request.headers[key] = value
        info = RequestInfo(method, str(request.url), attempt, dict(request.headers))
        if self._on_request is not None:
            hooked = self._on_request(info)
            if isinstance(hooked, Awaitable):
                await hooked
        for key, value in info.headers.items():
            request.headers[key] = value
        return request, info

    async def _respond(
        self, info: RequestInfo, status: int, headers: httpx.Headers, started: float
    ) -> None:
        if self._on_response is None:
            return
        hooked = self._on_response(
            ResponseInfo(
                info.method,
                info.url,
                info.attempt,
                status,
                headers,
                (time.perf_counter() - started) * 1000,
            )
        )
        if isinstance(hooked, Awaitable):
            await hooked

    async def _once(
        self,
        method: str,
        path: str,
        body: Any,
        extra: dict[str, str],
        params: Params,
        attempt: int,
        form: Mapping[str, str] | None = None,
    ) -> httpx.Response:
        request, info = await self._prepare(method, path, body, extra, params, attempt, form)
        started = time.perf_counter()
        try:
            async with asyncio.timeout(self._timeout):
                response = await self._http.send(request, stream=True)
                try:
                    chunks = []
                    size = 0
                    async for chunk in response.aiter_bytes():
                        size += len(chunk)
                        if size > MAX_RESPONSE_BYTES:
                            raise _Network(self._errors.too_large())
                        chunks.append(chunk)
                finally:
                    await response.aclose()
        except TimeoutError:
            raise _Network(self._errors.timeout(self._timeout)) from None
        except httpx.HTTPError as e:
            # Raised `from None`: the cause can quote a header value, i.e. a token.
            raise _Network(self._errors.unreachable(type(e).__name__)) from None
        result = httpx.Response(
            response.status_code, headers=response.headers, content=b"".join(chunks)
        )
        await self._respond(info, result.status_code, result.headers, started)
        return result


async def _backoff(attempt: int) -> None:
    await asyncio.sleep(random.random() * 0.04 * attempt)
