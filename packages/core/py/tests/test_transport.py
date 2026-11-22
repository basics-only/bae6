import asyncio
import functools

import httpx
import pytest
from bae6_sdk_core import Errors, Transport


def sync(fn):
    @functools.wraps(fn)
    def run():
        asyncio.run(fn())

    return run


class ApiError(Exception):
    def __init__(self, status: int) -> None:
        super().__init__(f"api {status}")
        self.status = status


class NetError(Exception):
    pass


ERRORS = Errors(
    timeout=lambda s: NetError("timeout"),
    unreachable=lambda name: NetError(f"unreachable {name}"),
    too_large=lambda: NetError("too large"),
    api=lambda status, body: ApiError(status),
)


def make(handler, credentials="tok", **kwargs) -> Transport:
    return Transport(
        "http://svc.test",
        credentials,
        timeout=1.0,
        errors=ERRORS,
        transport=httpx.MockTransport(handler),
        **kwargs,
    )


@sync
async def test_sends_bearer_credentials_through_the_injected_transport():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["auth"] = request.headers["authorization"]
        return httpx.Response(200, json={})

    await make(handler).raw("GET", "/v1/x")
    assert seen == {"url": "http://svc.test/v1/x", "auth": "Bearer tok"}


@sync
async def test_calls_a_credentials_function_before_every_attempt():
    auths: list[str] = []
    n = 0

    async def credentials() -> str:
        nonlocal n
        n += 1
        return f"tok{n}"

    def handler(request: httpx.Request) -> httpx.Response:
        auths.append(request.headers["authorization"])
        return httpx.Response(503 if len(auths) == 1 else 200, json={})

    await make(handler, credentials).raw("GET", "/v1/x")
    assert auths == ["Bearer tok1", "Bearer tok2"]


@sync
async def test_hooks_can_add_headers_and_see_each_attempt():
    sent: list[str | None] = []
    seen: list[tuple[int, int]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request.headers.get("x-trace"))
        return httpx.Response(502 if len(sent) == 1 else 200, json={})

    def on_request(r) -> None:
        r.headers["x-trace"] = f"a{r.attempt}"

    async def on_response(r) -> None:
        seen.append((r.attempt, r.status))

    await make(handler, on_request=on_request, on_response=on_response).raw("GET", "/v1/x")
    assert sent == ["a1", "a2"]
    assert seen == [(1, 502), (2, 200)]


@sync
async def test_max_retries_bounds_the_attempts():
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503, json={})

    for retries, expected in ((0, 1), (1, 2)):
        calls = 0
        with pytest.raises(ApiError):
            await make(handler, max_retries=retries).raw("GET", "/v1/x")
        assert calls == expected


def test_rejects_unsupported_max_retries_and_empty_credentials():
    with pytest.raises(ValueError):
        make(lambda r: httpx.Response(200), max_retries=6)
    with pytest.raises(ValueError):
        make(lambda r: httpx.Response(200), credentials="")


@sync
async def test_does_not_retry_a_post_without_an_idempotency_key():
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503, json={})

    with pytest.raises(ApiError):
        await make(handler).raw("POST", "/v1/x", body={})
    assert calls == 1


@sync
async def test_retries_a_dropped_connection_on_an_idempotent_request():
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise httpx.ConnectError("bad header Bearer tok")
        return httpx.Response(200, json={})

    await make(handler).raw("GET", "/v1/x")
    assert calls == 2


@sync
async def test_connection_error_does_not_carry_the_token():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("bad header Bearer tok")

    with pytest.raises(NetError) as info:
        await make(handler, max_retries=0).raw("GET", "/v1/x")
    assert "tok" not in str(info.value)
    assert info.value.__cause__ is None
    assert info.value.__suppress_context__


@sync
async def test_a_failing_credentials_function_is_raised_once_and_not_retried():
    def credentials() -> str:
        raise RuntimeError("no token")

    with pytest.raises(RuntimeError, match="no token"):
        await make(lambda r: httpx.Response(200), credentials).raw("GET", "/v1/x")
