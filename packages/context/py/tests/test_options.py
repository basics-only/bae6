import asyncio

import httpx
import pytest
from bae6_context import ContextApiError, DataClient


def test_max_retries_zero_disables_retries_of_idempotent_requests() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503, json={})

    async def go() -> None:
        async with DataClient(
            "http://ctx.test",
            "tok",
            transport=httpx.MockTransport(handler),
            max_retries=0,
        ) as data:
            await data.sources()

    with pytest.raises(ContextApiError):
        asyncio.run(go())
    assert calls == 1
