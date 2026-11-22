import asyncio

import httpx
from bae6_authz import Authz


def test_credentials_function_and_hooks_apply_to_every_request() -> None:
    seen: list[tuple[str, str | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.headers["authorization"], request.headers.get("x-trace")))
        return httpx.Response(200, json={"status": "allow", "requestId": "r1"})

    async def go() -> None:
        async with Authz(
            "http://authz.test",
            lambda: "rotated",
            "crm",
            transport=httpx.MockTransport(handler),
            on_request=lambda r: r.headers.update({"x-trace": "t"}),
        ) as authz:
            await authz.check(action="read", resource="doc:1", end_user_token="u")

    asyncio.run(go())
    assert seen == [("Bearer rotated", "t")]
