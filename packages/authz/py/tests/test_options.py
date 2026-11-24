import asyncio
import json

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


def test_place_principal_puts_the_unit_for_the_principal() -> None:
    seen: list[tuple[str, str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path, json.loads(request.content)))
        return httpx.Response(200, json={"unit": "finance"})

    async def go() -> None:
        async with Authz(
            "http://authz.test",
            lambda: "t",
            "crm",
            transport=httpx.MockTransport(handler),
        ) as authz:
            await authz.place_principal(
                principal_id="prn_" + "a" * 32, principal_type="user", unit="finance"
            )

    asyncio.run(go())
    assert seen == [
        (
            "PUT",
            "/v1/tenant/principals/prn_" + "a" * 32 + "/unit",
            {"principalType": "user", "unit": "finance"},
        )
    ]
