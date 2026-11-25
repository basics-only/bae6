import asyncio
import json

import httpx
import pytest
from bae6_authz import Authz, AuthzApiError


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


def test_tenant_check_posts_the_resource_and_raises_instead_of_denying_quietly() -> None:
    replies = [
        httpx.Response(200, json={"allowed": True}),
        httpx.Response(200, json={"allowed": "yes"}),
        httpx.Response(503, json={"code": "x", "message": "m", "requestId": "r"}),
    ]
    seen: list[tuple[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.path, json.loads(request.content)))
        return replies.pop(0)

    async def go() -> None:
        async with Authz(
            "http://authz.test",
            lambda: "t",
            "crm",
            transport=httpx.MockTransport(handler),
        ) as authz:
            assert await authz.tenant_check(resource_type="model", resource_id="llm")
            with pytest.raises(AuthzApiError):
                await authz.tenant_check(resource_type="model", resource_id="llm")
            with pytest.raises(AuthzApiError) as err:
                await authz.tenant_check(resource_type="model", resource_id="llm")
            assert err.value.status == 503

    asyncio.run(go())
    assert seen[0] == (
        "/v1/tenant/check",
        {"resourceType": "model", "resourceId": "llm"},
    )


def test_place_tenant_resource_puts_the_placement_and_returns_its_audit_id() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "PUT"
        assert request.url.path == "/v1/tenant/resources/unit"
        assert json.loads(request.content) == {
            "resourceType": "model",
            "resourceId": "llm",
            "unit": "finance",
        }
        return httpx.Response(200, json={"auditEventId": "42"})

    async def go() -> None:
        async with Authz(
            "http://authz.test", lambda: "t", "crm", transport=httpx.MockTransport(handler)
        ) as authz:
            assert (
                await authz.place_tenant_resource(
                    resource_type="model", resource_id="llm", unit="finance"
                )
                == "42"
            )

    asyncio.run(go())
