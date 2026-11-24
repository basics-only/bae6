import asyncio
import json

import httpx
import pytest
from bae6_authz import ExecutionContext
from bae6_authz.middleware import (
    ExchangedToken,
    TenantGuard,
    TenantResource,
    fastapi_dependency,
)
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

RESOURCE = TenantResource("model", "gpt")


class Fakes:
    def __init__(self) -> None:
        self.answer = httpx.Response(200, json={"allowed": True})
        self.exchanges: list[str] = []
        self.checked: list[tuple[str, object]] = []
        self.exchange_error: Exception | None = None
        self.expires_in = 300

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.checked.append((request.headers["authorization"], json.loads(request.content)))
        return self.answer

    async def exchange(self, subject_token: str) -> ExchangedToken:
        self.exchanges.append(subject_token)
        if self.exchange_error:
            raise self.exchange_error
        return ExchangedToken(f"authz-for-{subject_token}", self.expires_in)

    def guard(self, *, include_execution_context: bool = False) -> TenantGuard:
        return TenantGuard(
            "http://authz.test",
            "app",
            self.exchange,
            transport=httpx.MockTransport(self.handler),
            include_execution_context=include_execution_context,
        )


class Refused(Exception):
    status = 400


def run(guard: TenantGuard, authorization: str | None, resource: TenantResource | None = RESOURCE):
    return asyncio.run(guard(authorization, resource))


def test_an_allowed_check_passes_with_the_exchanged_token_and_the_resource() -> None:
    fakes = Fakes()
    assert run(fakes.guard(), "Bearer t1").allowed
    assert fakes.checked == [
        ("Bearer authz-for-t1", {"resourceType": "model", "resourceId": "gpt"})
    ]


def test_a_denied_check_is_403() -> None:
    fakes = Fakes()
    fakes.answer = httpx.Response(200, json={"allowed": False})
    verdict = run(fakes.guard(), "Bearer t1")
    assert (verdict.allowed, verdict.status) == (False, 403)


@pytest.mark.parametrize("header", [None, "", "Basic abc", "Bearer ", "Bearer a b"])
def test_a_missing_or_malformed_bearer_is_401_without_contacting_anyone(header: str | None) -> None:
    fakes = Fakes()
    assert run(fakes.guard(), header).status == 401
    assert fakes.exchanges == [] and fakes.checked == []


def test_a_request_with_no_resource_is_denied() -> None:
    fakes = Fakes()
    assert run(fakes.guard(), "Bearer t1", None).status == 403
    assert fakes.exchanges == []


def test_a_refused_token_is_401_and_an_exchange_outage_is_503() -> None:
    fakes = Fakes()
    fakes.exchange_error = Refused()
    assert run(fakes.guard(), "Bearer t1").status == 401
    fakes.exchange_error = RuntimeError("down")
    assert run(fakes.guard(), "Bearer t1").status == 503
    assert fakes.checked == []


def test_authz_failures_deny_and_never_allow() -> None:
    fakes = Fakes()
    guard = fakes.guard()
    fakes.answer = httpx.Response(503, json={"code": "authorization_unavailable"})
    assert run(guard, "Bearer t1").status == 503
    fakes.answer = httpx.Response(403, json={"code": "forbidden"})
    assert run(guard, "Bearer t1").status == 403
    fakes.answer = httpx.Response(200, json={"allowed": "yes"})
    assert not run(guard, "Bearer t1").allowed


def test_the_exchanged_token_is_reused_for_the_same_subject_token() -> None:
    fakes = Fakes()
    guard = fakes.guard()

    async def go() -> None:
        await guard("Bearer t1", RESOURCE)
        await guard("Bearer t1", RESOURCE)
        await guard("Bearer t2", RESOURCE)

    asyncio.run(go())
    assert fakes.exchanges == ["t1", "t2"]


def test_fastapi_dependency_lets_allowed_requests_in_and_answers_denials() -> None:
    fakes = Fakes()
    app = FastAPI()
    dependency = fastapi_dependency(fakes.guard(), lambda request: RESOURCE)

    @app.get("/x", dependencies=[Depends(dependency)])
    async def x() -> dict[str, str]:
        return {"ok": "yes"}

    client = TestClient(app)
    assert client.get("/x", headers={"authorization": "Bearer t1"}).json() == {"ok": "yes"}
    fakes.answer = httpx.Response(200, json={"allowed": False})
    denied = client.get("/x", headers={"authorization": "Bearer t9"})
    assert denied.status_code == 403
    assert denied.json()["detail"]["code"] == "forbidden"
    unauthenticated = client.get("/x")
    assert unauthenticated.status_code == 401
    assert unauthenticated.headers["www-authenticate"] == "Bearer"


def test_a_reused_exchanged_token_never_reuses_a_decision() -> None:
    fakes = Fakes()
    guard = fakes.guard()

    async def go() -> list[bool]:
        results = [(await guard("Bearer t1", RESOURCE)).allowed]
        fakes.answer = httpx.Response(200, json={"allowed": False})
        results.append((await guard("Bearer t1", RESOURCE)).allowed)
        fakes.answer = httpx.Response(200, json={"allowed": True})
        results.append((await guard("Bearer t1", RESOURCE)).allowed)
        return results

    assert asyncio.run(go()) == [True, False, True]
    assert len(fakes.exchanges) == 1 and len(fakes.checked) == 3


def test_an_exchanged_token_about_to_expire_is_exchanged_again_on_every_request() -> None:
    fakes = Fakes()
    fakes.expires_in = 30
    guard = fakes.guard()

    async def go() -> None:
        await guard("Bearer t1", RESOURCE)
        await guard("Bearer t1", RESOURCE)

    asyncio.run(go())
    assert fakes.exchanges == ["t1", "t1"]


def test_fastapi_dependency_returns_context_from_an_allowed_check() -> None:
    fakes = Fakes()
    identity = "prn_" + "a" * 32
    fakes.answer = httpx.Response(
        200,
        json={
            "allowed": True,
            "executionContext": {
                "tenantId": "acme",
                "orgPath": ["acme"],
                "principalId": identity,
                "principalType": "user",
                "actorId": identity,
                "requestId": "signed-request",
            },
        },
    )
    guard = fakes.guard(include_execution_context=True)
    dependency = fastapi_dependency(guard, lambda request: RESOURCE)
    app = FastAPI()

    @app.get("/")
    async def route(context: ExecutionContext = Depends(dependency)) -> dict[str, str]:
        return {"requestId": context.request_id}

    with TestClient(app) as client:
        headers = {"Authorization": "Bearer caller", "X-Request-Id": "forged"}
        assert client.get("/", headers=headers).json() == {"requestId": "signed-request"}
        assert fakes.checked[-1][1] == {
            "resourceType": "model",
            "resourceId": "gpt",
            "includeExecutionContext": True,
        }
        fakes.answer = httpx.Response(200, json={"allowed": True})
        assert client.get("/", headers=headers).status_code == 503
