import asyncio
import json
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qsl

import httpx
import pytest
from bae6_authn import (
    Authn,
    AuthnApiError,
    AuthnAuthError,
    AuthnTimeoutError,
    AuthnValidationError,
)

SECRET = "client-secret-xxxxxxxxxxxxxxxxxxxxxxxx"
SESSION = f"ses_{'a' * 32}.{'b' * 43}"


def _run(handler: Callable[[httpx.Request], httpx.Response], call: Callable[[Authn], Any]) -> Any:
    async def go() -> Any:
        async with Authn(
            "http://authn.test", SECRET, timeout=0.2, transport=httpx.MockTransport(handler)
        ) as authn:
            return await call(authn)

    return asyncio.run(go())


def _exchange(authn: Authn) -> Any:
    return authn.exchange_token(
        subject_token=SESSION, subject_token_type="session", audience="bae6-ai"
    )


def test_exchange_posts_rfc8693_form_with_client_secret_bearer() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            200, json={"access_token": "tok", "token_type": "Bearer", "expires_in": 300}
        )

    token = _run(handler, _exchange)
    assert (token.access_token, token.expires_in) == ("tok", 300)
    [request] = seen
    assert (request.method, request.url.path) == ("POST", "/auth/token")
    assert request.headers["authorization"] == f"Bearer {SECRET}"
    assert request.headers["content-type"] == "application/x-www-form-urlencoded"
    assert dict(parse_qsl(request.content.decode())) == {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token": SESSION,
        "subject_token_type": "urn:bae6:params:oauth:token-type:session",
        "audience": "bae6-ai",
    }


@pytest.mark.parametrize(
    ("status", "code", "error_type"),
    [(401, "invalid_client", AuthnAuthError), (400, "invalid_target", AuthnValidationError)],
)
def test_exchange_maps_oauth_errors_without_leaking_or_retrying(
    status: int, code: str, error_type: type[AuthnApiError]
) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(status, json={"error": code})

    with pytest.raises(error_type) as caught:
        _run(handler, _exchange)
    assert (caught.value.status, caught.value.code, calls) == (status, code, 1)
    assert SECRET not in str(caught.value) and SESSION not in str(caught.value)


def test_exchange_rejects_success_that_is_not_a_bearer_token() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"access_token": "tok", "token_type": "DPoP", "expires_in": True}
        )

    with pytest.raises(AuthnApiError) as caught:
        _run(handler, _exchange)
    assert caught.value.code == "invalid_response"


def test_me_sends_the_bae6_token_not_the_client_secret() -> None:
    principal = {"id": f"prn_{'c' * 32}", "tenantId": "acme", "type": "user", "status": "active"}
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"principal": principal, "orgPath": ["acme", "eng"]})

    me = _run(handler, lambda authn: authn.me("user-token"))
    assert (me.principal, me.org_path) == (principal, ["acme", "eng"])
    assert (seen[0].method, seen[0].url.path) == ("GET", "/auth/me")
    assert seen[0].headers["authorization"] == "Bearer user-token"


@pytest.mark.parametrize(
    "body",
    [
        {"principal": {"id": "prn_x"}, "orgPath": ["acme"]},
        {
            "principal": {"id": "prn_x", "tenantId": "acme", "type": "root", "status": "active"},
            "orgPath": ["acme"],
        },
        {
            "principal": {"id": "prn_x", "tenantId": "acme", "type": "user", "status": "active"},
            "orgPath": [],
        },
    ],
)
def test_me_rejects_a_partial_principal_or_empty_org_path(body: dict[str, Any]) -> None:
    with pytest.raises(AuthnApiError) as caught:
        _run(lambda r: httpx.Response(200, json=body), lambda authn: authn.me("user-token"))
    assert caught.value.code == "invalid_response"


def test_exchange_refuses_an_unknown_subject_token_type_before_sending() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json={})

    with pytest.raises(ValueError):
        _run(
            handler,
            lambda authn: authn.exchange_token(
                subject_token=SESSION,
                subject_token_type="access_token",  # type: ignore[arg-type]
                audience="bae6-ai",
            ),
        )
    assert calls == []


def test_me_maps_401_and_times_out() -> None:
    with pytest.raises(AuthnAuthError):
        _run(
            lambda r: httpx.Response(401, json={"code": "unauthenticated"}),
            lambda authn: authn.me("user-token"),
        )

    async def slow(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(1)
        return httpx.Response(200, json={})

    async def go() -> None:
        async with Authn(
            "http://authn.test", SECRET, timeout=0.05, transport=httpx.MockTransport(slow)
        ) as authn:
            await authn.me("user-token")

    with pytest.raises(AuthnTimeoutError):
        asyncio.run(go())


def test_place_principal_puts_json_and_returns_the_stored_path() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"orgPath": ["acme", "finance"]})

    path = _run(
        handler,
        lambda authn: authn.place_principal(
            tenant_id="acme",
            principal_id="prn_x",
            principal_type="user",
            org_path=["acme", "finance"],
        ),
    )
    assert path == ["acme", "finance"]
    (request,) = seen
    assert request.method == "PUT"
    assert request.url.path == "/admin/principals/prn_x/org-path"
    assert request.headers["authorization"] == f"Bearer {SECRET}"
    assert json.loads(request.content) == {
        "tenantId": "acme",
        "principalType": "user",
        "orgPath": ["acme", "finance"],
    }


@pytest.mark.parametrize(
    ("status", "error_type"),
    [(401, AuthnAuthError), (400, AuthnValidationError), (404, AuthnApiError)],
)
def test_place_principal_maps_refusals_to_typed_errors(
    status: int, error_type: type[AuthnApiError]
) -> None:
    with pytest.raises(error_type) as caught:
        _run(
            lambda _request: httpx.Response(status, json={"code": "refused"}),
            lambda authn: authn.place_principal(
                tenant_id="acme",
                principal_id="prn_x",
                principal_type="user",
                org_path=["acme"],
            ),
        )
    assert caught.value.status == status
