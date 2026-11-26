import re
from urllib.parse import quote
from dataclasses import dataclass
from types import TracebackType
from typing import Literal, Self, Unpack, cast, get_args

import httpx
from bae6_sdk_core import Credentials, Errors, Options, parse_json
from bae6_sdk_core import Transport as CoreTransport
from bae6_sdk_core.identity import Principal, PrincipalType

_SUBJECT_TYPES = {
    "session": "urn:bae6:params:oauth:token-type:session",
    "jwt": "urn:ietf:params:oauth:token-type:jwt",
}


class AuthnError(Exception):
    pass


class AuthnApiError(AuthnError):
    def __init__(self, status: int, code: str | None, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code


class AuthnAuthError(AuthnApiError):
    """401 or 403: a bad client secret or bearer token."""


class AuthnValidationError(AuthnApiError):
    """400: authn refused the request or its subject token."""


class AuthnTransportError(AuthnError):
    pass


class AuthnTimeoutError(AuthnTransportError):
    pass


@dataclass(frozen=True)
class Token:
    access_token: str
    expires_in: int


@dataclass(frozen=True)
class Delegation:
    delegation_id: str
    expires_at: str
    token: Token


@dataclass(frozen=True)
class Me:
    principal: Principal
    org_path: list[str]


def _str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _http_error(status: int, content: bytes) -> AuthnApiError:
    parsed = parse_json(content)
    body = parsed if isinstance(parsed, dict) else {}
    code = _str(body.get("error")) or _str(body.get("code"))
    error_type = (
        AuthnValidationError
        if status == 400
        else AuthnAuthError
        if status in (401, 403)
        else AuthnApiError
    )
    detail = f" ({code})" if code else ""
    return error_type(status, code, f"authn returned HTTP {status}{detail}")


def _is_principal(value: object) -> bool:
    return (
        isinstance(value, dict)
        and isinstance(value.get("id"), str)
        and isinstance(value.get("tenantId"), str)
        and value.get("type") in get_args(PrincipalType)
        and value.get("status") in ("active", "disabled", "deprovisioned")
    )


def _invalid_response() -> AuthnApiError:
    return AuthnApiError(200, "invalid_response", "authn returned an unusable response")


_ERRORS = Errors(
    timeout=lambda seconds: AuthnTimeoutError(f"authn did not answer within {seconds} s"),
    unreachable=lambda name: AuthnTransportError(f"could not reach authn ({name})"),
    too_large=lambda: AuthnTransportError("the authn response is too large"),
    api=_http_error,
)


class Authn:
    """Async authn client; `credentials` is this client's authn client secret."""

    def __init__(
        self,
        base_url: str,
        credentials: Credentials,
        timeout: float = 5.0,
        transport: httpx.AsyncBaseTransport | None = None,
        **options: Unpack[Options],
    ) -> None:
        self._http = CoreTransport(
            base_url, credentials, timeout=timeout, errors=_ERRORS, transport=transport, **options
        )

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._http.aclose()

    async def exchange_token(
        self,
        *,
        subject_token: str,
        subject_token_type: Literal["session", "jwt"],
        audience: str,
    ) -> Token:
        """RFC 8693 exchange of a session cookie value or a bae6 token for a token for `audience`."""
        if subject_token_type not in _SUBJECT_TYPES:
            raise ValueError('subject_token_type must be "session" or "jwt"')
        body = await self._http.json(
            "POST",
            "/auth/token",
            form={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": subject_token,
                "subject_token_type": _SUBJECT_TYPES[subject_token_type],
                "audience": audience,
            },
        )
        if not isinstance(body, dict):
            raise _invalid_response()
        token = body.get("access_token")
        expires_in = body.get("expires_in")
        if (
            not isinstance(token, str)
            or body.get("token_type") != "Bearer"
            or type(expires_in) is not int
            or expires_in < 1
        ):
            raise _invalid_response()
        return Token(access_token=token, expires_in=expires_in)

    async def me(self, token: str) -> Me:
        """The principal behind `token`, a bae6 token issued to `bae6-authn`."""
        if token == "":
            raise ValueError("token must not be empty")
        body = await self._http.json(
            "GET", "/auth/me", headers={"authorization": f"Bearer {token}"}
        )
        if not isinstance(body, dict):
            raise _invalid_response()
        principal = body.get("principal")
        org_path = body.get("orgPath")
        if (
            not _is_principal(principal)
            or not isinstance(org_path, list)
            or not 1 <= len(org_path) <= 32
            or not all(isinstance(p, str) for p in org_path)
        ):
            raise _invalid_response()
        return Me(principal=cast(Principal, principal), org_path=org_path)

    async def revoke_delegation(self, delegation_id: str, token: str) -> None:
        if re.fullmatch(r"dlg_[0-9a-f]{32}", delegation_id) is None or not token:
            raise ValueError("A delegation ID and bearer token are required.")
        response = await self._http.raw(
            "POST",
            f"/v1/delegations/{delegation_id}/revoke",
            headers={"authorization": f"Bearer {token}"},
        )
        if response.status_code != 204:
            raise _invalid_response()

    async def create_delegation(
        self,
        token: str,
        *,
        actor_principal_id: str,
        application_id: str,
        task_id: str,
        allowed_resources: list[str],
        allowed_actions: list[str],
        expires_in_seconds: int,
        audience: str,
        parent_delegation_id: str | None = None,
        approved_actions: list[str] | None = None,
    ) -> Delegation:
        """Delegates a task scope to an actor; `token` is the caller's bae6-authn token."""
        if not token:
            raise ValueError("token must not be empty")
        payload: dict[str, object] = {
            "actorPrincipalId": actor_principal_id,
            "applicationId": application_id,
            "taskId": task_id,
            "allowedResources": allowed_resources,
            "allowedActions": allowed_actions,
            "expiresInSeconds": expires_in_seconds,
            "audience": audience,
        }
        if parent_delegation_id is not None:
            payload["parentDelegationId"] = parent_delegation_id
        if approved_actions is not None:
            payload["approvedActions"] = approved_actions
        body = await self._http.json(
            "POST",
            "/v1/delegations",
            headers={"authorization": f"Bearer {token}"},
            body=payload,
        )
        issued = body.get("token") if isinstance(body, dict) else None
        delegation_id = body.get("delegationId") if isinstance(body, dict) else None
        expires_at = body.get("expiresAt") if isinstance(body, dict) else None
        access = issued.get("access_token") if isinstance(issued, dict) else None
        expires_in = issued.get("expires_in") if isinstance(issued, dict) else None
        if (
            not isinstance(delegation_id, str)
            or re.fullmatch(r"dlg_[0-9a-f]{32}", delegation_id) is None
            or not isinstance(expires_at, str)
            or not isinstance(access, str)
            or type(expires_in) is not int
            or expires_in < 1
        ):
            raise _invalid_response()
        return Delegation(
            delegation_id=delegation_id,
            expires_at=expires_at,
            token=Token(access_token=access, expires_in=expires_in),
        )

    async def place_principal(
        self, *, tenant_id: str, principal_id: str, principal_type: str, org_path: list[str]
    ) -> list[str]:
        """Moves a principal to `org_path`; needs the placement client secret."""
        body = await self._http.json(
            "PUT",
            f"/admin/principals/{quote(principal_id, safe='')}/org-path",
            body={"tenantId": tenant_id, "principalType": principal_type, "orgPath": org_path},
        )
        stored = body.get("orgPath") if isinstance(body, dict) else None
        if not isinstance(stored, list) or not all(isinstance(p, str) for p in stored):
            raise _invalid_response()
        return stored
