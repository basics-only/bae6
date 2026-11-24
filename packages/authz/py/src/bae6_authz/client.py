from collections.abc import Sequence
from dataclasses import dataclass
from types import TracebackType
from typing import Literal, Self, Unpack
from urllib.parse import quote

import httpx
from bae6_sdk_core import Credentials, Errors, Options, parse_json
from bae6_sdk_core import Transport as CoreTransport


class AuthzError(Exception):
    def __init__(self, message: str, request_id: str | None = None) -> None:
        super().__init__(message)
        self.request_id = request_id


class AuthzApiError(AuthzError):
    """authz answered with something other than a decision."""

    def __init__(
        self, status: int, code: str | None, message: str, request_id: str | None = None
    ) -> None:
        super().__init__(message, request_id)
        self.status = status
        self.code = code


class AuthzAuthError(AuthzApiError):
    """401 or 403: bad workload or end-user credentials, or a missing scope."""


class AuthzValidationError(AuthzApiError):
    """400: authz rejected the request."""


class AuthzIndeterminateError(AuthzError):
    """authz could not decide (for example its authorization backend timed out)."""

    def __init__(self, code: str | None, request_id: str) -> None:
        detail = f" ({code})" if code else ""
        super().__init__(f"authz could not decide{detail}; treat as denied", request_id)
        self.code = code


class AuthzTransportError(AuthzError):
    """authz was not reached or did not answer."""


class AuthzTimeoutError(AuthzTransportError):
    pass


@dataclass(frozen=True)
class ExecutionContext:
    tenant_id: str
    org_path: tuple[str, ...]
    principal_id: str
    principal_type: str
    actor_id: str
    request_id: str
    application_id: str | None = None
    session_id: str | None = None
    task_id: str | None = None
    delegation_id: str | None = None
    trace_id: str | None = None
    cost_center_id: str | None = None


@dataclass(frozen=True)
class Check:
    action: str
    resource: str


Consistency = Literal["minimize_latency", "higher_consistency"]


@dataclass(frozen=True)
class Decision:
    """`allowed` is true only for `allow`; an undecidable check raises instead."""

    allowed: bool
    status: Literal["allow", "deny"]
    request_id: str
    model_id: str | None = None


@dataclass(frozen=True)
class ItemDecision:
    allowed: bool
    status: Literal["allow", "deny", "indeterminate"]


@dataclass(frozen=True)
class BatchDecision:
    request_id: str
    # One per input check, in input order.
    results: list[ItemDecision]
    model_id: str | None = None


@dataclass(frozen=True)
class ObjectPage:
    request_id: str
    # Ascending `type:id` objects the user holds the action on.
    objects: list[str]
    model_id: str | None = None
    # Pass as `cursor` for the next page; None on the last page.
    next_cursor: str | None = None


def _str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _http_error(status: int, content: bytes) -> AuthzApiError:
    parsed = parse_json(content)
    body = parsed if isinstance(parsed, dict) else {}
    error_type = (
        AuthzValidationError
        if status == 400
        else AuthzAuthError
        if status in (401, 403)
        else AuthzApiError
    )
    return error_type(
        status,
        _str(body.get("code")),
        _str(body.get("message")) or f"authz returned HTTP {status}",
        _str(body.get("requestId")),
    )


def _invalid_response() -> AuthzApiError:
    return AuthzApiError(200, "invalid_response", "authz returned an unusable response")


def _item_decision(status: str | None) -> ItemDecision:
    # Anything that is not `allow` is not an allow; `indeterminate` is kept apart.
    if status == "allow":
        return ItemDecision(True, "allow")
    if status is None or status == "indeterminate":
        return ItemDecision(False, "indeterminate")
    return ItemDecision(False, "deny")


_ERRORS = Errors(
    timeout=lambda seconds: AuthzTimeoutError(f"authz did not answer within {seconds} s"),
    unreachable=lambda name: AuthzTransportError(f"could not reach authz ({name})"),
    too_large=lambda: AuthzTransportError("the authz response is too large"),
    api=_http_error,
)


class Authz:
    """Async authz client. Use `async with Authz(...) as authz` so connections are closed."""

    def __init__(
        self,
        base_url: str,
        credentials: Credentials,
        application: str,
        timeout: float = 5.0,
        transport: httpx.AsyncBaseTransport | None = None,
        **options: Unpack[Options],
    ) -> None:
        self._application = application
        self._http = CoreTransport(
            base_url,
            credentials,
            timeout=timeout,
            errors=_ERRORS,
            transport=transport,
            **options,
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

    async def check(
        self,
        *,
        action: str,
        resource: str,
        end_user_token: str,
        consistency: Consistency | None = None,
    ) -> Decision:
        """Whether the end user holds `action` on `resource`.

        `consistency="higher_consistency"` sees revocations already committed, at more cost;
        unset uses authz's default, `minimize_latency`, which may serve a briefly cached answer.
        Raises AuthzIndeterminateError when authz cannot decide; never returns allow then.
        """
        payload: dict[str, object] = {
            "application": self._application,
            "relation": action,
            "object": resource,
        }
        if consistency is not None:
            payload["consistency"] = consistency
        body = await self._post("/v1/check", end_user_token, payload)
        status = _str(body.get("status"))
        request_id = _str(body.get("requestId"))
        if status is None or request_id is None:
            raise _invalid_response()
        if status == "indeterminate":
            raise AuthzIndeterminateError(_str(body.get("code")), request_id)
        allowed = status == "allow"
        return Decision(
            allowed=allowed,
            status="allow" if allowed else "deny",
            request_id=request_id,
            model_id=_str(body.get("modelId")),
        )

    async def batch_check(
        self,
        checks: Sequence[Check],
        *,
        end_user_token: str,
        consistency: Consistency | None = None,
    ) -> BatchDecision:
        """At most 100 checks (authz may allow fewer). An indeterminate item does not affect the rest.

        `consistency` applies to every check in the batch, as in `check`.
        """
        payload: dict[str, object] = {
            "application": self._application,
            "checks": [
                {"correlationId": str(i), "relation": c.action, "object": c.resource}
                for i, c in enumerate(checks)
            ],
        }
        if consistency is not None:
            payload["consistency"] = consistency
        body = await self._post("/v1/batch-check", end_user_token, payload)
        request_id = _str(body.get("requestId"))
        results = body.get("results")
        if request_id is None or not isinstance(results, list):
            raise _invalid_response()
        by_id: dict[str, str | None] = {}
        for r in results:
            if isinstance(r, dict) and isinstance(r.get("correlationId"), str):
                # A repeated ID is ambiguous, so neither answer is used.
                repeated = r["correlationId"] in by_id
                by_id[r["correlationId"]] = None if repeated else _str(r.get("status"))
        return BatchDecision(
            request_id=request_id,
            model_id=_str(body.get("modelId")),
            results=[_item_decision(by_id.get(str(i))) for i in range(len(checks))],
        )

    async def list_objects(
        self,
        *,
        action: str,
        type: str,
        end_user_token: str,
        limit: int | None = None,
        cursor: str | None = None,
        consistency: Consistency | None = None,
    ) -> ObjectPage:
        """One page of the `type` objects the end user holds `action` on.

        Raises AuthzIndeterminateError when authz cannot list; never returns a partial guess then.
        """
        payload: dict[str, object] = {
            "application": self._application,
            "relation": action,
            "type": type,
        }
        for key, value in (("limit", limit), ("cursor", cursor), ("consistency", consistency)):
            if value is not None:
                payload[key] = value
        body = await self._post("/v1/list-objects", end_user_token, payload)
        request_id = _str(body.get("requestId"))
        objects = body.get("objects")
        if (
            request_id is None
            or not isinstance(objects, list)
            or not all(isinstance(o, str) for o in objects)
        ):
            raise _invalid_response()
        if body.get("code") is not None:
            raise AuthzIndeterminateError(_str(body.get("code")), request_id)
        return ObjectPage(
            request_id=request_id,
            objects=objects,
            model_id=_str(body.get("modelId")),
            next_cursor=_str(body.get("nextCursor")),
        )

    async def place_principal(
        self,
        *,
        principal_id: str,
        principal_type: Literal["user", "service", "agent", "application"],
        unit: str,
    ) -> None:
        """Places a principal in an org unit of the caller's tenant; the credential must be a bae6 token for authz."""
        parsed = await self._http.json(
            "PUT",
            f"/v1/tenant/principals/{quote(principal_id, safe='')}/unit",
            body={"principalType": principal_type, "unit": unit},
        )
        if not isinstance(parsed, dict) or parsed.get("unit") != unit:
            raise _invalid_response()

    async def place_tenant_resource(
        self, *, resource_type: str, resource_id: str, unit: str
    ) -> str:
        parsed = await self._http.json(
            "PUT",
            "/v1/tenant/resources/unit",
            body={"resourceType": resource_type, "resourceId": resource_id, "unit": unit},
        )
        event_id = parsed.get("auditEventId") if isinstance(parsed, dict) else None
        if not isinstance(event_id, str):
            raise _invalid_response()
        return event_id

    async def tenant_check(self, *, resource_type: str, resource_id: str) -> bool:
        """Whether the credential's own principal may use the tenant resource. Anything but a 200 raises; treat it as denied."""
        parsed = await self._http.json(
            "POST",
            "/v1/tenant/check",
            body={"resourceType": resource_type, "resourceId": resource_id},
        )
        allowed = parsed.get("allowed") if isinstance(parsed, dict) else None
        if not isinstance(allowed, bool):
            raise _invalid_response()
        return allowed

    async def tenant_check_with_context(
        self, *, resource_type: str, resource_id: str
    ) -> ExecutionContext | None:
        parsed = await self._http.json(
            "POST",
            "/v1/tenant/check",
            body={
                "resourceType": resource_type,
                "resourceId": resource_id,
                "includeExecutionContext": True,
            },
        )
        if not isinstance(parsed, dict) or not isinstance(parsed.get("allowed"), bool):
            raise _invalid_response()
        if not parsed["allowed"]:
            return None
        context = parsed.get("executionContext")
        if not isinstance(context, dict):
            raise _invalid_response()
        tenant_id = context.get("tenantId")
        principal_id = context.get("principalId")
        principal_type = context.get("principalType")
        actor_id = context.get("actorId")
        request_id = context.get("requestId")
        org_path = context.get("orgPath")
        if (
            not isinstance(tenant_id, str)
            or not isinstance(principal_id, str)
            or not isinstance(principal_type, str)
            or not isinstance(actor_id, str)
            or not isinstance(request_id, str)
            or not isinstance(org_path, list)
            or not 1 <= len(org_path) <= 32
            or org_path[0] != tenant_id
            or not all(isinstance(unit, str) for unit in org_path)
        ):
            raise _invalid_response()
        fields = {
            "application_id": "applicationId",
            "session_id": "sessionId",
            "task_id": "taskId",
            "delegation_id": "delegationId",
            "trace_id": "traceId",
            "cost_center_id": "costCenterId",
        }
        optional: dict[str, str] = {}
        for attribute, field in fields.items():
            if field in context:
                value = context[field]
                if not isinstance(value, str):
                    raise _invalid_response()
                optional[attribute] = value
        return ExecutionContext(
            tenant_id,
            tuple(org_path),
            principal_id,
            principal_type,
            actor_id,
            request_id,
            **optional,
        )

    async def _post(
        self, path: str, end_user_token: str, payload: dict[str, object]
    ) -> dict[str, object]:
        parsed = await self._http.json(
            "POST", path, body=payload, headers={"bae6-end-user-token": end_user_token}
        )
        if not isinstance(parsed, dict):
            raise _invalid_response()
        return parsed
