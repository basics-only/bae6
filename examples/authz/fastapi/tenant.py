import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated

from bae6_authn import Authn
from bae6_authz import ExecutionContext
from bae6_authz.middleware import ExchangedToken, TenantGuard, TenantResource, fastapi_dependency
from fastapi import Depends, FastAPI, HTTPException, Request


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    async with Authn(os.environ["BAE6_AUTHN_URL"], os.environ["BAE6_AUTHN_CLIENT_SECRET"]) as authn:

        async def exchange(subject_token: str) -> ExchangedToken:
            token = await authn.exchange_token(
                subject_token=subject_token, subject_token_type="jwt", audience="bae6-authz"
            )
            return ExchangedToken(token.access_token, token.expires_in)

        guard = TenantGuard(
            os.environ["BAE6_API_URL"],
            "fastapi-protected-api",
            exchange,
            include_execution_context=True,
        )
        app.state.authorize = fastapi_dependency(
            guard, lambda request: TenantResource("document", request.path_params["doc_id"])
        )
        try:
            yield
        finally:
            await guard.aclose()


app = FastAPI(lifespan=lifespan)


async def authorize(request: Request) -> ExecutionContext:
    context = await request.app.state.authorize(request)
    if not isinstance(context, ExecutionContext):
        raise HTTPException(503, "Execution context is unavailable.")
    return context


@app.get("/documents/{doc_id}")
async def read_document(
    doc_id: str, context: Annotated[ExecutionContext, Depends(authorize)]
) -> dict[str, str]:
    return {"id": doc_id, "requestId": context.request_id}
