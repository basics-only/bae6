import asyncio

import httpx
from bae6_ai import Ai


def test_hooks_and_credentials_function_apply_to_streams_and_calls() -> None:
    seen: list[tuple[str, str | None]] = []
    statuses: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.headers["authorization"], request.headers.get("x-trace")))
        if request.url.path == "/v1/models":
            return httpx.Response(200, json={"data": []})
        return httpx.Response(200, text='data: {"usage": {}}\n\ndata: [DONE]\n\n')

    async def go() -> None:
        async with Ai(
            "http://ai.test",
            lambda: "rotated",
            transport=httpx.MockTransport(handler),
            on_request=lambda r: r.headers.update({"x-trace": "t"}),
            on_response=lambda r: statuses.append(r.status),
        ) as ai:
            await ai.models()
            [_ async for _ in ai.chat_stream(model="m", messages=[])]

    asyncio.run(go())
    assert seen == [("Bearer rotated", "t")] * 2
    assert statuses == [200, 200]
