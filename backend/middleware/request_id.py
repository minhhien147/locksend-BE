"""
Gắn X-Request-ID cho mọi request (dùng lại header client gửi nếu có).

Pure ASGI — `request.state.request_id` vẫn hoạt động vì Starlette đọc state từ
scope["state"] (xem audit.get_request_id).
"""
from __future__ import annotations

import uuid

from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class RequestIdMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = Headers(scope=scope).get("x-request-id") or str(uuid.uuid4())
        scope.setdefault("state", {})["request_id"] = request_id

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                MutableHeaders(scope=message)["x-request-id"] = request_id
            await send(message)

        await self.app(scope, receive, send_wrapper)
