"""ASGI middleware: Starlette, FastAPI, Django (ASGI), Quart, Litestar.

    from x402_gateway import Gateway
    from x402_gateway.asgi import X402Middleware

    gateway = Gateway("https://your-site.com", coinpay_api_key=os.environ["COINPAY_X402_KEY"], pay_to=os.environ["CRAWL_PAY_TO"])
    app.add_middleware(X402Middleware, gateway=gateway)      # Starlette / FastAPI
    application = X402Middleware(get_asgi_application(), gateway)  # Django
"""

from __future__ import annotations

import asyncio
from typing import Any, Callable, Optional
from urllib.parse import quote

from .core import Gateway, Request


def request_from_scope(scope: Any) -> Request:
    headers = {}
    for k, v in scope.get("headers") or []:
        name = k.decode("latin-1").lower()
        value = v.decode("latin-1")
        headers[name] = f"{headers[name]}, {value}" if name in headers else value
    host = headers.get("host")
    if not host:
        server = scope.get("server") or ("localhost", None)
        host = server[0] if server[1] in (None, 80, 443) else f"{server[0]}:{server[1]}"
    scheme = scope.get("scheme") or "http"
    path = scope.get("raw_path")
    path = path.decode("latin-1") if path else quote(scope.get("path") or "/")
    qs = (scope.get("query_string") or b"").decode("latin-1")
    url = f"{scheme}://{host}{path}" + (f"?{qs}" if qs else "")
    return Request(url=url, headers=headers, method=scope.get("method", "GET"))


class X402Middleware:
    def __init__(self, app: Callable, gateway: Optional[Gateway] = None, **options: Any) -> None:
        self.app = app
        self.gateway = gateway or Gateway(**options)

    async def __call__(self, scope: Any, receive: Callable, send: Callable) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        request = request_from_scope(scope)
        gw = self.gateway
        if gw.needs_io(request):
            answer = await asyncio.get_running_loop().run_in_executor(None, gw.handle, request)
        else:
            answer = gw.handle(request)
        if answer is None:
            await self.app(scope, receive, send)
            return
        body = answer.body_bytes
        headers = [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in answer.headers.items()]
        headers.append((b"content-length", str(len(body)).encode("ascii")))
        await send({"type": "http.response.start", "status": answer.status, "headers": headers})
        await send({"type": "http.response.body", "body": body})
