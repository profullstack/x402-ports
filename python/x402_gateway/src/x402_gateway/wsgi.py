"""WSGI middleware: Flask, Django (WSGI), Bottle, Pyramid, plain wsgiref.

    from x402_gateway import Gateway
    from x402_gateway.wsgi import X402Middleware

    gateway = Gateway("https://your-site.com", coinpay_api_key=..., pay_to=...)
    app.wsgi_app = X402Middleware(app.wsgi_app, gateway)   # Flask
    application = X402Middleware(get_wsgi_application(), gateway)  # Django
"""

from __future__ import annotations

from typing import Any, Callable, Iterable, Optional
from urllib.parse import quote

from .core import Gateway, Request

_REASONS = {200: "OK", 402: "Payment Required", 403: "Forbidden"}


def request_from_environ(environ: Any) -> Request:
    headers = {}
    for k, v in environ.items():
        if k.startswith("HTTP_"):
            headers[k[5:].replace("_", "-").lower()] = v
    if "CONTENT_TYPE" in environ:
        headers.setdefault("content-type", environ["CONTENT_TYPE"])
    host = headers.get("host") or environ.get("SERVER_NAME", "localhost")
    scheme = environ.get("wsgi.url_scheme", "http")
    path = quote(environ.get("SCRIPT_NAME", "") + environ.get("PATH_INFO", "")) or "/"
    qs = environ.get("QUERY_STRING", "")
    url = f"{scheme}://{host}{path}" + (f"?{qs}" if qs else "")
    return Request(url=url, headers=headers, method=environ.get("REQUEST_METHOD", "GET"))


class X402Middleware:
    def __init__(self, app: Callable, gateway: Optional[Gateway] = None, **options: Any) -> None:
        self.app = app
        self.gateway = gateway or Gateway(**options)

    def __call__(self, environ: Any, start_response: Callable) -> Iterable[bytes]:
        answer = self.gateway.handle(request_from_environ(environ))
        if answer is None:
            return self.app(environ, start_response)
        body = answer.body_bytes
        headers = [(k, v) for k, v in answer.headers.items()] + [("Content-Length", str(len(body)))]
        start_response(f"{answer.status} {_REASONS.get(answer.status, '')}".strip(), headers)
        return [body]
