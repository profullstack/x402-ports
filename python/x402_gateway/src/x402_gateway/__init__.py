"""Sell crawl access to AI training crawlers, by the day, over x402.

A port of @profullstack/x402-gateway. ``Gateway.handle(request)`` takes a
:class:`Request` and returns a :class:`Response` to send, or ``None`` to let
the request through. :mod:`x402_gateway.asgi` and :mod:`x402_gateway.wsgi`
wrap it for Starlette, FastAPI, Django, Flask and anything else on either
interface.
"""

from .core import (
    METHODS,
    RETRIEVAL_AGENTS,
    TRAINING_AGENTS,
    Gateway,
    Request,
    Response,
    build_offer,
    client_ip,
    compile_cidrs,
    days_paid,
    decode_payment,
    expected_for,
    in_cidrs,
    is_spoofed_browser,
    is_training_agent,
    mint_pass,
    read_pass,
    robots_txt,
)

__all__ = [
    "METHODS",
    "RETRIEVAL_AGENTS",
    "TRAINING_AGENTS",
    "Gateway",
    "Request",
    "Response",
    "build_offer",
    "client_ip",
    "compile_cidrs",
    "days_paid",
    "decode_payment",
    "expected_for",
    "in_cidrs",
    "is_spoofed_browser",
    "is_training_agent",
    "mint_pass",
    "read_pass",
    "robots_txt",
]
__version__ = "0.1.0"
