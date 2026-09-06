"""The gateway, framework-free.

Everything here is a port of @profullstack/x402-gateway 0.3.0, kept close
enough that the shared fixtures in spec/vectors.json pass unchanged: the
same 402 body, the same pass format (``cp_<payload>.<hmac>``), the same
robots.txt, the same order of decisions in :meth:`Gateway.handle`.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import math
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import parse_qs, urlsplit

# --------------------------------------------------------------- agents --

#: Training-only crawlers: refused in robots.txt, charged by the gateway.
TRAINING_AGENTS: List[str] = [
    "GPTBot",
    "ClaudeBot",
    "anthropic-ai",
    "CCBot",
    "meta-externalagent",
    "FacebookBot",
    "Bytespider",
    "Applebot-Extended",
]

#: Retrieval crawlers, named in robots.txt so their operators see they are welcome.
RETRIEVAL_AGENTS: List[str] = [
    "OAI-SearchBot",
    "ChatGPT-User",
    "Claude-SearchBot",
    "Claude-User",
    "PerplexityBot",
    "Perplexity-User",
    "Google-Extended",
    "Bingbot",
]


def is_training_agent(user_agent: Optional[str], agents: Sequence[str] = TRAINING_AGENTS) -> bool:
    """Whether a user agent names one of ``agents`` (substring, case-insensitive)."""
    ua = (user_agent or "").lower()
    if not ua:
        return False
    return any(a.lower() in ua for a in agents)


# ----------------------------------------------------------------- x402 --

#: What CoinPay can settle under the ``exact`` scheme: USDC on three chains.
METHODS: List[Dict[str, str]] = [
    {"key": "usdc_base", "network": "eip155:8453", "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "label": "USDC on Base"},
    {"key": "usdc_polygon", "network": "eip155:137", "asset": "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359", "label": "USDC on Polygon"},
    {"key": "usdc_eth", "network": "eip155:1", "asset": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "label": "USDC on Ethereum"},
]
_DECIMALS = 6
_DOMAIN = {"name": "USD Coin", "version": "2"}


def build_offer(
    pay_to: str,
    price_cents: float,
    resource: str,
    description: str = "Payment required",
    max_timeout_seconds: int = 300,
    methods: Sequence[Mapping[str, str]] = METHODS,
) -> Dict[str, Any]:
    """A v2 402 body. ``amount`` is the price in the token's smallest unit, rounded up."""
    if not pay_to:
        raise ValueError("an offer needs a payTo address")
    amount = str(math.ceil((float(price_cents) / 100) * 10**_DECIMALS))
    return {
        "x402Version": 2,
        "accepts": [
            {
                "scheme": "exact",
                "network": m["network"],
                "amount": amount,
                "asset": m["asset"],
                "payTo": pay_to,
                "resource": resource,
                "description": description,
                "mimeType": "application/json",
                "maxTimeoutSeconds": max_timeout_seconds,
                "extra": dict(_DOMAIN),
            }
            for m in methods
        ],
    }


_B64_OK = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")


def _from_base64(s: str) -> str:
    """Forgiving base64 (and base64url) to text, the way ``atob`` reads it."""
    t = re.sub(r"\s+", "", str(s)).replace("-", "+").replace("_", "/")
    if len(t) % 4 == 0:
        t = t.rstrip("=") if t.endswith("==") or t.endswith("=") else t
    if len(t) % 4 == 1 or not _B64_OK.match(t):
        raise ValueError("not base64")
    t += "=" * (-len(t) % 4)
    return base64.b64decode(t, validate=True).decode("utf-8")


def decode_payment(header: Optional[str]) -> Optional[Any]:
    """The proof out of an X-PAYMENT header, or None if it is not base64 JSON."""
    if not header:
        return None
    try:
        parsed = json.loads(_from_base64(header))
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None
    return parsed if isinstance(parsed, (dict, list)) else None


def expected_for(payment: Any, offer: Mapping[str, Any]) -> Optional[Dict[str, str]]:
    """What CoinPay must hold the proof to, taken from the OFFERED entry for its network."""
    network = str(_get(payment, "network") or "").lower()
    for a in offer.get("accepts") or []:
        if str(a["network"]).lower() == network:
            return {"amount": a["amount"], "resource": a["resource"], "payTo": a["payTo"], "asset": a["asset"]}
    return None


def _get(obj: Any, *path: str) -> Any:
    for key in path:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


def nonce_of(payment: Any) -> Optional[str]:
    return _get(payment, "payload", "authorization", "nonce")


def valid_before_of(payment: Any) -> Optional[int]:
    raw = _get(payment, "payload", "authorization", "validBefore")
    try:
        v = float(raw)
    except (TypeError, ValueError):
        return None
    return int(v) if math.isfinite(v) and v > 0 else None


def _bigint(raw: Any) -> Optional[int]:
    """``BigInt(raw)`` for the shapes a proof carries: decimal or 0x hex strings, ints."""
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw
    if isinstance(raw, float):
        return int(raw) if raw.is_integer() else None
    if not isinstance(raw, str):
        return None
    s = raw.strip()
    try:
        if re.match(r"^[+-]?\d+$", s):
            return int(s)
        if re.match(r"^0[xX][0-9a-fA-F]+$", s):
            return int(s, 16)
    except ValueError:
        pass
    return None


def paid_value_of(payment: Any) -> Optional[int]:
    """The value a proof authorizes, in the token's smallest unit, or None."""
    raw = _get(payment, "payload", "authorization", "value")
    if raw is None or raw == "":
        return None
    v = _bigint(raw)
    return v if v is not None and v > 0 else None


def days_paid(value: Optional[int], unit: Any, max_days: int) -> int:
    """How many terms ``value`` buys at ``unit`` per term: a whole number in [1, max_days], else 0."""
    if value is None:
        return 0
    per = _bigint(unit)
    if per is None or per <= 0 or value % per != 0:
        return 0
    days = value // per
    if days < 1 or days > max_days:
        return 0
    return int(days)


# --------------------------------------------------------------- passes --


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _unb64url(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _sign(secret: str, data: str) -> str:
    return _b64url(hmac.new(secret.encode("utf-8"), data.encode("utf-8"), hashlib.sha256).digest())


def mint_pass(secret: str, ref: Optional[str], expires_at: int, now: Optional[int] = None) -> Dict[str, Any]:
    """Mint a pass: ``{"token", "expires_at", "ref"}``."""
    if now is None:
        now = int(time.time())
    if not secret:
        raise ValueError("a pass needs a signing secret")
    if expires_at is None or expires_at <= now:
        raise ValueError("a pass needs a future expiry")
    claims = {"v": 1, "iat": now, "exp": int(expires_at), "ref": ref}
    payload = _b64url(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
    return {"token": f"cp_{payload}.{_sign(secret, payload)}", "expires_at": int(expires_at), "ref": ref}


def read_pass(token: Any, secret: str, now: Optional[int] = None) -> Optional[Dict[str, Any]]:
    """``{"exp", "iat", "ref"}`` when the signature holds and the pass is live, else None. Never raises."""
    if now is None:
        now = int(time.time())
    if not secret or not isinstance(token, str) or not token.startswith("cp_"):
        return None
    dot = token.find(".")
    if dot < 0:
        return None
    payload, sig = token[3:dot], token[dot + 1 :]
    if not payload or not sig:
        return None
    try:
        if not hmac.compare_digest(_sign(secret, payload), sig):
            return None
        claims = json.loads(_unb64url(payload).decode("utf-8"))
        if not isinstance(claims, dict) or claims.get("v") != 1:
            return None
        exp = claims.get("exp")
        if isinstance(exp, bool) or not isinstance(exp, (int, float)) or not math.isfinite(exp):
            return None
        if exp <= now:
            return None
        return {"exp": exp, "iat": claims.get("iat"), "ref": claims.get("ref")}
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None


# ----------------------------------------------------------------- edge --


def _ipv4_to_int(ip: str) -> Optional[int]:
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    n = 0
    for p in parts:
        if not re.match(r"^\d{1,3}$", p):
            return None
        v = int(p)
        if v > 255:
            return None
        n = n * 256 + v
    return n


def parse_cidr(cidr: str) -> Optional[Tuple[int, int, str]]:
    """``(base, mask, text)`` for "a.b.c.d/len" or a bare address; None if unreadable."""
    ip, _, len_raw = str(cidr).strip().partition("/")
    base = _ipv4_to_int(ip)
    if base is None:
        return None
    if len_raw == "" and "/" not in str(cidr):
        length = 32
    else:
        if not re.match(r"^\d+$", len_raw):
            return None
        length = int(len_raw)
        if length > 32:
            return None
    mask = 0 if length == 0 else (0xFFFFFFFF << (32 - length)) & 0xFFFFFFFF
    return (base & mask, mask, f"{ip}/{length}")


def compile_cidrs(cidrs: Iterable[str]) -> List[Tuple[int, int, str]]:
    """Compile a denylist once. Unreadable entries are dropped, not guessed at."""
    return [c for c in (parse_cidr(x) for x in cidrs) if c is not None]


def in_cidrs(ip: Optional[str], compiled: Sequence[Tuple[int, int, str]]) -> bool:
    n = _ipv4_to_int(str(ip or "").strip())
    if n is None:
        return False
    return any((n & mask) == base for base, mask, _ in compiled)


def client_ip(request: "Request") -> str:
    """The caller's address as the edge reported it: x-real-ip, else the LAST x-forwarded-for hop."""
    real = (request.header("x-real-ip") or "").strip()
    if real:
        return real
    xff = request.header("x-forwarded-for")
    if not xff:
        return ""
    hops = [h.strip() for h in xff.split(",") if h.strip()]
    return hops[-1] if hops else ""


_CLAIMS_CHROMIUM = re.compile(r"\bChrome/\d+")
_DECLARES_ITSELF = re.compile(r"compatible;|\bbot\b|bot/|crawler|spider|slurp", re.I)


def is_spoofed_browser(request: "Request") -> bool:
    """Claims Chromium, declares no crawler, and sends no Sec-Fetch-Mode: an HTTP client with a copied string."""
    ua = request.header("user-agent") or ""
    if not _CLAIMS_CHROMIUM.search(ua):
        return False
    if _DECLARES_ITSELF.search(ua):
        return False
    return request.header("sec-fetch-mode") is None


# --------------------------------------------------------------- robots --


def robots_txt(
    site_url: str,
    disallow: Sequence[str] = (),
    allow: Sequence[str] = (),
    sitemap: Optional[str] = None,
    path: str = "/crawl",
    refused: Sequence[str] = (),
    training: Sequence[str] = TRAINING_AGENTS,
    retrieval: Sequence[str] = RETRIEVAL_AGENTS,
    comments: Sequence[str] = (),
) -> str:
    """robots.txt with the crawlers sorted the way the gateway sorts them."""
    if not site_url:
        raise ValueError("robots_txt needs site_url")
    base = site_url.rstrip("/")
    sitemap_line = f"{base}/sitemap.xml" if sitemap is None else sitemap

    def welcome(agent: str) -> str:
        return "\n".join([f"User-agent: {agent}", "Allow: /", *[f"Allow: {p}" for p in allow], *[f"Disallow: {p}" for p in disallow]])

    def refuse(agent: str) -> str:
        return f"User-agent: {agent}\nDisallow: /"

    def charge(agent: str) -> str:
        return f"{refuse(agent)}\nAllow: {path}"

    lines: List[str] = [
        *[f"# {c}" for c in comments],
        *([""] if comments else []),
        *[f"{refuse(a)}\n" for a in refused],
        *[f"{charge(a)}\n" for a in training],
        *[f"{welcome(a)}\n" for a in retrieval],
        welcome("*"),
        "",
    ]
    if sitemap_line:
        lines += [f"Sitemap: {sitemap_line}", ""]
    return "\n".join(lines)


# ------------------------------------------------------------- requests --


@dataclass
class Request:
    """The little the gateway needs to know about a request.

    ``url`` is absolute. ``headers`` maps lower-cased names to values; a
    multi-valued header is joined with ", " the way Fetch does.
    """

    url: str
    headers: Mapping[str, str] = field(default_factory=dict)
    method: str = "GET"

    def header(self, name: str) -> Optional[str]:
        return self.headers.get(name.lower())

    @property
    def path(self) -> str:
        return urlsplit(self.url).path or "/"

    def query(self, name: str) -> Optional[str]:
        values = parse_qs(urlsplit(self.url).query, keep_blank_values=True).get(name)
        return values[0] if values else None


@dataclass
class Response:
    status: int
    headers: Dict[str, str]
    body: str

    @property
    def body_bytes(self) -> bytes:
        return self.body.encode("utf-8")


#: ``post(url, headers, body_text) -> (status, body_text)``
Poster = Callable[[str, Mapping[str, str], str], Tuple[int, str]]


def _urllib_post(url: str, headers: Mapping[str, str], body: str) -> Tuple[int, str]:
    import urllib.error
    import urllib.request

    req = urllib.request.Request(url, data=body.encode("utf-8"), headers=dict(headers), method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as res:  # noqa: S310 (a fixed https host)
            return res.status, res.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def verify_and_settle(payment: Any, expected: Mapping[str, str], api_key: str, base_url: str, post: Poster) -> Dict[str, Any]:
    """Verify, then settle. ``{"ok": True, "payer", "ref"}`` or ``{"ok": False, "reason", "replay"}``."""

    def call(path: str, body: Any) -> Tuple[int, Dict[str, Any]]:
        status, text = post(f"{base_url}{path}", {"content-type": "application/json", "x-api-key": api_key}, json.dumps(body))
        try:
            data = json.loads(text)
        except ValueError:
            data = {}
        return status, data if isinstance(data, dict) else {}

    vs, v = call("/api/x402/verify", {"payment": payment, "expected": expected})
    if not v.get("valid"):
        reason = str(v.get("error", v.get("reason", f"verify failed ({vs})")))
        return {"ok": False, "reason": reason, "replay": bool(re.search(r"already used|replay", reason, re.I))}
    ss, s = call("/api/x402/settle", {"payment": payment})
    if not s.get("settled"):
        reason = str(s.get("error", f"settle failed ({ss})"))
        return {"ok": False, "reason": reason, "replay": bool(re.search(r"already settled|already being settled", reason, re.I))}
    return {"ok": True, "payer": _get(v, "payment", "from"), "ref": s.get("txHash") or nonce_of(payment)}


def settle_again(payment: Any, api_key: str, base_url: str, post: Poster) -> bool:
    """Whether the proof has already been paid, when a settle is asked about twice."""
    _, text = post(f"{base_url}/api/x402/settle", {"content-type": "application/json", "x-api-key": api_key}, json.dumps({"payment": payment}))
    try:
        data = json.loads(text)
    except ValueError:
        data = {}
    if not isinstance(data, dict):
        data = {}
    return bool(data.get("settled")) or bool(re.search(r"already settled", str(data.get("error", "")), re.I))


def wants_html(accept: Optional[str]) -> bool:
    return "text/html" in str(accept or "").lower()


def _iso(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


_BEARER = re.compile(r"^Bearer\s+(cp_[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$", re.I)
_LEADING_INT = re.compile(r"^\s*([+-]?\d+)")


class Gateway:
    """A gateway that sells crawl access to training crawlers, by the day, over x402.

    :param site_url: canonical origin, no trailing slash
    :param coinpay_api_key: a SCOPED CoinPay key (``cp_live_…``) with ``payments:create``
    :param pay_to: EVM address that receives the USDC
    :param price_cents: default 100
    :param pass_minutes: the term one payment buys, default 1440
    :param max_days: the most terms one proof may buy at once, default 30
    :param header: where the pass goes, default ``x-crawl-pass``
    :param path: the sales page, default ``/crawl``
    :param open_paths: extra paths a refused crawler may read
    :param is_paid_agent: ``(user_agent) -> bool``; default: the training list
    :param deny_cidrs: IPv4 ranges answered 403 before anything else
    :param charge_spoofed_browsers: charge a "Chrome/…" request that lacks Sec-Fetch-Mode
    :param exempt: ``(request) -> bool``, never charged (e.g. carries your session cookie)
    :param secret: pass signing secret; defaults to the CoinPay key
    :param page: ``(ctx) -> html``, a custom sales page
    :param contact: mailto: or URL for bulk deals
    :param on_sale: ``(sale_dict) -> None``, accounting hook; an exception here never costs a buyer the pass
    :param post: ``(url, headers, body) -> (status, text)``, for tests
    :param now: ``() -> int`` unix seconds, for tests
    """

    def __init__(
        self,
        site_url: str,
        *,
        site_name: Optional[str] = None,
        coinpay_api_key: str = "",
        coinpay_base_url: str = "https://coinpayportal.com",
        pay_to: str = "",
        price_cents: float = 100,
        currency: str = "USD",
        pass_minutes: int = 1440,
        max_days: int = 30,
        header: str = "x-crawl-pass",
        path: str = "/crawl",
        open_paths: Sequence[str] = (),
        is_paid_agent: Optional[Callable[[str], bool]] = None,
        deny_cidrs: Sequence[str] = (),
        charge_spoofed_browsers: bool = False,
        exempt: Optional[Callable[[Request], bool]] = None,
        secret: str = "",
        training: Sequence[str] = TRAINING_AGENTS,
        retrieval: Sequence[str] = RETRIEVAL_AGENTS,
        page: Optional[Callable[[Dict[str, Any]], str]] = None,
        contact: str = "",
        on_sale: Optional[Callable[[Dict[str, Any]], None]] = None,
        post: Poster = _urllib_post,
        now: Callable[[], int] = lambda: int(time.time()),
    ) -> None:
        site_url = str(site_url or "").rstrip("/")
        if not site_url:
            raise ValueError("Gateway needs site_url")
        self.site_url = site_url
        self.site_name = site_name or urlsplit(site_url).hostname or site_url
        self.coinpay_api_key = coinpay_api_key or ""
        self.coinpay_base_url = (coinpay_base_url or "https://coinpayportal.com").rstrip("/")
        self.pay_to = pay_to or ""
        self.price_cents = price_cents if isinstance(price_cents, (int, float)) and math.isfinite(price_cents) else 100
        self.currency = currency
        self.pass_minutes = pass_minutes if isinstance(pass_minutes, int) and pass_minutes > 0 else 1440
        self.max_days = max_days if isinstance(max_days, int) and max_days >= 1 else 30
        self.header = str(header or "x-crawl-pass").lower()
        self.path = path or "/crawl"
        self.open_paths = list(open_paths or ())
        self.deny_cidrs = list(deny_cidrs or ())
        self.charge_spoofed_browsers = bool(charge_spoofed_browsers)
        self.exempt = exempt
        self.training = list(training)
        self.retrieval = list(retrieval)
        self.is_paid_agent = is_paid_agent or (lambda ua: is_training_agent(ua, self.training))
        self.contact = contact or ""
        self.on_sale = on_sale
        self.post = post
        self.now = now
        if page is None:
            from .page import render_page

            page = render_page
        self.page = page

        self.enabled = bool(self.coinpay_api_key and self.pay_to)
        self.secret = secret or self.coinpay_api_key or ""
        self._open = ["/robots.txt", self.path, "/security.txt", "/.well-known/", *self.open_paths]
        self._denied = compile_cidrs(self.deny_cidrs)
        self.buy_url = f"{self.site_url}{self.path}"

    # -- pieces ----------------------------------------------------------

    def money(self, cents: float) -> str:
        return f"{cents / 100:.2f} {self.currency}"

    @property
    def price(self) -> str:
        return self.money(self.price_cents)

    def _is_open(self, path: str) -> bool:
        return any(path.startswith(p) if p.endswith("/") else path == p for p in self._open)

    def _days_from(self, request: Request) -> int:
        m = _LEADING_INT.match(request.query("days") or "")
        n = int(m.group(1)) if m else 0
        if n < 1:
            return 1
        return min(n, self.max_days)

    def offer(self, days: int = 1) -> Dict[str, Any]:
        """The offer for ``days`` terms: the same entries, ``days`` times the price."""
        if not self.enabled:
            return {"x402Version": 2, "accepts": []}
        extra = f" ({days} × {self.pass_minutes})" if days > 1 else ""
        return build_offer(
            pay_to=self.pay_to,
            price_cents=self.price_cents * days,
            resource=self.buy_url,
            description=f"{days * self.pass_minutes} minutes of crawl access to {self.site_url}{extra}",
        )

    def receipt(self, days: int = 1, **extra: Any) -> Dict[str, Any]:
        body = dict(self.offer(days))
        body["pass"] = {
            "price": self.price,
            "minutes": self.pass_minutes,
            "days": days,
            "total": self.money(self.price_cents * days),
            "maxDays": self.max_days,
            "header": self.header,
            "buy": f"{self.buy_url}?days={days}" if days > 1 else self.buy_url,
            "buyDays": f"{self.buy_url}?days=<n>",
        }
        body.update(extra)
        return body

    _NO_STORE = {"cache-control": "no-store", "vary": "Accept, User-Agent, X-Payment"}

    def _json(self, body: Any, status: int, headers: Optional[Mapping[str, str]] = None) -> Response:
        h = {"content-type": "application/json; charset=utf-8", **self._NO_STORE, **(headers or {})}
        return Response(status, h, json.dumps(body, indent=2, ensure_ascii=False))

    def _html(self, body: str, status: int) -> Response:
        return Response(status, {"content-type": "text/html; charset=utf-8", **self._NO_STORE}, body)

    def page_ctx(self, days: int = 1) -> Dict[str, Any]:
        return {
            "days": days,
            "total": self.money(self.price_cents * days),
            "site_name": self.site_name,
            "site_url": self.site_url,
            "buy_url": self.buy_url,
            "price": self.price,
            "minutes": self.pass_minutes,
            "max_days": self.max_days,
            "header": self.header,
            "enabled": self.enabled,
            "offer": self.offer(),
            "training": self.training,
            "retrieval": self.retrieval,
            "contact": self.contact,
        }

    def robots_txt(self, **extra: Any) -> str:
        """robots.txt with this gateway's lists and sales path."""
        opts: Dict[str, Any] = {"site_url": self.site_url, "path": self.path, "training": self.training, "retrieval": self.retrieval}
        opts.update(extra)
        return robots_txt(**opts)

    def render_page(self) -> str:
        """The sales page as HTML, for a site that mounts it on a route of its own."""
        return self.page(self.page_ctx())

    def _pass_from(self, request: Request) -> Optional[str]:
        direct = request.header(self.header)
        if direct:
            return direct.strip()
        m = _BEARER.match(request.header("authorization") or "")
        return m.group(1) if m else None

    # -- the sale ---------------------------------------------------------

    def sell(self, request: Request) -> Response:
        """Answer one request with the sale: a pass as the body of a 200, or a 402 with the offer."""
        ua = request.header("user-agent") or ""
        proof_header = request.header("x-payment")
        asked = self._days_from(request)

        if proof_header:
            if not self.enabled:
                return self._json(self.receipt(asked, error="Payments are not switched on here."), 402)
            payment = decode_payment(proof_header)
            if payment is None:
                return self._json(self.receipt(asked, error="X-PAYMENT is not base64 JSON."), 402)
            unit = expected_for(payment, self.offer(1))
            if unit is None:
                return self._json(self.receipt(asked, error="Proof does not match an offered network."), 402)
            days = days_paid(paid_value_of(payment), unit["amount"], self.max_days)
            if not days:
                return self._json(
                    self.receipt(
                        asked,
                        error=f"Pay a whole number of days: {unit['amount']} per day in the token's smallest unit, up to {self.max_days} days. Add ?days=<n> to {self.buy_url} for the offer.",
                    ),
                    402,
                )
            expected = expected_for(payment, self.offer(days)) or unit
            term = days * self.pass_minutes * 60
            now = int(self.now())
            result = verify_and_settle(payment, expected, self.coinpay_api_key, self.coinpay_base_url, self.post)

            expires_at: Optional[int] = None
            replayed = False
            if result["ok"]:
                expires_at = now + term
            elif result.get("replay"):
                paid = settle_again(payment, self.coinpay_api_key, self.coinpay_base_url, self.post)
                valid_before = valid_before_of(payment)
                if paid and valid_before:
                    expires_at = min(now + term, valid_before + term)
                    replayed = True
            if not expires_at or expires_at <= now:
                return self._json(self.receipt(days, error=result.get("reason") or "Payment could not be settled."), 402)

            ref = nonce_of(payment) or result.get("ref")
            minted = mint_pass(self.secret, ref, expires_at, now)
            expires = _iso(minted["expires_at"])
            if self.on_sale and not replayed:
                try:
                    self.on_sale(
                        {
                            "payer": result.get("payer"),
                            "ref": ref,
                            "token": minted["token"],
                            "expires_at": expires,
                            "user_agent": ua,
                            "price_cents": self.price_cents,
                            "days": days,
                            "total_cents": self.price_cents * days,
                            "currency": self.currency,
                        }
                    )
                except Exception:  # noqa: BLE001 - accounting must never cost a buyer the pass
                    pass
            return self._json(
                {
                    "ok": True,
                    "pass": minted["token"],
                    "expires_at": expires,
                    "days": days,
                    "minutes": days * self.pass_minutes,
                    "header": self.header,
                    "replayed": replayed,
                    "use": f'curl -H "{self.header}: {minted["token"]}" {self.site_url}/',
                },
                200,
                {self.header: minted["token"], f"{self.header}-expires": expires},
            )

        if wants_html(request.header("accept")):
            return self._html(self.page(self.page_ctx(asked)), 402)
        return self._json(self.receipt(asked, error=f"Payment required for training crawlers. Read {self.buy_url} for how."), 402)

    # -- the gate ---------------------------------------------------------

    def handle(self, request: Request) -> Optional[Response]:
        """The gate. None means "not for me, carry on"."""
        if self._denied and in_cidrs(client_ip(request), self._denied):
            return Response(403, {"content-type": "text/plain; charset=utf-8", **self._NO_STORE}, "Not available from this network.\n")

        path = request.path
        if path == self.path:
            return self.sell(request)
        if self.exempt is not None and self.exempt(request):
            return None
        pays = self.is_paid_agent(request.header("user-agent") or "") or (self.charge_spoofed_browsers and is_spoofed_browser(request))
        if not pays:
            return None
        if self._is_open(path):
            return None
        token = self._pass_from(request)
        if token and read_pass(token, self.secret, int(self.now())) is not None:
            return None
        return self.sell(request)

    def needs_io(self, request: Request) -> bool:
        """Whether handling this request may call CoinPay (only a proof does). For async adapters."""
        return request.header("x-payment") is not None
