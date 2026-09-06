"""Every port runs the same fixtures: spec/vectors.json, generated from the JS reference."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from x402_gateway import (  # noqa: E402
    Gateway,
    Request,
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
from x402_gateway.core import _bigint  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS = os.environ.get("X402_VECTORS") or os.path.join(HERE, "..", "..", "..", "spec", "vectors.json")
with open(VECTORS, encoding="utf-8") as f:
    V = json.load(f)
C = V["constants"]
NOW = C["NOW"]
SITE = C["SITE"]


def snake(d):
    m = {"siteUrl": "site_url", "payTo": "pay_to", "priceCents": "price_cents", "maxTimeoutSeconds": "max_timeout_seconds"}
    return {m.get(k, k): v for k, v in d.items()}


def gateway(opts, post=None, **extra):
    o = dict(opts)
    exempt_sub = o.pop("exempt", None)
    kw = {
        "site_url": o["siteUrl"],
        "coinpay_api_key": o.get("coinpay", {}).get("apiKey", ""),
        "pay_to": o.get("payTo", ""),
        "deny_cidrs": o.get("denyCidrs", ()),
        "charge_spoofed_browsers": o.get("chargeSpoofedBrowsers", False),
        "open_paths": o.get("openPaths", ()),
        "now": lambda: NOW,
        "post": post or (lambda *a: (_ for _ in ()).throw(AssertionError("CoinPay must not be called here"))),
    }
    if exempt_sub:
        kw["exempt"] = lambda r: exempt_sub in (r.header("cookie") or "")
    kw.update(extra)
    return Gateway(**kw)


def req(case):
    return Request(url=SITE + case["url"], headers={k.lower(): v for k, v in case["headers"].items()})


class Passes(unittest.TestCase):
    def test_mint(self):
        for p in V["passes"]:
            with self.subTest(ref=p["ref"]):
                self.assertEqual(mint_pass(p["secret"], p["ref"], p["exp"], p["iat"])["token"], p["token"])

    def test_read(self):
        for c in V["readPass"]:
            with self.subTest(token=c["token"][:24], why=c.get("why")):
                r = read_pass(c["token"], c.get("secret", C["SECRET"]), c["now"])
                self.assertEqual(r is not None, c["ok"])
                if c["ok"]:
                    self.assertEqual(r, c["claims"])


class Offers(unittest.TestCase):
    def test_offers(self):
        for o in V["offers"]:
            with self.subTest(price=o["in"]["priceCents"]):
                self.assertEqual(build_offer(**snake(o["in"])), o["out"])


class Payments(unittest.TestCase):
    def test_decode_and_expected(self):
        offer = V["offers"][0]["out"]
        for p in V["payments"]:
            with self.subTest(why=p.get("why")):
                d = decode_payment(p["header"])
                self.assertEqual(d is not None, p["decodes"])
                if "expected" in p:
                    self.assertEqual(expected_for(d, offer), p["expected"])

    def test_days_paid(self):
        for d in V["daysPaid"]:
            with self.subTest(value=d["value"], why=d.get("why")):
                v = None if d["value"] is None else _bigint(d["value"])
                if v is not None and v <= 0:
                    v = None
                self.assertEqual(days_paid(v, d["unit"], d["maxDays"]), d["days"])


class Agents(unittest.TestCase):
    def test_training(self):
        for a in V["agents"]:
            with self.subTest(ua=a["ua"][:40]):
                self.assertEqual(is_training_agent(a["ua"]), a["training"])


class Edge(unittest.TestCase):
    def test_cidrs(self):
        c = compile_cidrs(V["cidrs"]["list"])
        self.assertEqual([t for _, _, t in c], V["cidrs"]["compiled"])
        for k in V["cidrs"]["cases"]:
            with self.subTest(ip=k["ip"]):
                self.assertEqual(in_cidrs(k["ip"], c), k["hit"])
        n = compile_cidrs(V["cidrs"]["narrow"]["list"])
        for k in V["cidrs"]["narrow"]["cases"]:
            with self.subTest(ip=k["ip"]):
                self.assertEqual(in_cidrs(k["ip"], n), k["hit"])

    def test_client_ip(self):
        for c in V["clientIp"]:
            with self.subTest(headers=c["headers"]):
                self.assertEqual(client_ip(Request(SITE + "/", c["headers"])), c["ip"])

    def test_spoofs(self):
        for s in V["spoofs"]:
            with self.subTest(ua=s["ua"][:40]):
                h = {"user-agent": s["ua"], **s["headers"]}
                self.assertEqual(is_spoofed_browser(Request(SITE + "/", h)), s["spoofed"])


class Robots(unittest.TestCase):
    def test_robots(self):
        for r in V["robots"]:
            with self.subTest(opts=list(r["in"])):
                self.assertEqual(robots_txt(**snake(r["in"])), r["out"])


class Handle(unittest.TestCase):
    def check(self, gw, case):
        r = gw.handle(req(case))
        if case.get("pass"):
            self.assertIsNone(r, case["name"])
            return
        self.assertIsNotNone(r, case["name"])
        self.assertEqual(r.status, case["status"])
        self.assertEqual(r.headers["content-type"].split(";")[0], case["contentType"])
        if "body" in case:
            self.assertEqual(json.loads(r.body), case["body"])
        if "text" in case:
            self.assertEqual(r.body, case["text"])
        for s in case.get("htmlContains", []):
            self.assertIn(s, r.body)
        for k, v in case.get("responseHeaders", {}).items():
            self.assertEqual(r.headers.get(k), v)

    def test_handle(self):
        gw = gateway(V["gateway"])
        for case in V["handle"]:
            with self.subTest(name=case["name"]):
                self.check(gw, case)

    def test_disabled(self):
        gw = Gateway(SITE, now=lambda: NOW)
        for case in V["disabled"]:
            with self.subTest(name=case["name"]):
                r = gw.handle(req(case))
                self.assertEqual(r.status, case["status"])
                self.assertEqual(json.loads(r.body), case["body"])

    def test_robots_from_gateway(self):
        gw = gateway(V["gateway"])
        self.assertEqual(gw.robots_txt(), robots_txt(SITE))
        self.assertIn("1.00 USD", gw.render_page())


class Paid(unittest.TestCase):
    def test_paid(self):
        import base64

        cp = V["coinpay"]
        for case in cp["paid"]:
            with self.subTest(name=case["name"]):
                calls = []

                def post(url, headers, body, case=case, calls=calls):
                    calls.append((url, headers, json.loads(body)))
                    self.assertEqual(headers["x-api-key"], C["SECRET"])
                    if url.endswith(cp["verify"]["path"]):
                        return 200, json.dumps(case["verify"])
                    if url.endswith(cp["settle"]["path"]):
                        n = sum(1 for u, _, _ in calls if u.endswith(cp["settle"]["path"]))
                        if n == 1 and "settle" in case:
                            return 200, json.dumps(case["settle"])
                        return 200, json.dumps(case.get("settleAgain", case.get("settle")))
                    raise AssertionError(url)

                sales = []
                gw = gateway(V["gateway"], post=post, on_sale=sales.append)
                header = base64.b64encode(json.dumps(case["proof"]).encode()).decode()
                r = gw.handle(Request(SITE + "/crawl", {"x-payment": header, "user-agent": "curl/8"}))
                self.assertEqual(r.status, case["status"])
                body = json.loads(r.body)
                if case["status"] == 200:
                    self.assertTrue(body["ok"])
                    self.assertEqual(body["days"], case["days"])
                    if "minutes" in case:
                        self.assertEqual(body["minutes"], case["minutes"])
                    self.assertEqual(body["replayed"], case["replayed"])
                    claims = read_pass(body["pass"], C["SECRET"], NOW)
                    self.assertIsNotNone(claims)
                    if "ref" in case:
                        self.assertEqual(claims["ref"], case["ref"])
                    if "expiresAt" in case:
                        self.assertEqual(claims["exp"], case["expiresAt"])
                    self.assertEqual(r.headers["x-crawl-pass"], body["pass"])
                    self.assertEqual(len(sales), 0 if case["replayed"] else 1)
                    # verify was sent the OFFERED entry for the days paid, not the proof's claim
                    verify_body = calls[0][2]
                    self.assertEqual(verify_body["expected"]["amount"], str(1000000 * case["days"]))
                else:
                    if "error" in case:
                        self.assertEqual(body["error"], case["error"])
                    self.assertEqual(sales, [])


if __name__ == "__main__":
    unittest.main()
