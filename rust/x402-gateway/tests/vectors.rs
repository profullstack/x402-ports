//! Every port runs the same fixtures: spec/vectors.json, generated from the JS reference.

use http::{HeaderMap, HeaderName, HeaderValue, Request};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use x402_gateway::*;

fn vectors() -> Value {
    let p = std::env::var("X402_VECTORS")
        .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/../../spec/vectors.json").into());
    serde_json::from_str(&std::fs::read_to_string(&p).expect("vectors.json")).unwrap()
}

fn strs(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| a.iter().map(|s| s.as_str().unwrap().to_string()).collect())
        .unwrap_or_default()
}

fn headers(obj: &Value) -> HeaderMap {
    let mut h = HeaderMap::new();
    if let Some(m) = obj.as_object() {
        for (k, v) in m {
            h.append(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v.as_str().unwrap()).unwrap(),
            );
        }
    }
    h
}

struct Mock {
    verify: Value,
    settle: Option<Value>,
    settle_again: Option<Value>,
    calls: Mutex<Vec<(String, Value)>>,
}

impl Transport for Mock {
    fn post(&self, url: &str, api_key: &str, body: &str) -> (u16, String) {
        assert_eq!(api_key, "cp_live_test_secret_0123456789");
        let b: Value = serde_json::from_str(body).unwrap();
        let mut calls = self.calls.lock().unwrap();
        calls.push((url.to_string(), b));
        let settles = calls
            .iter()
            .filter(|(u, _)| u.ends_with("/api/x402/settle"))
            .count();
        let out = if url.ends_with("/api/x402/verify") {
            self.verify.clone()
        } else if settles == 1 && self.settle.is_some() {
            self.settle.clone().unwrap()
        } else {
            self.settle_again
                .clone()
                .or(self.settle.clone())
                .unwrap_or(json!({}))
        };
        (200, out.to_string())
    }
}

struct Never;
impl Transport for Never {
    fn post(&self, url: &str, _: &str, _: &str) -> (u16, String) {
        panic!("CoinPay must not be called: {url}")
    }
}

fn gateway(
    v: &Value,
    transport: Box<dyn Transport>,
    on_sale: Option<Arc<dyn Fn(Sale) + Send + Sync>>,
) -> Gateway {
    let g = &v["gateway"];
    let now = v["constants"]["NOW"].as_i64().unwrap();
    let sub = g["exempt"].as_str().unwrap().to_string();
    Gateway::new(Options {
        site_url: g["siteUrl"].as_str().unwrap().into(),
        coinpay_api_key: g["coinpay"]["apiKey"].as_str().unwrap().into(),
        pay_to: g["payTo"].as_str().unwrap().into(),
        deny_cidrs: strs(&g["denyCidrs"]),
        charge_spoofed_browsers: g["chargeSpoofedBrowsers"].as_bool().unwrap(),
        open_paths: strs(&g["openPaths"]),
        exempt: Some(Arc::new(move |h: &HeaderMap| {
            header(h, "cookie").contains(&sub)
        })),
        transport: Some(transport),
        now: Some(Arc::new(move || now)),
        on_sale,
        ..Default::default()
    })
    .unwrap()
}

#[test]
fn passes() {
    let v = vectors();
    let secret = v["constants"]["SECRET"].as_str().unwrap();
    for p in v["passes"].as_array().unwrap() {
        let got = mint_pass(
            p["secret"].as_str().unwrap(),
            p["ref"].as_str(),
            p["exp"].as_i64().unwrap(),
            p["iat"].as_i64().unwrap(),
        )
        .unwrap();
        assert_eq!(got.token, p["token"].as_str().unwrap());
    }
    for c in v["readPass"].as_array().unwrap() {
        let s = c["secret"].as_str().unwrap_or(secret);
        let r = read_pass(c["token"].as_str().unwrap(), s, c["now"].as_i64().unwrap());
        assert_eq!(r.is_some(), c["ok"].as_bool().unwrap(), "{}", c);
        if let Some(r) = r {
            assert_eq!(r.exp, c["claims"]["exp"].as_f64().unwrap());
            assert_eq!(r.r#ref, c["claims"]["ref"]);
        }
    }
}

#[test]
fn offers_and_payments() {
    let v = vectors();
    for o in v["offers"].as_array().unwrap() {
        let i = &o["in"];
        let got = build_offer(&OfferOptions {
            pay_to: i["payTo"].as_str().unwrap(),
            price_cents: i["priceCents"].as_f64().unwrap(),
            resource: i["resource"].as_str().unwrap(),
            description: i["description"].as_str().unwrap(),
            max_timeout_seconds: i["maxTimeoutSeconds"].as_u64().unwrap_or(300) as u32,
        })
        .unwrap();
        assert_eq!(serde_json::to_value(&got).unwrap(), o["out"]);
    }
    let i = &v["offers"][0]["in"];
    let offer = build_offer(&OfferOptions {
        pay_to: i["payTo"].as_str().unwrap(),
        price_cents: 100.0,
        resource: i["resource"].as_str().unwrap(),
        description: i["description"].as_str().unwrap(),
        max_timeout_seconds: 300,
    })
    .unwrap();
    for p in v["payments"].as_array().unwrap() {
        let d = decode_payment(p["header"].as_str().unwrap());
        assert_eq!(d.is_some(), p["decodes"].as_bool().unwrap(), "{}", p);
        if let Some(exp) = p.get("expected") {
            let got = d
                .as_ref()
                .and_then(|d| expected_for(d, &offer))
                .map(|e| serde_json::to_value(e).unwrap())
                .unwrap_or(Value::Null);
            assert_eq!(&got, exp, "{}", p);
        }
    }
    for d in v["daysPaid"].as_array().unwrap() {
        let val = d["value"]
            .as_str()
            .and_then(bigint_str)
            .filter(|b| b > &num_bigint::BigInt::from(0));
        assert_eq!(
            days_paid(
                val.as_ref(),
                d["unit"].as_str().unwrap(),
                d["maxDays"].as_i64().unwrap()
            ),
            d["days"].as_i64().unwrap(),
            "{}",
            d
        );
    }
}

#[test]
fn agents_edge_robots() {
    let v = vectors();
    let training: Vec<String> = TRAINING_AGENTS.iter().map(|s| s.to_string()).collect();
    for a in v["agents"].as_array().unwrap() {
        assert_eq!(
            is_training_agent(a["ua"].as_str().unwrap(), &training),
            a["training"].as_bool().unwrap(),
            "{}",
            a
        );
    }
    let c = compile_cidrs(&strs(&v["cidrs"]["list"]));
    assert_eq!(
        c.iter().map(|x| x.text.clone()).collect::<Vec<_>>(),
        strs(&v["cidrs"]["compiled"])
    );
    for k in v["cidrs"]["cases"].as_array().unwrap() {
        assert_eq!(
            in_cidrs(k["ip"].as_str().unwrap(), &c),
            k["hit"].as_bool().unwrap(),
            "{}",
            k
        );
    }
    let n = compile_cidrs(&strs(&v["cidrs"]["narrow"]["list"]));
    for k in v["cidrs"]["narrow"]["cases"].as_array().unwrap() {
        assert_eq!(
            in_cidrs(k["ip"].as_str().unwrap(), &n),
            k["hit"].as_bool().unwrap(),
            "{}",
            k
        );
    }
    for k in v["clientIp"].as_array().unwrap() {
        assert_eq!(
            client_ip(&headers(&k["headers"])),
            k["ip"].as_str().unwrap(),
            "{}",
            k
        );
    }
    for s in v["spoofs"].as_array().unwrap() {
        let mut h = headers(&s["headers"]);
        h.insert(
            "user-agent",
            HeaderValue::from_str(s["ua"].as_str().unwrap()).unwrap(),
        );
        assert_eq!(
            is_spoofed_browser(&h),
            s["spoofed"].as_bool().unwrap(),
            "{}",
            s
        );
    }
    for r in v["robots"].as_array().unwrap() {
        let i = &r["in"];
        let o = RobotsOptions {
            site_url: i["siteUrl"].as_str().unwrap().into(),
            disallow: strs(&i["disallow"]),
            allow: strs(&i["allow"]),
            sitemap: i["sitemap"].as_str().map(String::from),
            path: i["path"].as_str().map(String::from),
            refused: strs(&i["refused"]),
            training: i.get("training").map(strs),
            retrieval: i.get("retrieval").map(strs),
            comments: strs(&i["comments"]),
        };
        assert_eq!(robots_txt(&o), r["out"].as_str().unwrap());
    }
}

fn check(g: &Gateway, site: &str, c: &Value) {
    let req = Request::builder().uri(format!("{site}{}", c["url"].as_str().unwrap()));
    let mut req = req.body(()).unwrap();
    *req.headers_mut() = headers(&c["headers"]);
    let name = c["name"].as_str().unwrap();
    let a = g.handle(&req);
    if c["pass"].as_bool().unwrap_or(false) {
        assert!(
            a.is_none(),
            "{name}: expected pass-through, got {:?}",
            a.map(|r| r.status())
        );
        return;
    }
    let a = a.unwrap_or_else(|| panic!("{name}: passed through"));
    assert_eq!(
        a.status().as_u16(),
        c["status"].as_u64().unwrap() as u16,
        "{name}"
    );
    if let Some(ct) = c["contentType"].as_str() {
        assert_eq!(
            a.headers()["content-type"]
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap(),
            ct,
            "{name}"
        );
    }
    if let Some(body) = c.get("body") {
        let got: Value = serde_json::from_str(a.body()).unwrap();
        assert_eq!(&got, body, "{name}");
    }
    if let Some(t) = c["text"].as_str() {
        assert_eq!(a.body(), t, "{name}");
    }
    for s in strs(&c["htmlContains"]) {
        assert!(a.body().contains(&s), "{name}: html lacks {s}");
    }
    if let Some(h) = c["responseHeaders"].as_object() {
        for (k, val) in h {
            assert_eq!(
                a.headers()[k.as_str()].to_str().unwrap(),
                val.as_str().unwrap(),
                "{name}: {k}"
            );
        }
    }
}

#[test]
fn handle() {
    let v = vectors();
    let site = v["constants"]["SITE"].as_str().unwrap();
    let g = gateway(&v, Box::new(Never), None);
    for c in v["handle"].as_array().unwrap() {
        check(&g, site, c);
    }
    let now = v["constants"]["NOW"].as_i64().unwrap();
    let d = Gateway::new(Options {
        site_url: site.into(),
        transport: Some(Box::new(Never)),
        now: Some(Arc::new(move || now)),
        ..Default::default()
    })
    .unwrap();
    for c in v["disabled"].as_array().unwrap() {
        check(&d, site, c);
    }
    assert_eq!(
        g.robots_txt(RobotsOptions::default()),
        robots_txt(&RobotsOptions {
            site_url: site.into(),
            ..Default::default()
        })
    );
    assert!(g.page().contains("1.00 USD"));
}

#[test]
fn paid() {
    let v = vectors();
    let site = v["constants"]["SITE"].as_str().unwrap();
    let secret = v["constants"]["SECRET"].as_str().unwrap();
    let now = v["constants"]["NOW"].as_i64().unwrap();
    for c in v["coinpay"]["paid"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let sales = Arc::new(Mutex::new(0));
        let s2 = sales.clone();
        let mock = Box::new(Mock {
            verify: c["verify"].clone(),
            settle: c.get("settle").cloned(),
            settle_again: c.get("settleAgain").cloned(),
            calls: Mutex::new(vec![]),
        });
        let g = gateway(&v, mock, Some(Arc::new(move |_| *s2.lock().unwrap() += 1)));
        let proof = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            c["proof"].to_string(),
        );
        let mut req = Request::builder()
            .uri(format!("{site}/crawl"))
            .body(())
            .unwrap();
        req.headers_mut()
            .insert("x-payment", HeaderValue::from_str(&proof).unwrap());
        req.headers_mut()
            .insert("user-agent", HeaderValue::from_static("curl/8"));
        let a = g.handle(&req).unwrap();
        assert_eq!(
            a.status().as_u16(),
            c["status"].as_u64().unwrap() as u16,
            "{name}: {}",
            a.body()
        );
        let body: Value = serde_json::from_str(a.body()).unwrap();
        if a.status() == 200 {
            assert_eq!(body["ok"], true, "{name}");
            assert_eq!(body["days"], c["days"], "{name}");
            if let Some(m) = c.get("minutes") {
                assert_eq!(&body["minutes"], m, "{name}");
            }
            assert_eq!(body["replayed"], c["replayed"], "{name}");
            let claims =
                read_pass(body["pass"].as_str().unwrap(), secret, now).expect("pass reads back");
            if let Some(r) = c["ref"].as_str() {
                assert_eq!(claims.r#ref, r, "{name}");
            }
            if let Some(e) = c["expiresAt"].as_i64() {
                assert_eq!(claims.exp as i64, e, "{name}");
            }
            assert_eq!(
                a.headers()["x-crawl-pass"].to_str().unwrap(),
                body["pass"].as_str().unwrap()
            );
            assert_eq!(
                *sales.lock().unwrap(),
                if c["replayed"].as_bool().unwrap() {
                    0
                } else {
                    1
                },
                "{name}: sales"
            );
        } else {
            if let Some(e) = c["error"].as_str() {
                assert_eq!(body["error"], e, "{name}");
            }
            assert_eq!(*sales.lock().unwrap(), 0);
        }
    }
}
