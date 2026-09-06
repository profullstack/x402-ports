//! Sell crawl access to AI training crawlers, by the day, over x402, settled by CoinPay.
//!
//! A port of `@profullstack/x402-gateway`: the same 402 body, the same signed
//! pass (`cp_<payload>.<hmac>`), the same robots.txt, the same order of
//! decisions, checked against the same fixtures.
//!
//! [`Gateway::handle`] takes an [`http::Request`] and returns an
//! [`http::Response<String>`] to send, or `None` to let the request through.
//! With the `axum` feature, [`axum::gate`] is a ready middleware.

use base64::Engine;
use hmac::{Hmac, Mac};
use http::{HeaderMap, Request, Response};
use num_bigint::BigInt;
use num_traits::{FromPrimitive, Signed, ToPrimitive, Zero};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::Sha256;
use std::sync::Arc;

// ------------------------------------------------------------------ agents --

/// Training-only crawlers: refused in robots.txt, charged by the gateway.
pub const TRAINING_AGENTS: &[&str] = &[
    "GPTBot",
    "ClaudeBot",
    "anthropic-ai",
    "CCBot",
    "meta-externalagent",
    "FacebookBot",
    "Bytespider",
    "Applebot-Extended",
];

/// Retrieval crawlers, named in robots.txt so their operators can see they are welcome.
pub const RETRIEVAL_AGENTS: &[&str] = &[
    "OAI-SearchBot",
    "ChatGPT-User",
    "Claude-SearchBot",
    "Claude-User",
    "PerplexityBot",
    "Perplexity-User",
    "Google-Extended",
    "Bingbot",
];

/// Whether a user agent names one of `agents` (substring, case-insensitive).
pub fn is_training_agent(user_agent: &str, agents: &[String]) -> bool {
    let ua = user_agent.to_lowercase();
    if ua.is_empty() {
        return false;
    }
    agents.iter().any(|a| ua.contains(&a.to_lowercase()))
}

fn owned(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

// -------------------------------------------------------------------- x402 --

/// One way CoinPay can settle under the `exact` scheme: USDC on one chain.
pub struct Method {
    pub key: &'static str,
    pub network: &'static str,
    pub asset: &'static str,
    pub label: &'static str,
}

/// USDC on Base, Polygon and Ethereum, Base first.
pub const METHODS: &[Method] = &[
    Method {
        key: "usdc_base",
        network: "eip155:8453",
        asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        label: "USDC on Base",
    },
    Method {
        key: "usdc_polygon",
        network: "eip155:137",
        asset: "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359",
        label: "USDC on Polygon",
    },
    Method {
        key: "usdc_eth",
        network: "eip155:1",
        asset: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        label: "USDC on Ethereum",
    },
];

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Domain {
    pub name: String,
    pub version: String,
}

/// One entry of an x402 v2 offer.
#[derive(Clone, Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Accept {
    pub scheme: String,
    pub network: String,
    pub amount: String,
    pub asset: String,
    pub pay_to: String,
    pub resource: String,
    pub description: String,
    pub mime_type: String,
    pub max_timeout_seconds: u32,
    pub extra: Domain,
}

/// An x402 v2 402 body.
#[derive(Clone, Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Offer {
    pub x402_version: u8,
    pub accepts: Vec<Accept>,
}

/// Builds [`Offer`]s. `amount` is the price in the token's smallest unit, rounded up.
pub struct OfferOptions<'a> {
    pub pay_to: &'a str,
    pub price_cents: f64,
    pub resource: &'a str,
    pub description: &'a str,
    pub max_timeout_seconds: u32,
}

pub fn build_offer(o: &OfferOptions) -> Result<Offer, String> {
    if o.pay_to.is_empty() {
        return Err("an offer needs a payTo address".into());
    }
    let amount = ((o.price_cents / 100.0) * 1_000_000f64).ceil() as i64;
    Ok(Offer {
        x402_version: 2,
        accepts: METHODS
            .iter()
            .map(|m| Accept {
                scheme: "exact".into(),
                network: m.network.into(),
                amount: amount.to_string(),
                asset: m.asset.into(),
                pay_to: o.pay_to.into(),
                resource: o.resource.into(),
                description: o.description.into(),
                mime_type: "application/json".into(),
                max_timeout_seconds: o.max_timeout_seconds,
                extra: Domain {
                    name: "USD Coin".into(),
                    version: "2".into(),
                },
            })
            .collect(),
    })
}

/// base64 or base64url to bytes, the forgiving way `atob` reads it.
fn from_base64(s: &str) -> Option<Vec<u8>> {
    let mut t: String = s
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            c => c,
        })
        .collect();
    if t.len() % 4 == 0 {
        while t.ends_with('=') {
            t.pop();
        }
    }
    if t.len() % 4 == 1
        || !t
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/')
    {
        return None;
    }
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(t)
        .ok()
}

/// The proof out of an X-PAYMENT header: a JSON object or array, else None.
pub fn decode_payment(header: &str) -> Option<Value> {
    if header.is_empty() {
        return None;
    }
    let raw = from_base64(header)?;
    let v: Value = serde_json::from_slice(&raw).ok()?;
    if v.is_object() || v.is_array() {
        Some(v)
    } else {
        None
    }
}

/// What CoinPay must hold a proof to, taken from the offered entry for its network.
#[derive(Clone, Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Expected {
    pub amount: String,
    pub resource: String,
    pub pay_to: String,
    pub asset: String,
}

fn value_str(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}

pub fn expected_for(payment: &Value, offer: &Offer) -> Option<Expected> {
    let network = value_str(payment.get("network")).to_lowercase();
    offer
        .accepts
        .iter()
        .find(|a| a.network.to_lowercase() == network)
        .map(|a| Expected {
            amount: a.amount.clone(),
            resource: a.resource.clone(),
            pay_to: a.pay_to.clone(),
            asset: a.asset.clone(),
        })
}

pub fn nonce_of(payment: &Value) -> Option<String> {
    match payment.pointer("/payload/authorization/nonce") {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Number(n)) => Some(n.to_string()),
        _ => None,
    }
}

pub fn valid_before_of(payment: &Value) -> Option<i64> {
    let v = value_str(payment.pointer("/payload/authorization/validBefore"));
    let f: f64 = v.trim().parse().ok()?;
    if f.is_finite() && f > 0.0 {
        Some(f as i64)
    } else {
        None
    }
}

/// What `BigInt(raw)` would read: decimal or 0x strings, whole numbers.
pub fn bigint(raw: &Value) -> Option<BigInt> {
    match raw {
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                return Some(BigInt::from(i));
            }
            if let Some(u) = n.as_u64() {
                return Some(BigInt::from(u));
            }
            let f = n.as_f64()?;
            if f.fract() != 0.0 {
                return None;
            }
            BigInt::from_f64(f)
        }
        Value::String(s) => bigint_str(s),
        _ => None,
    }
}

pub fn bigint_str(s: &str) -> Option<BigInt> {
    let s = s.trim();
    let body = s
        .strip_prefix('+')
        .or_else(|| s.strip_prefix('-'))
        .unwrap_or(s);
    if !body.is_empty() && body.chars().all(|c| c.is_ascii_digit()) {
        return s.parse().ok();
    }
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        if !h.is_empty() && h.chars().all(|c| c.is_ascii_hexdigit()) {
            return BigInt::parse_bytes(h.as_bytes(), 16);
        }
    }
    None
}

/// The value a proof authorizes, in the token's smallest unit, or None.
pub fn paid_value_of(payment: &Value) -> Option<BigInt> {
    let raw = payment.pointer("/payload/authorization/value")?;
    if raw.is_null() || raw == "" {
        return None;
    }
    let v = bigint(raw)?;
    if v.is_positive() {
        Some(v)
    } else {
        None
    }
}

/// How many terms `value` buys at `unit` per term: a whole number in [1, max_days], else 0.
pub fn days_paid(value: Option<&BigInt>, unit: &str, max_days: i64) -> i64 {
    let Some(value) = value else { return 0 };
    let Some(per) = bigint_str(unit) else {
        return 0;
    };
    if !per.is_positive() || !(value % &per).is_zero() {
        return 0;
    }
    let days = value / &per;
    if days < BigInt::from(1) || days > BigInt::from(max_days) {
        return 0;
    }
    days.to_i64().unwrap_or(0)
}

/// How the gateway reaches CoinPay. Implement it to mock CoinPay in tests.
pub trait Transport: Send + Sync {
    /// POST JSON; returns (status, body). A transport error is (0, "").
    fn post(&self, url: &str, api_key: &str, body: &str) -> (u16, String);
}

#[cfg(feature = "ureq")]
pub struct Ureq;

#[cfg(feature = "ureq")]
impl Transport for Ureq {
    fn post(&self, url: &str, api_key: &str, body: &str) -> (u16, String) {
        let res = ureq::post(url)
            .timeout(std::time::Duration::from_secs(20))
            .set("content-type", "application/json")
            .set("x-api-key", api_key)
            .send_string(body);
        match res {
            Ok(r) => (r.status(), r.into_string().unwrap_or_default()),
            Err(ureq::Error::Status(code, r)) => (code, r.into_string().unwrap_or_default()),
            Err(_) => (0, String::new()),
        }
    }
}

struct NoTransport;
impl Transport for NoTransport {
    fn post(&self, _: &str, _: &str, _: &str) -> (u16, String) {
        (0, String::new())
    }
}

pub struct Settlement {
    pub ok: bool,
    pub payer: Option<String>,
    pub r#ref: Option<String>,
    pub reason: Option<String>,
    pub replay: bool,
}

fn contains_ci(hay: &str, needles: &[&str]) -> bool {
    let h = hay.to_lowercase();
    needles.iter().any(|n| h.contains(n))
}

fn parse_obj(text: &str) -> serde_json::Map<String, Value> {
    match serde_json::from_str::<Value>(text) {
        Ok(Value::Object(m)) => m,
        _ => Default::default(),
    }
}

fn truthy(v: Option<&Value>) -> bool {
    match v {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Number(n)) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Some(Value::Null) | None => false,
        Some(_) => true,
    }
}

fn first_string(m: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|k| {
        m.get(*k).filter(|v| !v.is_null()).map(|v| match v {
            Value::String(s) => s.clone(),
            v => v.to_string(),
        })
    })
}

/// Verify, then settle. Two calls because verify moves no money.
pub fn verify_and_settle(
    t: &dyn Transport,
    api_key: &str,
    base_url: &str,
    payment: &Value,
    expected: &Expected,
) -> Settlement {
    let (vs, vt) = t.post(
        &format!("{base_url}/api/x402/verify"),
        api_key,
        &json!({"payment": payment, "expected": expected}).to_string(),
    );
    let v = parse_obj(&vt);
    if !truthy(v.get("valid")) {
        let reason = first_string(&v, &["error", "reason"])
            .unwrap_or_else(|| format!("verify failed ({vs})"));
        let replay = contains_ci(&reason, &["already used", "replay"]);
        return Settlement {
            ok: false,
            payer: None,
            r#ref: None,
            reason: Some(reason),
            replay,
        };
    }
    let (ss, st) = t.post(
        &format!("{base_url}/api/x402/settle"),
        api_key,
        &json!({"payment": payment}).to_string(),
    );
    let s = parse_obj(&st);
    if !truthy(s.get("settled")) {
        let reason =
            first_string(&s, &["error"]).unwrap_or_else(|| format!("settle failed ({ss})"));
        let replay = contains_ci(&reason, &["already settled", "already being settled"]);
        return Settlement {
            ok: false,
            payer: None,
            r#ref: None,
            reason: Some(reason),
            replay,
        };
    }
    let payer = v
        .get("payment")
        .and_then(|p| p.get("from"))
        .and_then(|f| f.as_str())
        .map(String::from);
    let r#ref = first_string(&s, &["txHash"])
        .filter(|s| !s.is_empty())
        .or_else(|| nonce_of(payment));
    Settlement {
        ok: true,
        payer,
        r#ref,
        reason: None,
        replay: false,
    }
}

/// Whether the proof has already been paid, when a settle is asked about twice.
pub fn settle_again(t: &dyn Transport, api_key: &str, base_url: &str, payment: &Value) -> bool {
    let (_, st) = t.post(
        &format!("{base_url}/api/x402/settle"),
        api_key,
        &json!({"payment": payment}).to_string(),
    );
    let s = parse_obj(&st);
    truthy(s.get("settled"))
        || contains_ci(
            &first_string(&s, &["error"]).unwrap_or_default(),
            &["already settled"],
        )
}

// ------------------------------------------------------------------ passes --

type HmacSha256 = Hmac<Sha256>;

fn b64url(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn sign(secret: &str, data: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("hmac accepts any key length");
    mac.update(data.as_bytes());
    b64url(&mac.finalize().into_bytes())
}

#[derive(Clone, Debug)]
pub struct Pass {
    pub token: String,
    pub expires_at: i64,
    pub r#ref: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Claims {
    pub exp: f64,
    pub iat: Value,
    pub r#ref: Value,
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Mint a pass. `now` is unix seconds.
pub fn mint_pass(
    secret: &str,
    r#ref: Option<&str>,
    expires_at: i64,
    now: i64,
) -> Result<Pass, String> {
    if secret.is_empty() {
        return Err("a pass needs a signing secret".into());
    }
    if expires_at <= now {
        return Err("a pass needs a future expiry".into());
    }
    let claims = json!({"v": 1, "iat": now, "exp": expires_at, "ref": r#ref});
    // serde_json keeps insertion order only with preserve_order; write the four keys by hand.
    let text = format!(
        "{{\"v\":1,\"iat\":{},\"exp\":{},\"ref\":{}}}",
        now, expires_at, claims["ref"]
    );
    let payload = b64url(text.as_bytes());
    Ok(Pass {
        token: format!("cp_{payload}.{}", sign(secret, &payload)),
        expires_at,
        r#ref: r#ref.map(String::from),
    })
}

/// The claims when the signature holds and the pass is live, else None. Never panics on garbage.
pub fn read_pass(token: &str, secret: &str, now: i64) -> Option<Claims> {
    if secret.is_empty() || !token.starts_with("cp_") {
        return None;
    }
    let dot = token.find('.')?;
    let (payload, sig) = (&token[3..dot], &token[dot + 1..]);
    if payload.is_empty() || sig.is_empty() {
        return None;
    }
    let expect = sign(secret, payload);
    let mut diff = (expect.len() != sig.len()) as u8;
    for (a, b) in expect.bytes().zip(sig.bytes()) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return None;
    }
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .ok()?;
    let claims: Value = serde_json::from_slice(&raw).ok()?;
    if claims.get("v").and_then(|v| v.as_f64()) != Some(1.0) {
        return None;
    }
    let exp = claims.get("exp").and_then(|e| e.as_f64())?;
    if !exp.is_finite() || exp <= now as f64 {
        return None;
    }
    Some(Claims {
        exp,
        iat: claims.get("iat").cloned().unwrap_or(Value::Null),
        r#ref: claims.get("ref").cloned().unwrap_or(Value::Null),
    })
}

// -------------------------------------------------------------------- edge --

#[derive(Clone, Debug, PartialEq)]
pub struct Cidr {
    pub base: u32,
    pub mask: u32,
    pub text: String,
}

fn ipv4_to_int(ip: &str) -> Option<u32> {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut n: u32 = 0;
    for p in parts {
        if p.is_empty() || p.len() > 3 || !p.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        let v: u32 = p.parse().ok()?;
        if v > 255 {
            return None;
        }
        n = n.wrapping_mul(256).wrapping_add(v);
    }
    Some(n)
}

/// "a.b.c.d/len" or a bare address. None if unreadable.
pub fn parse_cidr(cidr: &str) -> Option<Cidr> {
    let s = cidr.trim();
    let (ip, len) = match s.split_once('/') {
        Some((ip, l)) => (ip, Some(l)),
        None => (s, None),
    };
    let base = ipv4_to_int(ip)?;
    let length: u32 = match len {
        None => 32,
        Some(l) => {
            if l.is_empty() || !l.chars().all(|c| c.is_ascii_digit()) {
                return None;
            }
            let n: u32 = l.parse().ok()?;
            if n > 32 {
                return None;
            }
            n
        }
    };
    let mask = if length == 0 {
        0
    } else {
        0xffff_ffffu32 << (32 - length)
    };
    Some(Cidr {
        base: base & mask,
        mask,
        text: format!("{ip}/{length}"),
    })
}

pub fn compile_cidrs(list: &[String]) -> Vec<Cidr> {
    list.iter().filter_map(|s| parse_cidr(s)).collect()
}

pub fn in_cidrs(ip: &str, compiled: &[Cidr]) -> bool {
    match ipv4_to_int(ip.trim()) {
        Some(n) => compiled.iter().any(|c| n & c.mask == c.base),
        None => false,
    }
}

/// Every value of a header joined with ", ", the way Fetch reads it. Empty if absent.
pub fn header(h: &HeaderMap, name: &str) -> String {
    h.get_all(name)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join(", ")
}

/// The caller's address as the edge reported it: x-real-ip, else the LAST x-forwarded-for hop.
pub fn client_ip(h: &HeaderMap) -> String {
    let real = header(h, "x-real-ip");
    if !real.trim().is_empty() {
        return real.trim().to_string();
    }
    header(h, "x-forwarded-for")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .last()
        .unwrap_or("")
        .to_string()
}

fn is_word(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn claims_chromium(ua: &str) -> bool {
    let mut from = 0;
    while let Some(i) = ua[from..].find("Chrome/") {
        let at = from + i;
        let before_ok = at == 0 || !ua[..at].chars().last().map(is_word).unwrap_or(false);
        let after_ok = ua[at + 7..]
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false);
        if before_ok && after_ok {
            return true;
        }
        from = at + 7;
    }
    false
}

fn declares_itself(ua: &str) -> bool {
    let l = ua.to_lowercase();
    if ["compatible;", "bot/", "crawler", "spider", "slurp"]
        .iter()
        .any(|n| l.contains(n))
    {
        return true;
    }
    let b = l.as_bytes();
    let mut from = 0;
    while let Some(i) = l[from..].find("bot") {
        let at = from + i;
        let before = at == 0 || !is_word(b[at - 1] as char);
        let after = at + 3 >= b.len() || !is_word(b[at + 3] as char);
        if before && after {
            return true;
        }
        from = at + 3;
    }
    false
}

/// Claims Chromium, declares no crawler, sends no Sec-Fetch-Mode: an HTTP client with a copied string.
pub fn is_spoofed_browser(h: &HeaderMap) -> bool {
    let ua = header(h, "user-agent");
    if !claims_chromium(&ua) || declares_itself(&ua) {
        return false;
    }
    !h.contains_key("sec-fetch-mode")
}

// ------------------------------------------------------------------ robots --

#[derive(Clone, Debug, Default)]
pub struct RobotsOptions {
    pub site_url: String,
    pub disallow: Vec<String>,
    pub allow: Vec<String>,
    /// None: `<site_url>/sitemap.xml`; Some(""): omit.
    pub sitemap: Option<String>,
    pub path: Option<String>,
    pub refused: Vec<String>,
    pub training: Option<Vec<String>>,
    pub retrieval: Option<Vec<String>>,
    pub comments: Vec<String>,
}

/// robots.txt with the crawlers sorted the way the gateway sorts them.
pub fn robots_txt(o: &RobotsOptions) -> String {
    let base = o.site_url.trim_end_matches('/');
    let path = o.path.clone().unwrap_or_else(|| "/crawl".into());
    let training = o.training.clone().unwrap_or_else(|| owned(TRAINING_AGENTS));
    let retrieval = o
        .retrieval
        .clone()
        .unwrap_or_else(|| owned(RETRIEVAL_AGENTS));
    let sitemap = o
        .sitemap
        .clone()
        .unwrap_or_else(|| format!("{base}/sitemap.xml"));
    let welcome = |agent: &str| {
        let mut lines = vec![format!("User-agent: {agent}"), "Allow: /".to_string()];
        lines.extend(o.allow.iter().map(|p| format!("Allow: {p}")));
        lines.extend(o.disallow.iter().map(|p| format!("Disallow: {p}")));
        lines.join("\n")
    };
    let refuse = |agent: &str| format!("User-agent: {agent}\nDisallow: /");
    let charge = |agent: &str| format!("{}\nAllow: {path}", refuse(agent));
    let mut lines: Vec<String> = o.comments.iter().map(|c| format!("# {c}")).collect();
    if !o.comments.is_empty() {
        lines.push(String::new());
    }
    lines.extend(o.refused.iter().map(|a| format!("{}\n", refuse(a))));
    lines.extend(training.iter().map(|a| format!("{}\n", charge(a))));
    lines.extend(retrieval.iter().map(|a| format!("{}\n", welcome(a))));
    lines.push(welcome("*"));
    lines.push(String::new());
    if !sitemap.is_empty() {
        lines.push(format!("Sitemap: {sitemap}"));
        lines.push(String::new());
    }
    lines.join("\n")
}

// -------------------------------------------------------------------- page --

pub mod page;
pub use page::{render_page, PageContext};

// ----------------------------------------------------------------- gateway --

/// What `on_sale` receives.
#[derive(Clone, Debug)]
pub struct Sale {
    pub payer: Option<String>,
    pub r#ref: Option<String>,
    pub token: String,
    pub expires_at: String,
    pub user_agent: String,
    pub price_cents: f64,
    pub days: i64,
    pub total_cents: f64,
    pub currency: String,
}

pub type Predicate<T> = Arc<dyn Fn(&T) -> bool + Send + Sync>;

/// Gateway options. `Default` takes the reference defaults; set `site_url` at least.
pub struct Options {
    pub site_url: String,
    pub site_name: Option<String>,
    pub coinpay_api_key: String,
    pub coinpay_base_url: String,
    pub pay_to: String,
    pub price_cents: f64,
    pub currency: String,
    pub pass_minutes: i64,
    pub max_days: i64,
    pub header: String,
    pub path: String,
    pub open_paths: Vec<String>,
    pub is_paid_agent: Option<Predicate<str>>,
    pub deny_cidrs: Vec<String>,
    pub charge_spoofed_browsers: bool,
    pub exempt: Option<Predicate<HeaderMap>>,
    pub secret: String,
    pub training: Vec<String>,
    pub retrieval: Vec<String>,
    pub page: Option<Arc<dyn Fn(&PageContext) -> String + Send + Sync>>,
    pub contact: String,
    pub on_sale: Option<Arc<dyn Fn(Sale) + Send + Sync>>,
    pub transport: Option<Box<dyn Transport>>,
    pub now: Option<Arc<dyn Fn() -> i64 + Send + Sync>>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            site_url: String::new(),
            site_name: None,
            coinpay_api_key: String::new(),
            coinpay_base_url: "https://coinpayportal.com".into(),
            pay_to: String::new(),
            price_cents: 100.0,
            currency: "USD".into(),
            pass_minutes: 1440,
            max_days: 30,
            header: "x-crawl-pass".into(),
            path: "/crawl".into(),
            open_paths: vec![],
            is_paid_agent: None,
            deny_cidrs: vec![],
            charge_spoofed_browsers: false,
            exempt: None,
            secret: String::new(),
            training: owned(TRAINING_AGENTS),
            retrieval: owned(RETRIEVAL_AGENTS),
            page: None,
            contact: String::new(),
            on_sale: None,
            transport: None,
            now: None,
        }
    }
}

pub struct Gateway {
    o: Options,
    pub enabled: bool,
    secret: String,
    open: Vec<String>,
    denied: Vec<Cidr>,
    buy_url: String,
    transport: Box<dyn Transport>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PassInfo {
    price: String,
    minutes: i64,
    days: i64,
    total: String,
    max_days: i64,
    header: String,
    buy: String,
    buy_days: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Receipt {
    x402_version: u8,
    accepts: Vec<Accept>,
    pass: PassInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn iso(ts: i64) -> String {
    // civil-from-days, Howard Hinnant
    let days = ts.div_euclid(86400);
    let secs = ts.rem_euclid(86400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.000Z",
        secs / 3600,
        (secs / 60) % 60,
        secs % 60
    )
}

fn leading_int(s: &str) -> Option<i64> {
    let t = s.trim_start();
    let mut chars = t.char_indices().peekable();
    let mut end = 0;
    if let Some(&(_, c)) = chars.peek() {
        if c == '+' || c == '-' {
            chars.next();
            end = 1;
        }
    }
    let start_digits = end;
    for (i, c) in chars {
        if c.is_ascii_digit() {
            end = i + 1;
        } else {
            break;
        }
    }
    if end == start_digits {
        return None;
    }
    let text = &t[..end];
    text.parse::<i64>().ok().or(Some(if text.starts_with('-') {
        i64::MIN
    } else {
        i64::MAX
    }))
}

fn bearer(auth: &str) -> Option<String> {
    let rest = auth
        .get(..6)
        .filter(|p| p.eq_ignore_ascii_case("bearer"))
        .map(|_| &auth[6..])?;
    let token = rest.trim_start();
    if token.len() == rest.len() {
        return None;
    }
    let body = token.strip_prefix("cp_")?;
    let (a, b) = body.split_once('.')?;
    let ok = |s: &str| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    };
    if ok(a) && ok(b) {
        Some(token.to_string())
    } else {
        None
    }
}

impl Gateway {
    pub fn new(mut o: Options) -> Result<Gateway, String> {
        o.site_url = o.site_url.trim_end_matches('/').to_string();
        if o.site_url.is_empty() {
            return Err("Gateway needs site_url".into());
        }
        if o.site_name.is_none() {
            let host = o
                .site_url
                .split("//")
                .nth(1)
                .unwrap_or(&o.site_url)
                .split('/')
                .next()
                .unwrap_or("")
                .split(':')
                .next()
                .unwrap_or("");
            o.site_name = Some(if host.is_empty() {
                o.site_url.clone()
            } else {
                host.to_string()
            });
        }
        o.coinpay_base_url = o.coinpay_base_url.trim_end_matches('/').to_string();
        if !o.price_cents.is_finite() {
            o.price_cents = 100.0;
        }
        if o.pass_minutes <= 0 {
            o.pass_minutes = 1440;
        }
        if o.max_days < 1 {
            o.max_days = 30;
        }
        o.header = o.header.to_lowercase();
        if o.header.is_empty() {
            o.header = "x-crawl-pass".into();
        }
        if o.path.is_empty() {
            o.path = "/crawl".into();
        }
        let enabled = !o.coinpay_api_key.is_empty() && !o.pay_to.is_empty();
        let secret = if o.secret.is_empty() {
            o.coinpay_api_key.clone()
        } else {
            o.secret.clone()
        };
        let mut open = vec![
            "/robots.txt".to_string(),
            o.path.clone(),
            "/security.txt".into(),
            "/.well-known/".into(),
        ];
        open.extend(o.open_paths.iter().cloned());
        let denied = compile_cidrs(&o.deny_cidrs);
        let buy_url = format!("{}{}", o.site_url, o.path);
        let transport: Box<dyn Transport> = match o.transport.take() {
            Some(t) => t,
            None => default_transport(),
        };
        Ok(Gateway {
            enabled,
            secret,
            open,
            denied,
            buy_url,
            transport,
            o,
        })
    }

    pub fn options(&self) -> &Options {
        &self.o
    }

    fn now(&self) -> i64 {
        self.o.now.as_ref().map(|f| f()).unwrap_or_else(unix_now)
    }

    fn money(&self, cents: f64) -> String {
        format!("{:.2} {}", cents / 100.0, self.o.currency)
    }

    fn is_open(&self, path: &str) -> bool {
        self.open.iter().any(|p| {
            if p.ends_with('/') {
                path.starts_with(p.as_str())
            } else {
                path == p
            }
        })
    }

    fn days_from(&self, query: Option<&str>) -> i64 {
        let raw = query
            .unwrap_or("")
            .split('&')
            .find_map(|kv| {
                kv.strip_prefix("days=")
                    .or(if kv == "days" { Some("") } else { None })
            })
            .unwrap_or("");
        match leading_int(raw) {
            Some(n) if n >= 1 => n.min(self.o.max_days),
            _ => 1,
        }
    }

    /// The offer for `days` terms.
    pub fn offer(&self, days: i64) -> Offer {
        if !self.enabled {
            return Offer {
                x402_version: 2,
                accepts: vec![],
            };
        }
        let extra = if days > 1 {
            format!(" ({days} × {})", self.o.pass_minutes)
        } else {
            String::new()
        };
        let description = format!(
            "{} minutes of crawl access to {}{extra}",
            days * self.o.pass_minutes,
            self.o.site_url
        );
        build_offer(&OfferOptions {
            pay_to: &self.o.pay_to,
            price_cents: self.o.price_cents * days as f64,
            resource: &self.buy_url,
            description: &description,
            max_timeout_seconds: 300,
        })
        .expect("pay_to is set when enabled")
    }

    fn receipt(&self, days: i64, error: Option<String>) -> Receipt {
        let o = self.offer(days);
        Receipt {
            x402_version: o.x402_version,
            accepts: o.accepts,
            pass: PassInfo {
                price: self.money(self.o.price_cents),
                minutes: self.o.pass_minutes,
                days,
                total: self.money(self.o.price_cents * days as f64),
                max_days: self.o.max_days,
                header: self.o.header.clone(),
                buy: if days > 1 {
                    format!("{}?days={days}", self.buy_url)
                } else {
                    self.buy_url.clone()
                },
                buy_days: format!("{}?days=<n>", self.buy_url),
            },
            error,
        }
    }

    fn respond(
        &self,
        status: u16,
        content_type: &str,
        body: String,
        extra: &[(String, String)],
    ) -> Response<String> {
        let mut b = Response::builder()
            .status(status)
            .header("content-type", content_type)
            .header("cache-control", "no-store")
            .header("vary", "Accept, User-Agent, X-Payment");
        for (k, v) in extra {
            b = b.header(k.as_str(), v.as_str());
        }
        b.body(body).expect("static headers are valid")
    }

    fn json<T: Serialize>(
        &self,
        body: &T,
        status: u16,
        extra: &[(String, String)],
    ) -> Response<String> {
        self.respond(
            status,
            "application/json; charset=utf-8",
            serde_json::to_string_pretty(body).unwrap_or_default(),
            extra,
        )
    }

    pub fn page_ctx(&self, days: i64) -> PageContext {
        PageContext {
            days,
            total: self.money(self.o.price_cents * days as f64),
            site_name: self.o.site_name.clone().unwrap_or_default(),
            site_url: self.o.site_url.clone(),
            buy_url: self.buy_url.clone(),
            price: self.money(self.o.price_cents),
            minutes: self.o.pass_minutes,
            max_days: self.o.max_days,
            header: self.o.header.clone(),
            enabled: self.enabled,
            offer: self.offer(1),
            training: self.o.training.clone(),
            retrieval: self.o.retrieval.clone(),
            contact: self.o.contact.clone(),
        }
    }

    fn render(&self, days: i64) -> String {
        let ctx = self.page_ctx(days);
        match &self.o.page {
            Some(f) => f(&ctx),
            None => render_page(&ctx),
        }
    }

    /// The sales page as HTML, for a site that mounts it on a route of its own.
    pub fn page(&self) -> String {
        self.render(1)
    }

    /// robots.txt with this gateway's lists and sales path; empty fields of `extra` take the gateway's.
    pub fn robots_txt(&self, mut extra: RobotsOptions) -> String {
        if extra.site_url.is_empty() {
            extra.site_url = self.o.site_url.clone();
        }
        if extra.path.is_none() {
            extra.path = Some(self.o.path.clone());
        }
        if extra.training.is_none() {
            extra.training = Some(self.o.training.clone());
        }
        if extra.retrieval.is_none() {
            extra.retrieval = Some(self.o.retrieval.clone());
        }
        robots_txt(&extra)
    }

    fn pass_from(&self, h: &HeaderMap) -> Option<String> {
        let direct = header(h, &self.o.header);
        if !direct.is_empty() {
            return Some(direct.trim().to_string());
        }
        bearer(&header(h, "authorization"))
    }

    /// Whether handling this request may call CoinPay (only a proof does). For async adapters.
    pub fn needs_io(&self, h: &HeaderMap) -> bool {
        h.contains_key("x-payment")
    }

    fn is_paid(&self, ua: &str) -> bool {
        match &self.o.is_paid_agent {
            Some(f) => f(ua),
            None => is_training_agent(ua, &self.o.training),
        }
    }

    /// Answer one request with the sale: a pass as the body of a 200, or a 402 with the offer.
    pub fn sell(&self, h: &HeaderMap, query: Option<&str>) -> Response<String> {
        let ua = header(h, "user-agent");
        let proof_header = header(h, "x-payment");
        let asked = self.days_from(query);

        if !proof_header.is_empty() {
            if !self.enabled {
                return self.json(
                    &self.receipt(asked, Some("Payments are not switched on here.".into())),
                    402,
                    &[],
                );
            }
            let Some(payment) = decode_payment(&proof_header) else {
                return self.json(
                    &self.receipt(asked, Some("X-PAYMENT is not base64 JSON.".into())),
                    402,
                    &[],
                );
            };
            let Some(unit) = expected_for(&payment, &self.offer(1)) else {
                return self.json(
                    &self.receipt(
                        asked,
                        Some("Proof does not match an offered network.".into()),
                    ),
                    402,
                    &[],
                );
            };
            let days = days_paid(
                paid_value_of(&payment).as_ref(),
                &unit.amount,
                self.o.max_days,
            );
            if days == 0 {
                let msg = format!(
                    "Pay a whole number of days: {} per day in the token's smallest unit, up to {} days. Add ?days=<n> to {} for the offer.",
                    unit.amount, self.o.max_days, self.buy_url
                );
                return self.json(&self.receipt(asked, Some(msg)), 402, &[]);
            }
            let expected = expected_for(&payment, &self.offer(days)).unwrap_or(unit);
            let term = days * self.o.pass_minutes * 60;
            let now = self.now();
            let result = verify_and_settle(
                self.transport.as_ref(),
                &self.o.coinpay_api_key,
                &self.o.coinpay_base_url,
                &payment,
                &expected,
            );

            let mut expires_at: Option<i64> = None;
            let mut replayed = false;
            if result.ok {
                expires_at = Some(now + term);
            } else if result.replay {
                let paid = settle_again(
                    self.transport.as_ref(),
                    &self.o.coinpay_api_key,
                    &self.o.coinpay_base_url,
                    &payment,
                );
                if let (true, Some(vb)) = (paid, valid_before_of(&payment)) {
                    expires_at = Some((now + term).min(vb + term));
                    replayed = true;
                }
            }
            let Some(expires_at) = expires_at.filter(|e| *e > now) else {
                let reason = result
                    .reason
                    .unwrap_or_else(|| "Payment could not be settled.".into());
                return self.json(&self.receipt(days, Some(reason)), 402, &[]);
            };

            let r#ref = nonce_of(&payment).or(result.r#ref);
            let Ok(pass) = mint_pass(&self.secret, r#ref.as_deref(), expires_at, now) else {
                return self.json(
                    &self.receipt(days, Some("Payment could not be settled.".into())),
                    402,
                    &[],
                );
            };
            let expires = iso(pass.expires_at);
            if let (Some(f), false) = (&self.o.on_sale, replayed) {
                let sale = Sale {
                    payer: result.payer,
                    r#ref: r#ref.clone(),
                    token: pass.token.clone(),
                    expires_at: expires.clone(),
                    user_agent: ua,
                    price_cents: self.o.price_cents,
                    days,
                    total_cents: self.o.price_cents * days as f64,
                    currency: self.o.currency.clone(),
                };
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(sale)));
            }
            let body = json!({
                "ok": true,
                "pass": pass.token,
                "expires_at": expires,
                "days": days,
                "minutes": days * self.o.pass_minutes,
                "header": self.o.header,
                "replayed": replayed,
                "use": format!("curl -H \"{}: {}\" {}/", self.o.header, pass.token, self.o.site_url),
            });
            return self.json(
                &body,
                200,
                &[
                    (self.o.header.clone(), pass.token.clone()),
                    (format!("{}-expires", self.o.header), expires),
                ],
            );
        }

        if header(h, "accept").to_lowercase().contains("text/html") {
            return self.respond(402, "text/html; charset=utf-8", self.render(asked), &[]);
        }
        self.json(
            &self.receipt(
                asked,
                Some(format!(
                    "Payment required for training crawlers. Read {} for how.",
                    self.buy_url
                )),
            ),
            402,
            &[],
        )
    }

    /// The gate on parts: path, query and headers. None means "not for me, carry on".
    pub fn handle_parts(
        &self,
        path: &str,
        query: Option<&str>,
        h: &HeaderMap,
    ) -> Option<Response<String>> {
        if !self.denied.is_empty() && in_cidrs(&client_ip(h), &self.denied) {
            return Some(self.respond(
                403,
                "text/plain; charset=utf-8",
                "Not available from this network.\n".into(),
                &[],
            ));
        }
        let path = if path.is_empty() { "/" } else { path };
        if path == self.o.path {
            return Some(self.sell(h, query));
        }
        if let Some(f) = &self.o.exempt {
            if f(h) {
                return None;
            }
        }
        let pays = self.is_paid(&header(h, "user-agent"))
            || (self.o.charge_spoofed_browsers && is_spoofed_browser(h));
        if !pays || self.is_open(path) {
            return None;
        }
        if let Some(token) = self.pass_from(h) {
            if read_pass(&token, &self.secret, self.now()).is_some() {
                return None;
            }
        }
        Some(self.sell(h, query))
    }

    /// The gate. None means "not for me, carry on".
    pub fn handle<B>(&self, req: &Request<B>) -> Option<Response<String>> {
        self.handle_parts(req.uri().path(), req.uri().query(), req.headers())
    }
}

#[cfg(feature = "ureq")]
fn default_transport() -> Box<dyn Transport> {
    Box::new(Ureq)
}

#[cfg(not(feature = "ureq"))]
fn default_transport() -> Box<dyn Transport> {
    Box::new(NoTransport)
}

#[allow(dead_code)]
fn _keep(_: NoTransport) {}

#[cfg(feature = "axum")]
pub mod axum {
    //! `axum::middleware::from_fn_with_state(Arc::new(gateway), x402_gateway::axum::gate)`
    use super::Gateway;
    use ::axum::{
        body::Body,
        extract::{Request, State},
        middleware::Next,
        response::{IntoResponse, Response},
    };
    use std::sync::Arc;

    pub async fn gate(State(gw): State<Arc<Gateway>>, req: Request, next: Next) -> Response {
        let (parts, body) = req.into_parts();
        let path = parts.uri.path().to_string();
        let query = parts.uri.query().map(String::from);
        let headers = parts.headers.clone();
        let answer = if gw.needs_io(&headers) {
            let g = gw.clone();
            tokio::task::spawn_blocking(move || g.handle_parts(&path, query.as_deref(), &headers))
                .await
                .unwrap_or(None)
        } else {
            gw.handle_parts(&path, query.as_deref(), &headers)
        };
        match answer {
            Some(r) => r.map(Body::from).into_response(),
            None => next.run(Request::from_parts(parts, body)).await,
        }
    }
}
