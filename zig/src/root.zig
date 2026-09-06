//! Sell crawl access to AI training crawlers, by the day, over x402, settled by CoinPay.
//!
//! A port of @profullstack/x402-gateway: the same 402 body, the same signed pass
//! (cp_<payload>.<hmac>), the same robots.txt, the same order of decisions,
//! checked against the same fixtures.
//!
//! `Gateway.handle(arena, request)` returns a `Response` to send, or null to let the
//! request through. Every function takes an arena allocator and frees nothing:
//! make one per request, free it when the response is written.
//!
//! CoinPay is reached through a `Transport` you supply (a function pointer over
//! your HTTP client), because Zig's HTTP client needs your `std.Io` instance.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;

// ------------------------------------------------------------------ agents --

/// Training-only crawlers: refused in robots.txt, charged by the gateway.
pub const training_agents = [_][]const u8{ "GPTBot", "ClaudeBot", "anthropic-ai", "CCBot", "meta-externalagent", "FacebookBot", "Bytespider", "Applebot-Extended" };
/// Retrieval crawlers, named in robots.txt so their operators can see they are welcome.
pub const retrieval_agents = [_][]const u8{ "OAI-SearchBot", "ChatGPT-User", "Claude-SearchBot", "Claude-User", "PerplexityBot", "Perplexity-User", "Google-Extended", "Bingbot" };

/// Whether a user agent names one of `agents` (substring, case-insensitive).
pub fn isTrainingAgent(user_agent: []const u8, agents: []const []const u8) bool {
    if (user_agent.len == 0) return false;
    for (agents) |a| {
        if (std.ascii.indexOfIgnoreCase(user_agent, a) != null) return true;
    }
    return false;
}

// ----------------------------------------------------------------- headers --

pub const Header = struct { name: []const u8, value: []const u8 };

/// The first value of a header, by case-insensitive name. Null if absent.
pub fn header(headers: []const Header, name: []const u8) ?[]const u8 {
    for (headers) |h| if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
    return null;
}

// -------------------------------------------------------------------- edge --

pub const Cidr = struct { base: u32, mask: u32 };

fn ipv4ToInt(ip: []const u8) ?u32 {
    var n: u32 = 0;
    var count: usize = 0;
    var it = std.mem.splitScalar(u8, ip, '.');
    while (it.next()) |p| {
        count += 1;
        if (count > 4 or p.len == 0 or p.len > 3) return null;
        for (p) |c| if (!std.ascii.isDigit(c)) return null;
        const v = std.fmt.parseInt(u32, p, 10) catch return null;
        if (v > 255) return null;
        n = n *% 256 +% v;
    }
    return if (count == 4) n else null;
}

/// "a.b.c.d/len" or a bare address. Null if unreadable.
pub fn parseCidr(cidr: []const u8) ?Cidr {
    const s = std.mem.trim(u8, cidr, " \t\r\n");
    var ip = s;
    var len: u32 = 32;
    if (std.mem.indexOfScalar(u8, s, '/')) |slash| {
        ip = s[0..slash];
        const l = s[slash + 1 ..];
        if (l.len == 0) return null;
        for (l) |c| if (!std.ascii.isDigit(c)) return null;
        len = std.fmt.parseInt(u32, l, 10) catch return null;
        if (len > 32) return null;
    }
    const base = ipv4ToInt(ip) orelse return null;
    const mask: u32 = if (len == 0) 0 else @truncate(@as(u64, 0xffffffff) << @intCast(32 - len));
    return .{ .base = base & mask, .mask = mask };
}

/// Compile a denylist once. Unreadable entries are dropped.
pub fn compileCidrs(gpa: Allocator, list: []const []const u8) ![]Cidr {
    var out: std.ArrayList(Cidr) = .empty;
    for (list) |s| if (parseCidr(s)) |c| try out.append(gpa, c);
    return out.toOwnedSlice(gpa);
}

pub fn inCidrs(ip: []const u8, compiled: []const Cidr) bool {
    const n = ipv4ToInt(std.mem.trim(u8, ip, " \t\r\n")) orelse return false;
    for (compiled) |c| if (n & c.mask == c.base) return true;
    return false;
}

/// The caller's address as the edge reported it: x-real-ip, else the LAST x-forwarded-for hop.
pub fn clientIp(headers: []const Header) []const u8 {
    if (header(headers, "x-real-ip")) |real| {
        const t = std.mem.trim(u8, real, " \t");
        if (t.len > 0) return t;
    }
    const xff = header(headers, "x-forwarded-for") orelse return "";
    var last: []const u8 = "";
    var it = std.mem.splitScalar(u8, xff, ',');
    while (it.next()) |hop| {
        const t = std.mem.trim(u8, hop, " \t");
        if (t.len > 0) last = t;
    }
    return last;
}

fn isWord(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_';
}

fn claimsChromium(ua: []const u8) bool {
    var from: usize = 0;
    while (std.mem.indexOfPos(u8, ua, from, "Chrome/")) |at| {
        const before_ok = at == 0 or !isWord(ua[at - 1]);
        const after_ok = at + 7 < ua.len and std.ascii.isDigit(ua[at + 7]);
        if (before_ok and after_ok) return true;
        from = at + 7;
    }
    return false;
}

fn declaresItself(ua: []const u8) bool {
    for ([_][]const u8{ "compatible;", "bot/", "crawler", "spider", "slurp" }) |n| {
        if (std.ascii.indexOfIgnoreCase(ua, n) != null) return true;
    }
    var from: usize = 0;
    while (std.ascii.indexOfIgnoreCasePos(ua, from, "bot")) |at| {
        const before = at == 0 or !isWord(ua[at - 1]);
        const after = at + 3 >= ua.len or !isWord(ua[at + 3]);
        if (before and after) return true;
        from = at + 3;
    }
    return false;
}

/// Claims Chromium, declares no crawler, sends no Sec-Fetch-Mode: an HTTP client with a copied string.
pub fn isSpoofedBrowser(headers: []const Header) bool {
    const ua = header(headers, "user-agent") orelse "";
    if (!claimsChromium(ua) or declaresItself(ua)) return false;
    return header(headers, "sec-fetch-mode") == null;
}

// ------------------------------------------------------------------ passes --

fn b64url(arena: Allocator, bytes: []const u8) ![]u8 {
    const enc = std.base64.url_safe_no_pad;
    const out = try arena.alloc(u8, enc.Encoder.calcSize(bytes.len));
    _ = enc.Encoder.encode(out, bytes);
    return out;
}

fn unb64url(arena: Allocator, s: []const u8) ![]u8 {
    const dec = std.base64.url_safe_no_pad.Decoder;
    const t = std.mem.trimEnd(u8, s, "=");
    const out = try arena.alloc(u8, try dec.calcSizeForSlice(t));
    try dec.decode(out, t);
    return out;
}

fn sign(arena: Allocator, secret: []const u8, data: []const u8) ![]u8 {
    var mac: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, data, secret);
    return b64url(arena, &mac);
}

/// Mint a pass: `cp_<payload>.<signature>`. `now` and `expires_at` are unix seconds.
pub fn mintPass(arena: Allocator, secret: []const u8, ref: ?[]const u8, expires_at: i64, now: i64) ![]u8 {
    if (secret.len == 0) return error.NoSecret;
    if (expires_at <= now) return error.NoFutureExpiry;
    const claims = try std.json.Stringify.valueAlloc(arena, .{ .v = 1, .iat = now, .exp = expires_at, .ref = ref }, .{});
    const payload = try b64url(arena, claims);
    return std.fmt.allocPrint(arena, "cp_{s}.{s}", .{ payload, try sign(arena, secret, payload) });
}

pub const Claims = struct { exp: f64, ref: ?[]const u8 };

/// The claims when the signature holds and the pass is live, else null. Never fails on garbage.
pub fn readPass(arena: Allocator, token: []const u8, secret: []const u8, now: i64) ?Claims {
    if (secret.len == 0 or !std.mem.startsWith(u8, token, "cp_")) return null;
    const dot = std.mem.indexOfScalar(u8, token, '.') orelse return null;
    const payload = token[3..dot];
    const sig = token[dot + 1 ..];
    if (payload.len == 0 or sig.len == 0) return null;
    const expect = sign(arena, secret, payload) catch return null;
    if (expect.len != sig.len) return null;
    var diff: u8 = 0;
    for (expect, sig) |a, b| diff |= a ^ b;
    if (diff != 0) return null;
    const raw = unb64url(arena, payload) catch return null;
    const parsed = std.json.parseFromSliceLeaky(std.json.Value, arena, raw, .{}) catch return null;
    if (parsed != .object) return null;
    const v = parsed.object.get("v") orelse return null;
    if (v != .integer or v.integer != 1) return null;
    const exp: f64 = switch (parsed.object.get("exp") orelse return null) {
        .integer => |i| @floatFromInt(i),
        .float => |f| f,
        else => return null,
    };
    if (!std.math.isFinite(exp) or exp <= @as(f64, @floatFromInt(now))) return null;
    const ref: ?[]const u8 = if (parsed.object.get("ref")) |r| (if (r == .string) r.string else null) else null;
    return .{ .exp = exp, .ref = ref };
}

// -------------------------------------------------------------------- x402 --

pub const Method = struct { key: []const u8, network: []const u8, asset: []const u8, label: []const u8 };

/// USDC on Base, Polygon and Ethereum, Base first.
pub const methods = [_]Method{
    .{ .key = "usdc_base", .network = "eip155:8453", .asset = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", .label = "USDC on Base" },
    .{ .key = "usdc_polygon", .network = "eip155:137", .asset = "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359", .label = "USDC on Polygon" },
    .{ .key = "usdc_eth", .network = "eip155:1", .asset = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", .label = "USDC on Ethereum" },
};

pub const Domain = struct { name: []const u8 = "USD Coin", version: []const u8 = "2" };

pub const Accept = struct {
    scheme: []const u8 = "exact",
    network: []const u8,
    amount: []const u8,
    asset: []const u8,
    payTo: []const u8,
    resource: []const u8,
    description: []const u8,
    mimeType: []const u8 = "application/json",
    maxTimeoutSeconds: u32 = 300,
    extra: Domain = .{},
};

pub const Offer = struct { x402Version: u8 = 2, accepts: []const Accept = &.{} };

/// A v2 402 body. `amount` is the price in the token's smallest unit, rounded up.
pub fn buildOffer(arena: Allocator, pay_to: []const u8, price_cents: f64, resource: []const u8, description: []const u8, max_timeout_seconds: u32) !Offer {
    if (pay_to.len == 0) return error.NoPayTo;
    const amount = try std.fmt.allocPrint(arena, "{d}", .{@as(u64, @intFromFloat(@ceil((price_cents / 100.0) * 1_000_000.0)))});
    const accepts = try arena.alloc(Accept, methods.len);
    for (&methods, 0..) |m, i| {
        accepts[i] = .{ .network = m.network, .amount = amount, .asset = m.asset, .payTo = pay_to, .resource = resource, .description = description, .maxTimeoutSeconds = max_timeout_seconds };
    }
    return .{ .accepts = accepts };
}

/// base64 or base64url to bytes, the forgiving way atob reads it. Null if it is not base64.
pub fn fromBase64(arena: Allocator, s: []const u8) ?[]u8 {
    var t: std.ArrayList(u8) = .empty;
    for (s) |c| {
        if (std.ascii.isWhitespace(c)) continue;
        t.append(arena, switch (c) {
            '-' => '+',
            '_' => '/',
            else => c,
        }) catch return null;
    }
    var slice: []const u8 = t.items;
    if (slice.len % 4 == 0) slice = std.mem.trimEnd(u8, slice, "=");
    if (slice.len % 4 == 1) return null;
    for (slice) |c| if (!(std.ascii.isAlphanumeric(c) or c == '+' or c == '/')) return null;
    const dec = std.base64.standard_no_pad.Decoder;
    const out = arena.alloc(u8, dec.calcSizeForSlice(slice) catch return null) catch return null;
    dec.decode(out, slice) catch return null;
    return out;
}

/// The proof out of an X-PAYMENT header: a JSON object or array, else null.
pub fn decodePayment(arena: Allocator, hdr: []const u8) ?std.json.Value {
    if (hdr.len == 0) return null;
    const raw = fromBase64(arena, hdr) orelse return null;
    const v = std.json.parseFromSliceLeaky(std.json.Value, arena, raw, .{}) catch return null;
    return switch (v) {
        .object, .array => v,
        else => null,
    };
}

pub const Expected = struct { amount: []const u8, resource: []const u8, payTo: []const u8, asset: []const u8 };

fn dig(v: std.json.Value, path: []const []const u8) ?std.json.Value {
    var cur = v;
    for (path) |k| {
        if (cur != .object) return null;
        cur = cur.object.get(k) orelse return null;
    }
    return cur;
}

fn valueStr(arena: Allocator, v: ?std.json.Value) []const u8 {
    const x = v orelse return "";
    return switch (x) {
        .string => |s| s,
        .integer => |i| std.fmt.allocPrint(arena, "{d}", .{i}) catch "",
        .float => |f| std.fmt.allocPrint(arena, "{d}", .{f}) catch "",
        .bool => |b| if (b) "true" else "false",
        .number_string => |s| s,
        else => "",
    };
}

/// The offered entry for the proof's network, case-insensitively. Null if none.
pub fn expectedFor(arena: Allocator, payment: std.json.Value, offer: Offer) ?Expected {
    const network = valueStr(arena, dig(payment, &.{"network"}));
    for (offer.accepts) |a| {
        if (std.ascii.eqlIgnoreCase(a.network, network)) return .{ .amount = a.amount, .resource = a.resource, .payTo = a.payTo, .asset = a.asset };
    }
    return null;
}

pub fn nonceOf(arena: Allocator, payment: std.json.Value) ?[]const u8 {
    const v = dig(payment, &.{ "payload", "authorization", "nonce" }) orelse return null;
    if (v == .null) return null;
    return valueStr(arena, v);
}

pub fn validBeforeOf(arena: Allocator, payment: std.json.Value) ?i64 {
    const s = std.mem.trim(u8, valueStr(arena, dig(payment, &.{ "payload", "authorization", "validBefore" })), " \t");
    const f = std.fmt.parseFloat(f64, s) catch return null;
    if (!std.math.isFinite(f) or f <= 0) return null;
    return @intFromFloat(f);
}

/// What BigInt(raw) would read, as far as 128 bits carry it: decimal or 0x strings, whole numbers.
/// Larger values are refused (null), never mis-read.
pub fn bigint(raw: std.json.Value) ?u128 {
    switch (raw) {
        .integer => |i| return if (i < 0) null else @intCast(i),
        .float => |f| {
            if (!std.math.isFinite(f) or f != @floor(f) or f < 0) return null;
            return @intFromFloat(f);
        },
        .string, .number_string => |s0| {
            const s = std.mem.trim(u8, s0, " \t\r\n");
            if (s.len == 0) return null;
            if (s[0] == '-') return null; // negative: never a paid value
            const body = if (s[0] == '+') s[1..] else s;
            if (body.len > 2 and body[0] == '0' and (body[1] == 'x' or body[1] == 'X')) {
                return std.fmt.parseUnsigned(u128, body[2..], 16) catch null;
            }
            for (body) |c| if (!std.ascii.isDigit(c)) return null;
            return std.fmt.parseUnsigned(u128, body, 10) catch null;
        },
        else => return null,
    }
}

/// The value a proof authorizes, in the token's smallest unit, or null.
pub fn paidValueOf(payment: std.json.Value) ?u128 {
    const raw = dig(payment, &.{ "payload", "authorization", "value" }) orelse return null;
    if (raw == .null) return null;
    if (raw == .string and raw.string.len == 0) return null;
    const v = bigint(raw) orelse return null;
    return if (v > 0) v else null;
}

/// How many terms `value` buys at `unit` per term: a whole number in [1, max_days], else 0.
pub fn daysPaid(value: ?u128, unit: []const u8, max_days: i64) i64 {
    const v = value orelse return 0;
    const per = bigint(.{ .string = unit }) orelse return 0;
    if (per == 0 or v % per != 0) return 0;
    const days = v / per;
    if (days < 1 or days > @as(u128, @intCast(max_days))) return 0;
    return @intCast(days);
}

/// How the gateway reaches CoinPay: your HTTP client behind a function pointer.
pub const Transport = struct {
    ctx: *anyopaque,
    /// POST JSON to `url` with `x-api-key: api_key`. Return the status and body; on a transport error return status 0.
    post: *const fn (ctx: *anyopaque, arena: Allocator, url: []const u8, api_key: []const u8, body: []const u8) anyerror!PostResult,
};

pub const PostResult = struct { status: u16, body: []const u8 };

pub const Settlement = struct { ok: bool, payer: ?[]const u8 = null, ref: ?[]const u8 = null, reason: ?[]const u8 = null, replay: bool = false };

fn parseObj(arena: Allocator, text: []const u8) std.json.ObjectMap {
    const v = std.json.parseFromSliceLeaky(std.json.Value, arena, text, .{}) catch return std.json.ObjectMap.empty;
    return if (v == .object) v.object else std.json.ObjectMap.empty;
}

fn truthy(v: ?std.json.Value) bool {
    const x = v orelse return false;
    return switch (x) {
        .null => false,
        .bool => |b| b,
        .string => |s| s.len > 0,
        .integer => |i| i != 0,
        .float => |f| f != 0,
        else => true,
    };
}

fn firstString(arena: Allocator, m: std.json.ObjectMap, keys: []const []const u8) ?[]const u8 {
    for (keys) |k| if (m.get(k)) |v| if (v != .null) return valueStr(arena, v);
    return null;
}

fn containsAnyIgnoreCase(hay: []const u8, needles: []const []const u8) bool {
    for (needles) |n| if (std.ascii.indexOfIgnoreCase(hay, n) != null) return true;
    return false;
}

fn post(arena: Allocator, t: Transport, base_url: []const u8, api_key: []const u8, path: []const u8, body: anytype) !struct { u16, std.json.ObjectMap } {
    const url = try std.fmt.allocPrint(arena, "{s}{s}", .{ base_url, path });
    const text = try std.json.Stringify.valueAlloc(arena, body, .{});
    const res = t.post(t.ctx, arena, url, api_key, text) catch return .{ 0, std.json.ObjectMap.empty };
    return .{ res.status, parseObj(arena, res.body) };
}

/// Verify, then settle. Two calls because verify moves no money.
pub fn verifyAndSettle(arena: Allocator, t: Transport, api_key: []const u8, base_url: []const u8, payment: std.json.Value, expected: Expected) !Settlement {
    const vs, const v = try post(arena, t, base_url, api_key, "/api/x402/verify", .{ .payment = payment, .expected = expected });
    if (!truthy(v.get("valid"))) {
        const reason = firstString(arena, v, &.{ "error", "reason" }) orelse try std.fmt.allocPrint(arena, "verify failed ({d})", .{vs});
        return .{ .ok = false, .reason = reason, .replay = containsAnyIgnoreCase(reason, &.{ "already used", "replay" }) };
    }
    const ss, const s = try post(arena, t, base_url, api_key, "/api/x402/settle", .{ .payment = payment });
    if (!truthy(s.get("settled"))) {
        const reason = firstString(arena, s, &.{"error"}) orelse try std.fmt.allocPrint(arena, "settle failed ({d})", .{ss});
        return .{ .ok = false, .reason = reason, .replay = containsAnyIgnoreCase(reason, &.{ "already settled", "already being settled" }) };
    }
    var ref = firstString(arena, s, &.{"txHash"});
    if (ref == null or ref.?.len == 0) ref = nonceOf(arena, payment);
    const payer: ?[]const u8 = if (dig(.{ .object = v }, &.{ "payment", "from" })) |p| (if (p == .string) p.string else null) else null;
    return .{ .ok = true, .payer = payer, .ref = ref };
}

/// Whether the proof has already been paid, when a settle is asked about twice.
pub fn settleAgain(arena: Allocator, t: Transport, api_key: []const u8, base_url: []const u8, payment: std.json.Value) !bool {
    _, const s = try post(arena, t, base_url, api_key, "/api/x402/settle", .{ .payment = payment });
    if (truthy(s.get("settled"))) return true;
    return containsAnyIgnoreCase(firstString(arena, s, &.{"error"}) orelse "", &.{"already settled"});
}

// ------------------------------------------------------------------ robots --

pub const RobotsOptions = struct {
    site_url: []const u8,
    disallow: []const []const u8 = &.{},
    allow: []const []const u8 = &.{},
    /// null: <site_url>/sitemap.xml; "": omit
    sitemap: ?[]const u8 = null,
    path: []const u8 = "/crawl",
    refused: []const []const u8 = &.{},
    training: []const []const u8 = &training_agents,
    retrieval: []const []const u8 = &retrieval_agents,
    comments: []const []const u8 = &.{},
};

fn welcome(w: *Writer, o: RobotsOptions, agent: []const u8) !void {
    try w.print("User-agent: {s}\nAllow: /", .{agent});
    for (o.allow) |p| try w.print("\nAllow: {s}", .{p});
    for (o.disallow) |p| try w.print("\nDisallow: {s}", .{p});
}

/// robots.txt with the crawlers sorted the way the gateway sorts them.
pub fn robotsTxt(arena: Allocator, o: RobotsOptions) ![]u8 {
    if (o.site_url.len == 0) return error.NoSiteUrl;
    var aw: Writer.Allocating = .init(arena);
    const w = &aw.writer;
    const base = std.mem.trimEnd(u8, o.site_url, "/");
    for (o.comments) |c| try w.print("# {s}\n", .{c});
    if (o.comments.len > 0) try w.writeAll("\n");
    for (o.refused) |a| try w.print("User-agent: {s}\nDisallow: /\n\n", .{a});
    for (o.training) |a| try w.print("User-agent: {s}\nDisallow: /\nAllow: {s}\n\n", .{ a, o.path });
    for (o.retrieval) |a| {
        try welcome(w, o, a);
        try w.writeAll("\n\n");
    }
    try welcome(w, o, "*");
    try w.writeAll("\n");
    if (o.sitemap) |s| {
        if (s.len > 0) try w.print("\nSitemap: {s}\n", .{s});
    } else try w.print("\nSitemap: {s}/sitemap.xml\n", .{base});
    return aw.toOwnedSlice();
}

// --------------------------------------------------------------------- page --

fn esc(w: *Writer, s: []const u8) !void {
    for (s) |c| switch (c) {
        '&' => try w.writeAll("&amp;"),
        '<' => try w.writeAll("&lt;"),
        '>' => try w.writeAll("&gt;"),
        '"' => try w.writeAll("&quot;"),
        else => try w.writeByte(c),
    };
}

/// The sales page: what a refused crawler is shown, and what its operator reads.
pub fn renderPage(arena: Allocator, g: *const Gateway, days: i64) ![]u8 {
    var aw: Writer.Allocating = .init(arena);
    const w = &aw.writer;
    const price = try g.money(arena, g.o.price_cents);
    const total = try g.money(arena, g.o.price_cents * @as(f64, @floatFromInt(days)));
    try w.writeAll("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n<meta name=\"robots\" content=\"noindex\">\n<title>Crawl access · ");
    try esc(w, g.site_name);
    try w.writeAll("</title>\n<style>:root{color-scheme:light dark;--fg:#1a1a1a;--bg:#fff;--mut:#666;--code:#f4f4f4;--acc:#0a5}@media(prefers-color-scheme:dark){:root{--fg:#eee;--bg:#111;--mut:#aaa;--code:#1c1c1c;--acc:#3c9}}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.55 system-ui,sans-serif}main{max-width:44rem;margin:0 auto;padding:2.5rem 1.25rem 4rem}.mut{color:var(--mut)}pre{background:var(--code);padding:.9rem 1rem;overflow-x:auto}.price{font-size:2.2rem;font-weight:700;color:var(--acc)}</style>\n</head>\n<body>\n<main>\n<h1>Training crawlers pay for access here.</h1>\n<p class=\"mut\">People read <a href=\"");
    try esc(w, g.o.site_url);
    try w.writeAll("\">");
    try esc(w, g.site_name);
    try w.writeAll("</a> free. So do search engines and the retrieval crawlers behind AI answers, because they send readers back. A crawler that copies pages into a training corpus sends nobody back, so it pays for the time it spends.</p>\n<div class=\"price\">");
    try esc(w, if (days > 1) total else price);
    if (days > 1) try w.print(" <span class=\"mut\">for {d} days of requests</span></div>\n", .{days}) else try w.print(" <span class=\"mut\">for {d} minutes of requests</span></div>\n", .{g.o.pass_minutes});
    if (!g.enabled) try w.writeAll("<p><strong>Payments are not switched on here yet.</strong> The offer below is empty until the operator configures a payout address, so for now this crawler is simply refused.</p>\n");
    try w.writeAll("<h2>How it works</h2>\n<ol>\n<li>Any page you fetch answers <code>402 Payment Required</code>. This page, fetched with <code>Accept: application/json</code>, returns the x402 offer: USDC, <code>exact</code> scheme, on Base, Polygon or Ethereum.</li>\n<li>Sign the payment and retry with the proof in an <code>X-PAYMENT</code> header. The response is a JSON receipt carrying a pass.</li>\n<li>Send the pass in <code>");
    try esc(w, g.o.header);
    try w.print("</code> on every request until it expires. A proof for a whole multiple of the price buys that many days, up to {d}; <code>?days=&lt;n&gt;</code> quotes n.</li>\n</ol>\n<h2>Pay with the CoinPay CLI</h2>\n<pre><code>npm install -g @profullstack/coinpay\ncoinpay x402 pay ", .{g.o.max_days});
    try esc(w, g.buy_url);
    try w.writeAll(" --output pass.json\nPASS=$(node -p \"require('./pass.json').pass\")\ncurl -H \"");
    try esc(w, g.o.header);
    try w.writeAll(": $PASS\" ");
    try esc(w, g.o.site_url);
    try w.writeAll("/</code></pre>\n<h2>Who pays and who does not</h2>\n<p>Charged: ");
    for (g.o.training, 0..) |a, i| {
        if (i > 0) try w.writeAll(", ");
        try esc(w, a);
    }
    try w.writeAll("</p>\n<p>Free, named in robots.txt: ");
    for (g.o.retrieval, 0..) |a, i| {
        if (i > 0) try w.writeAll(", ");
        try esc(w, a);
    }
    try w.writeAll("</p>\n<p class=\"mut\">Everyone else is free: people, Googlebot, Applebot, Bingbot and any crawler not on the first line.");
    if (g.o.contact.len > 0) {
        try w.writeAll(" For bulk deals, <a href=\"");
        try esc(w, g.o.contact);
        try w.writeAll("\">get in touch</a>.");
    }
    try w.writeAll("</p>\n<footer class=\"mut\">Sold over <a href=\"https://x402.org\">x402</a>, settled by <a href=\"https://coinpayportal.com\">CoinPay</a>. Served by x402-gateway for Zig.</footer>\n</main>\n</body>\n</html>\n");
    return aw.toOwnedSlice();
}

// ----------------------------------------------------------------- gateway --

pub const Request = struct {
    /// The URL path, e.g. "/some/page".
    path: []const u8,
    /// The raw query string without "?", if any.
    query: ?[]const u8 = null,
    headers: []const Header,
};

pub const Response = struct {
    status: u16,
    content_type: []const u8,
    body: []const u8,
    /// On a 200 receipt: the pass and its expiry, to send as `<header>` and `<header>-expires`.
    pass: ?[]const u8 = null,
    pass_expires: ?[]const u8 = null,

    /// Every gateway answer carries these two headers.
    pub const no_store = [_]Header{ .{ .name = "cache-control", .value = "no-store" }, .{ .name = "vary", .value = "Accept, User-Agent, X-Payment" } };
};

pub const Sale = struct { payer: ?[]const u8, ref: ?[]const u8, token: []const u8, expires_at: []const u8, user_agent: []const u8, price_cents: f64, days: i64, total_cents: f64, currency: []const u8 };

pub const Options = struct {
    site_url: []const u8,
    site_name: ?[]const u8 = null,
    coinpay_api_key: []const u8 = "",
    coinpay_base_url: []const u8 = "https://coinpayportal.com",
    pay_to: []const u8 = "",
    price_cents: f64 = 100,
    currency: []const u8 = "USD",
    pass_minutes: i64 = 1440,
    max_days: i64 = 30,
    header: []const u8 = "x-crawl-pass",
    path: []const u8 = "/crawl",
    open_paths: []const []const u8 = &.{},
    is_paid_agent: ?*const fn (user_agent: []const u8) bool = null,
    deny_cidrs: []const []const u8 = &.{},
    charge_spoofed_browsers: bool = false,
    exempt: ?*const fn (req: Request) bool = null,
    secret: []const u8 = "",
    training: []const []const u8 = &training_agents,
    retrieval: []const []const u8 = &retrieval_agents,
    contact: []const u8 = "",
    on_sale: ?*const fn (sale: Sale) void = null,
    transport: ?Transport = null,
    /// Unix seconds. Set this, or `io`, so the gateway can read the clock; tests set it to a constant.
    now: ?*const fn () i64 = null,
    /// Your `std.Io`, used for the wall clock when `now` is not set.
    io: ?std.Io = null,
};

pub const PassInfo = struct { price: []const u8, minutes: i64, days: i64, total: []const u8, maxDays: i64, header: []const u8, buy: []const u8, buyDays: []const u8 };
pub const Receipt = struct { x402Version: u8, accepts: []const Accept, pass: PassInfo, @"error": ?[]const u8 = null };

pub const Gateway = struct {
    o: Options,
    site_name: []const u8,
    site_url: []const u8,
    enabled: bool,
    secret: []const u8,
    denied: []Cidr,
    buy_url: []const u8,
    header_lower: []const u8,

    /// Build a gateway. `gpa` owns the little the gateway keeps (compiled CIDRs, the buy URL).
    pub fn init(gpa: Allocator, o: Options) !Gateway {
        const site_url = std.mem.trimEnd(u8, o.site_url, "/");
        if (site_url.len == 0) return error.NoSiteUrl;
        var site_name: []const u8 = o.site_name orelse site_url;
        if (o.site_name == null) {
            if (std.mem.indexOf(u8, site_url, "//")) |i| {
                var host = site_url[i + 2 ..];
                if (std.mem.indexOfScalar(u8, host, '/')) |j| host = host[0..j];
                if (std.mem.indexOfScalar(u8, host, ':')) |j| host = host[0..j];
                if (host.len > 0) site_name = host;
            }
        }
        const header_lower = try std.ascii.allocLowerString(gpa, if (o.header.len == 0) "x-crawl-pass" else o.header);
        var opts = o;
        opts.site_url = site_url;
        opts.header = header_lower;
        if (opts.path.len == 0) opts.path = "/crawl";
        if (opts.pass_minutes <= 0) opts.pass_minutes = 1440;
        if (opts.max_days < 1) opts.max_days = 30;
        if (!std.math.isFinite(opts.price_cents)) opts.price_cents = 100;
        opts.coinpay_base_url = std.mem.trimEnd(u8, opts.coinpay_base_url, "/");
        return .{
            .o = opts,
            .site_name = site_name,
            .site_url = site_url,
            .enabled = o.coinpay_api_key.len > 0 and o.pay_to.len > 0,
            .secret = if (o.secret.len > 0) o.secret else o.coinpay_api_key,
            .denied = try compileCidrs(gpa, o.deny_cidrs),
            .buy_url = try std.fmt.allocPrint(gpa, "{s}{s}", .{ site_url, opts.path }),
            .header_lower = header_lower,
        };
    }

    pub fn deinit(g: *Gateway, gpa: Allocator) void {
        gpa.free(g.denied);
        gpa.free(g.buy_url);
        gpa.free(g.header_lower);
    }

    pub fn money(g: *const Gateway, arena: Allocator, cents: f64) ![]u8 {
        return std.fmt.allocPrint(arena, "{d:.2} {s}", .{ cents / 100.0, g.o.currency });
    }

    fn now(g: *const Gateway) i64 {
        if (g.o.now) |f| return f();
        if (g.o.io) |io| return std.Io.Timestamp.now(io, .real).toSeconds();
        return 0; // no clock: every pass reads as live only if you pass `now` or `io`
    }

    fn isOpen(g: *const Gateway, path: []const u8) bool {
        const fixed = [_][]const u8{ "/robots.txt", g.o.path, "/security.txt", "/.well-known/" };
        for (&fixed) |p| if (openMatch(p, path)) return true;
        for (g.o.open_paths) |p| if (openMatch(p, path)) return true;
        return false;
    }

    fn openMatch(p: []const u8, path: []const u8) bool {
        return if (std.mem.endsWith(u8, p, "/")) std.mem.startsWith(u8, path, p) else std.mem.eql(u8, path, p);
    }

    fn daysFrom(g: *const Gateway, query: ?[]const u8) i64 {
        const q = query orelse return 1;
        var it = std.mem.splitScalar(u8, q, '&');
        var raw: ?[]const u8 = null;
        while (it.next()) |kv| {
            if (std.mem.startsWith(u8, kv, "days=")) raw = kv[5..] else if (std.mem.eql(u8, kv, "days")) raw = "";
        }
        const s = std.mem.trimStart(u8, raw orelse return 1, " \t");
        var end: usize = 0;
        if (end < s.len and (s[end] == '+' or s[end] == '-')) end += 1;
        const digits_start = end;
        while (end < s.len and std.ascii.isDigit(s[end])) end += 1;
        if (end == digits_start) return 1;
        const n = std.fmt.parseInt(i64, s[0..end], 10) catch return if (s[0] == '-') 1 else g.o.max_days;
        if (n < 1) return 1;
        return @min(n, g.o.max_days);
    }

    /// The offer for `days` terms: the same entries, `days` times the price.
    pub fn offer(g: *const Gateway, arena: Allocator, days: i64) !Offer {
        if (!g.enabled) return .{};
        const description = if (days > 1)
            try std.fmt.allocPrint(arena, "{d} minutes of crawl access to {s} ({d} × {d})", .{ days * g.o.pass_minutes, g.site_url, days, g.o.pass_minutes })
        else
            try std.fmt.allocPrint(arena, "{d} minutes of crawl access to {s}", .{ g.o.pass_minutes, g.site_url });
        return buildOffer(arena, g.o.pay_to, g.o.price_cents * @as(f64, @floatFromInt(days)), g.buy_url, description, 300);
    }

    fn receipt(g: *const Gateway, arena: Allocator, days: i64, err: ?[]const u8) !Receipt {
        const o = try g.offer(arena, days);
        return .{
            .x402Version = o.x402Version,
            .accepts = o.accepts,
            .pass = .{
                .price = try g.money(arena, g.o.price_cents),
                .minutes = g.o.pass_minutes,
                .days = days,
                .total = try g.money(arena, g.o.price_cents * @as(f64, @floatFromInt(days))),
                .maxDays = g.o.max_days,
                .header = g.o.header,
                .buy = if (days > 1) try std.fmt.allocPrint(arena, "{s}?days={d}", .{ g.buy_url, days }) else g.buy_url,
                .buyDays = try std.fmt.allocPrint(arena, "{s}?days=<n>", .{g.buy_url}),
            },
            .@"error" = err,
        };
    }

    fn json(arena: Allocator, body: anytype, status: u16) !Response {
        return .{ .status = status, .content_type = "application/json; charset=utf-8", .body = try std.json.Stringify.valueAlloc(arena, body, .{ .whitespace = .indent_2, .emit_null_optional_fields = false }) };
    }

    /// robots.txt with this gateway's lists and sales path; `extra` fields override.
    pub fn robots(g: *const Gateway, arena: Allocator, extra: RobotsOptions) ![]u8 {
        var o = extra;
        if (o.site_url.len == 0) o.site_url = g.site_url;
        if (std.mem.eql(u8, o.path, "/crawl")) o.path = g.o.path;
        return robotsTxt(arena, o);
    }

    /// The sales page as HTML, for a site that mounts it on a route of its own.
    pub fn page(g: *const Gateway, arena: Allocator) ![]u8 {
        return renderPage(arena, g, 1);
    }

    fn passFrom(g: *const Gateway, headers: []const Header) ?[]const u8 {
        if (header(headers, g.o.header)) |direct| {
            const t = std.mem.trim(u8, direct, " \t");
            if (t.len > 0) return t;
        }
        const auth = header(headers, "authorization") orelse return null;
        if (auth.len < 7 or !std.ascii.eqlIgnoreCase(auth[0..6], "Bearer")) return null;
        const rest = auth[6..];
        const token = std.mem.trimStart(u8, rest, " \t");
        if (token.len == rest.len or !std.mem.startsWith(u8, token, "cp_")) return null;
        const dot = std.mem.indexOfScalar(u8, token, '.') orelse return null;
        if (dot == 3 or dot + 1 >= token.len) return null;
        for (token[3..]) |c| if (!(std.ascii.isAlphanumeric(c) or c == '_' or c == '-' or c == '.')) return null;
        return token;
    }

    /// Whether handling this request may call CoinPay (only a proof does).
    pub fn needsIo(req: Request) bool {
        return header(req.headers, "x-payment") != null;
    }

    fn isPaid(g: *const Gateway, ua: []const u8) bool {
        return if (g.o.is_paid_agent) |f| f(ua) else isTrainingAgent(ua, g.o.training);
    }

    /// Answer one request with the sale: a pass as the body of a 200, or a 402 with the offer.
    pub fn sell(g: *const Gateway, arena: Allocator, req: Request) !Response {
        const ua = header(req.headers, "user-agent") orelse "";
        const proof_header = header(req.headers, "x-payment") orelse "";
        const asked = g.daysFrom(req.query);

        if (proof_header.len > 0) {
            if (!g.enabled) return json(arena, try g.receipt(arena, asked, "Payments are not switched on here."), 402);
            const payment = decodePayment(arena, proof_header) orelse return json(arena, try g.receipt(arena, asked, "X-PAYMENT is not base64 JSON."), 402);
            const unit = expectedFor(arena, payment, try g.offer(arena, 1)) orelse return json(arena, try g.receipt(arena, asked, "Proof does not match an offered network."), 402);
            const days = daysPaid(paidValueOf(payment), unit.amount, g.o.max_days);
            if (days == 0) {
                const msg = try std.fmt.allocPrint(arena, "Pay a whole number of days: {s} per day in the token's smallest unit, up to {d} days. Add ?days=<n> to {s} for the offer.", .{ unit.amount, g.o.max_days, g.buy_url });
                return json(arena, try g.receipt(arena, asked, msg), 402);
            }
            const expected = expectedFor(arena, payment, try g.offer(arena, days)) orelse unit;
            const term = days * g.o.pass_minutes * 60;
            const t_now = g.now();
            const transport = g.o.transport orelse return json(arena, try g.receipt(arena, days, "No CoinPay transport configured."), 402);
            const result = try verifyAndSettle(arena, transport, g.o.coinpay_api_key, g.o.coinpay_base_url, payment, expected);

            var expires_at: ?i64 = null;
            var replayed = false;
            if (result.ok) {
                expires_at = t_now + term;
            } else if (result.replay) {
                const paid = try settleAgain(arena, transport, g.o.coinpay_api_key, g.o.coinpay_base_url, payment);
                if (validBeforeOf(arena, payment)) |vb| {
                    if (paid) {
                        expires_at = @min(t_now + term, vb + term);
                        replayed = true;
                    }
                }
            }
            const exp = expires_at orelse return json(arena, try g.receipt(arena, days, result.reason orelse "Payment could not be settled."), 402);
            if (exp <= t_now) return json(arena, try g.receipt(arena, days, result.reason orelse "Payment could not be settled."), 402);

            const ref = nonceOf(arena, payment) orelse result.ref;
            const token = try mintPass(arena, g.secret, ref, exp, t_now);
            const expires = try iso(arena, exp);
            if (g.o.on_sale) |f| if (!replayed) f(.{ .payer = result.payer, .ref = ref, .token = token, .expires_at = expires, .user_agent = ua, .price_cents = g.o.price_cents, .days = days, .total_cents = g.o.price_cents * @as(f64, @floatFromInt(days)), .currency = g.o.currency });
            const body = .{
                .ok = true,
                .pass = token,
                .expires_at = expires,
                .days = days,
                .minutes = days * g.o.pass_minutes,
                .header = g.o.header,
                .replayed = replayed,
                .use = try std.fmt.allocPrint(arena, "curl -H \"{s}: {s}\" {s}/", .{ g.o.header, token, g.site_url }),
            };
            var res = try json(arena, body, 200);
            res.pass = token;
            res.pass_expires = expires;
            return res;
        }

        if (header(req.headers, "accept")) |accept| {
            if (std.ascii.indexOfIgnoreCase(accept, "text/html") != null) {
                return .{ .status = 402, .content_type = "text/html; charset=utf-8", .body = try renderPage(arena, g, asked) };
            }
        }
        const msg = try std.fmt.allocPrint(arena, "Payment required for training crawlers. Read {s} for how.", .{g.buy_url});
        return json(arena, try g.receipt(arena, asked, msg), 402);
    }

    /// The gate. Null means "not for me, carry on".
    pub fn handle(g: *const Gateway, arena: Allocator, req: Request) !?Response {
        if (g.denied.len > 0 and inCidrs(clientIp(req.headers), g.denied)) {
            return .{ .status = 403, .content_type = "text/plain; charset=utf-8", .body = "Not available from this network.\n" };
        }
        const path = if (req.path.len == 0) "/" else req.path;
        if (std.mem.eql(u8, path, g.o.path)) return try g.sell(arena, req);
        if (g.o.exempt) |f| if (f(req)) return null;
        const pays = g.isPaid(header(req.headers, "user-agent") orelse "") or (g.o.charge_spoofed_browsers and isSpoofedBrowser(req.headers));
        if (!pays or g.isOpen(path)) return null;
        if (g.passFrom(req.headers)) |token| {
            if (readPass(arena, token, g.secret, g.now()) != null) return null;
        }
        return try g.sell(arena, req);
    }
};

fn iso(arena: Allocator, ts: i64) ![]u8 {
    const days = @divFloor(ts, 86400);
    const secs = @mod(ts, 86400);
    const z = days + 719468;
    const era = @divFloor(z, 146097);
    const doe = z - era * 146097;
    const yoe = @divFloor(doe - @divFloor(doe, 1460) + @divFloor(doe, 36524) - @divFloor(doe, 146096), 365);
    const doy = doe - (365 * yoe + @divFloor(yoe, 4) - @divFloor(yoe, 100));
    const mp = @divFloor(5 * doy + 2, 153);
    const d = doy - @divFloor(153 * mp + 2, 5) + 1;
    const m = if (mp < 10) mp + 3 else mp - 9;
    const y = yoe + era * 400 + @as(i64, if (m <= 2) 1 else 0);
    return std.fmt.allocPrint(arena, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.000Z", .{ y, m, d, @divFloor(secs, 3600), @mod(@divFloor(secs, 60), 60), @mod(secs, 60) });
}

test {
    _ = @import("vectors_test.zig");
}
