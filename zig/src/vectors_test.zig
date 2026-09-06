//! Every port runs the same fixtures: spec/vectors.json, generated from the JS reference.
const std = @import("std");
const x = @import("root.zig");
const Value = std.json.Value;

fn load(arena: std.mem.Allocator) !Value {
    const path = "../spec/vectors.json"; // `zig build test` runs from the build root
    const text = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, arena, .unlimited);
    return std.json.parseFromSliceLeaky(Value, arena, text, .{});
}

fn get(v: Value, key: []const u8) Value {
    return v.object.get(key) orelse .null;
}
fn str(v: Value) []const u8 {
    return if (v == .string) v.string else "";
}
fn int(v: Value) i64 {
    return switch (v) {
        .integer => |i| i,
        .float => |f| @intFromFloat(f),
        else => 0,
    };
}
fn boolean(v: Value) bool {
    return v == .bool and v.bool;
}
fn strs(arena: std.mem.Allocator, v: Value) ![]const []const u8 {
    if (v != .array) return &.{};
    const out = try arena.alloc([]const u8, v.array.items.len);
    for (v.array.items, 0..) |s, i| out[i] = str(s);
    return out;
}
fn headers(arena: std.mem.Allocator, v: Value) ![]x.Header {
    var out: std.ArrayList(x.Header) = .empty;
    if (v == .object) {
        var it = v.object.iterator();
        while (it.next()) |e| try out.append(arena, .{ .name = e.key_ptr.*, .value = str(e.value_ptr.*) });
    }
    return out.toOwnedSlice(arena);
}

fn jsonEql(a: Value, b: Value) bool {
    if (std.meta.activeTag(a) != std.meta.activeTag(b)) {
        // 1 vs 1.0
        if ((a == .integer or a == .float) and (b == .integer or b == .float)) {
            const fa: f64 = if (a == .integer) @floatFromInt(a.integer) else a.float;
            const fb: f64 = if (b == .integer) @floatFromInt(b.integer) else b.float;
            return fa == fb;
        }
        return false;
    }
    return switch (a) {
        .null => true,
        .bool => a.bool == b.bool,
        .integer => a.integer == b.integer,
        .float => a.float == b.float,
        .number_string, .string => std.mem.eql(u8, str(a), str(b)),
        .array => blk: {
            if (a.array.items.len != b.array.items.len) break :blk false;
            for (a.array.items, b.array.items) |p, q| if (!jsonEql(p, q)) break :blk false;
            break :blk true;
        },
        .object => blk: {
            if (a.object.count() != b.object.count()) break :blk false;
            var it = a.object.iterator();
            while (it.next()) |e| {
                const other = b.object.get(e.key_ptr.*) orelse break :blk false;
                if (!jsonEql(e.value_ptr.*, other)) break :blk false;
            }
            break :blk true;
        },
    };
}

fn expectJson(arena: std.mem.Allocator, got_text: []const u8, want: Value, name: []const u8) !void {
    const got = try std.json.parseFromSliceLeaky(Value, arena, got_text, .{});
    if (!jsonEql(got, want)) {
        std.debug.print("JSON mismatch: {s}\n got: {s}\nwant: {s}\n", .{ name, got_text, try std.json.Stringify.valueAlloc(arena, want, .{}) });
        return error.TestExpectedEqual;
    }
}

const SITE = "https://example.com";
const SECRET = "cp_live_test_secret_0123456789";
const NOW: i64 = 1_800_000_000;
fn nowFn() i64 {
    return NOW;
}
fn exemptFn(req: x.Request) bool {
    return std.mem.indexOf(u8, x.header(req.headers, "cookie") orelse "", "session=") != null;
}

const Mock = struct {
    verify: Value,
    settle: ?Value,
    settle_again: ?Value,
    settles: usize = 0,
    verify_body: ?Value = null,
    fn post(ctx: *anyopaque, arena: std.mem.Allocator, url: []const u8, api_key: []const u8, body: []const u8) anyerror!x.PostResult {
        const self: *Mock = @ptrCast(@alignCast(ctx));
        try std.testing.expectEqualStrings(SECRET, api_key);
        const out: Value = if (std.mem.endsWith(u8, url, "/api/x402/verify")) blk: {
            self.verify_body = try std.json.parseFromSliceLeaky(Value, arena, body, .{});
            break :blk self.verify;
        } else blk: {
            self.settles += 1;
            if (self.settles == 1 and self.settle != null) break :blk self.settle.?;
            break :blk self.settle_again orelse self.settle orelse Value{ .object = .empty };
        };
        return .{ .status = 200, .body = try std.json.Stringify.valueAlloc(arena, out, .{}) };
    }
};

var sales: usize = 0;
fn onSale(_: x.Sale) void {
    sales += 1;
}

fn gateway(gpa: std.mem.Allocator, v: Value, transport: ?x.Transport, on_sale: bool) !x.Gateway {
    const arena = gpa;
    const g = get(v, "gateway");
    return x.Gateway.init(gpa, .{
        .site_url = str(get(g, "siteUrl")),
        .coinpay_api_key = str(get(get(g, "coinpay"), "apiKey")),
        .pay_to = str(get(g, "payTo")),
        .deny_cidrs = try strs(arena, get(g, "denyCidrs")),
        .charge_spoofed_browsers = boolean(get(g, "chargeSpoofedBrowsers")),
        .open_paths = try strs(arena, get(g, "openPaths")),
        .exempt = exemptFn,
        .now = nowFn,
        .transport = transport,
        .on_sale = if (on_sale) onSale else null,
    });
}

test "passes" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const v = try load(arena);
    for (get(v, "passes").array.items) |p| {
        const ref: ?[]const u8 = if (get(p, "ref") == .string) str(get(p, "ref")) else null;
        const got = try x.mintPass(arena, str(get(p, "secret")), ref, int(get(p, "exp")), int(get(p, "iat")));
        try std.testing.expectEqualStrings(str(get(p, "token")), got);
    }
    for (get(v, "readPass").array.items) |c| {
        const secret = if (get(c, "secret") == .string) str(get(c, "secret")) else SECRET;
        const r = x.readPass(arena, str(get(c, "token")), secret, int(get(c, "now")));
        try std.testing.expectEqual(boolean(get(c, "ok")), r != null);
        if (r) |claims| {
            try std.testing.expectEqual(@as(f64, @floatFromInt(int(get(get(c, "claims"), "exp")))), claims.exp);
        }
    }
}

test "offers, payments, days" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const v = try load(arena);
    for (get(v, "offers").array.items) |o| {
        const i = get(o, "in");
        const price: f64 = switch (get(i, "priceCents")) {
            .integer => |n| @floatFromInt(n),
            .float => |f| f,
            else => 0,
        };
        const mts: u32 = if (get(i, "maxTimeoutSeconds") == .integer) @intCast(int(get(i, "maxTimeoutSeconds"))) else 300;
        const offer = try x.buildOffer(arena, str(get(i, "payTo")), price, str(get(i, "resource")), str(get(i, "description")), mts);
        try expectJson(arena, try std.json.Stringify.valueAlloc(arena, offer, .{}), get(o, "out"), "offer");
    }
    const first = get(get(v, "offers").array.items[0], "in");
    const offer = try x.buildOffer(arena, str(get(first, "payTo")), 100, str(get(first, "resource")), str(get(first, "description")), 300);
    for (get(v, "payments").array.items) |p| {
        const d = x.decodePayment(arena, str(get(p, "header")));
        try std.testing.expectEqual(boolean(get(p, "decodes")), d != null);
        if (p.object.get("expected")) |want| {
            const got = if (d) |dd| x.expectedFor(arena, dd, offer) else null;
            if (want == .null) {
                try std.testing.expect(got == null);
            } else {
                try std.testing.expect(got != null);
                try expectJson(arena, try std.json.Stringify.valueAlloc(arena, got.?, .{}), want, "expectedFor");
            }
        }
    }
    for (get(v, "daysPaid").array.items) |d| {
        const raw = get(d, "value");
        var val: ?u128 = if (raw == .null) null else x.bigint(raw);
        if (val != null and val.? == 0) val = null;
        try std.testing.expectEqual(int(get(d, "days")), x.daysPaid(val, str(get(d, "unit")), int(get(d, "maxDays"))));
    }
}

test "agents, edge, robots" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const v = try load(arena);
    for (get(v, "agents").array.items) |a| {
        try std.testing.expectEqual(boolean(get(a, "training")), x.isTrainingAgent(str(get(a, "ua")), &x.training_agents));
    }
    const cidrs = get(v, "cidrs");
    const c = try x.compileCidrs(arena, try strs(arena, get(cidrs, "list")));
    try std.testing.expectEqual(get(cidrs, "compiled").array.items.len, c.len);
    for (get(cidrs, "cases").array.items) |k| try std.testing.expectEqual(boolean(get(k, "hit")), x.inCidrs(str(get(k, "ip")), c));
    const n = try x.compileCidrs(arena, try strs(arena, get(get(cidrs, "narrow"), "list")));
    for (get(get(cidrs, "narrow"), "cases").array.items) |k| try std.testing.expectEqual(boolean(get(k, "hit")), x.inCidrs(str(get(k, "ip")), n));
    for (get(v, "clientIp").array.items) |k| {
        try std.testing.expectEqualStrings(str(get(k, "ip")), x.clientIp(try headers(arena, get(k, "headers"))));
    }
    for (get(v, "spoofs").array.items) |s| {
        var hs: std.ArrayList(x.Header) = .empty;
        try hs.append(arena, .{ .name = "user-agent", .value = str(get(s, "ua")) });
        try hs.appendSlice(arena, try headers(arena, get(s, "headers")));
        try std.testing.expectEqual(boolean(get(s, "spoofed")), x.isSpoofedBrowser(hs.items));
    }
    for (get(v, "robots").array.items) |r| {
        const i = get(r, "in");
        var o: x.RobotsOptions = .{ .site_url = str(get(i, "siteUrl")) };
        if (i.object.get("disallow")) |d| o.disallow = try strs(arena, d);
        if (i.object.get("allow")) |d| o.allow = try strs(arena, d);
        if (i.object.get("sitemap")) |d| o.sitemap = str(d);
        if (i.object.get("path")) |d| o.path = str(d);
        if (i.object.get("refused")) |d| o.refused = try strs(arena, d);
        if (i.object.get("training")) |d| o.training = try strs(arena, d);
        if (i.object.get("retrieval")) |d| o.retrieval = try strs(arena, d);
        if (i.object.get("comments")) |d| o.comments = try strs(arena, d);
        try std.testing.expectEqualStrings(str(get(r, "out")), try x.robotsTxt(arena, o));
    }
}

fn check(arena: std.mem.Allocator, g: *const x.Gateway, c: Value) !void {
    const name = str(get(c, "name"));
    const url = str(get(c, "url"));
    var path = url;
    var query: ?[]const u8 = null;
    if (std.mem.indexOfScalar(u8, url, '?')) |q| {
        path = url[0..q];
        query = url[q + 1 ..];
    }
    const r = try g.handle(arena, .{ .path = path, .query = query, .headers = try headers(arena, get(c, "headers")) });
    if (boolean(get(c, "pass"))) {
        if (r != null) {
            std.debug.print("{s}: expected pass-through, got {d}\n", .{ name, r.?.status });
            return error.TestUnexpectedResult;
        }
        return;
    }
    const a = r orelse {
        std.debug.print("{s}: passed through\n", .{name});
        return error.TestUnexpectedResult;
    };
    try std.testing.expectEqual(@as(u16, @intCast(int(get(c, "status")))), a.status);
    if (get(c, "contentType") == .string) {
        const ct = a.content_type[0 .. std.mem.indexOfScalar(u8, a.content_type, ';') orelse a.content_type.len];
        try std.testing.expectEqualStrings(str(get(c, "contentType")), ct);
    }
    if (c.object.get("body")) |b| try expectJson(arena, a.body, b, name);
    if (get(c, "text") == .string) try std.testing.expectEqualStrings(str(get(c, "text")), a.body);
    if (get(c, "htmlContains") == .array) for (get(c, "htmlContains").array.items) |s| {
        if (std.mem.indexOf(u8, a.body, str(s)) == null) {
            std.debug.print("{s}: html lacks {s}\n", .{ name, str(s) });
            return error.TestUnexpectedResult;
        }
    };
}

test "handle" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const v = try load(arena);
    var g = try gateway(arena, v, null, false);
    defer g.deinit(arena);
    for (get(v, "handle").array.items) |c| try check(arena, &g, c);
    var d = try x.Gateway.init(arena, .{ .site_url = SITE, .now = nowFn });
    defer d.deinit(arena);
    for (get(v, "disabled").array.items) |c| try check(arena, &d, c);
    try std.testing.expectEqualStrings(try x.robotsTxt(arena, .{ .site_url = SITE }), try g.robots(arena, .{ .site_url = "" }));
    try std.testing.expect(std.mem.indexOf(u8, try g.page(arena), "1.00 USD") != null);
}

test "paid" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const v = try load(arena);
    for (get(get(v, "coinpay"), "paid").array.items) |c| {
        const name = str(get(c, "name"));
        var mock = Mock{ .verify = get(c, "verify"), .settle = c.object.get("settle"), .settle_again = c.object.get("settleAgain") };
        sales = 0;
        var g = try gateway(arena, v, .{ .ctx = &mock, .post = Mock.post }, true);
        defer g.deinit(arena);
        const proof_json = try std.json.Stringify.valueAlloc(arena, get(c, "proof"), .{});
        const enc = std.base64.standard.Encoder;
        const proof = try arena.alloc(u8, enc.calcSize(proof_json.len));
        _ = enc.encode(proof, proof_json);
        const hs = [_]x.Header{ .{ .name = "x-payment", .value = proof }, .{ .name = "user-agent", .value = "curl/8" } };
        const r = (try g.handle(arena, .{ .path = "/crawl", .headers = &hs })) orelse return error.TestUnexpectedResult;
        if (r.status != int(get(c, "status"))) {
            std.debug.print("{s}: status {d} body {s}\n", .{ name, r.status, r.body });
            return error.TestUnexpectedResult;
        }
        const body = try std.json.parseFromSliceLeaky(Value, arena, r.body, .{});
        if (r.status == 200) {
            try std.testing.expect(boolean(get(body, "ok")));
            try std.testing.expectEqual(int(get(c, "days")), int(get(body, "days")));
            if (get(c, "minutes") == .integer) try std.testing.expectEqual(int(get(c, "minutes")), int(get(body, "minutes")));
            try std.testing.expectEqual(boolean(get(c, "replayed")), boolean(get(body, "replayed")));
            const claims = x.readPass(arena, str(get(body, "pass")), SECRET, NOW) orelse return error.TestUnexpectedResult;
            if (get(c, "ref") == .string) try std.testing.expectEqualStrings(str(get(c, "ref")), claims.ref.?);
            if (get(c, "expiresAt") == .integer) try std.testing.expectEqual(@as(f64, @floatFromInt(int(get(c, "expiresAt")))), claims.exp);
            try std.testing.expectEqualStrings(str(get(body, "pass")), r.pass.?);
            try std.testing.expectEqual(@as(usize, if (boolean(get(c, "replayed"))) 0 else 1), sales);
            const amount = str(get(get(mock.verify_body.?, "expected"), "amount"));
            try std.testing.expectEqualStrings(try std.fmt.allocPrint(arena, "{d}", .{1_000_000 * int(get(c, "days"))}), amount);
        } else {
            if (get(c, "error") == .string) try std.testing.expectEqualStrings(str(get(c, "error")), str(get(body, "error")));
            try std.testing.expectEqual(@as(usize, 0), sales);
        }
    }
}
