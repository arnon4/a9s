//! Network ACL evaluation for the network map. Pure functions over loaded rules.
//!
//! NACLs are stateless, so a flow only passes when both directions are allowed:
//! the request on one side and the return traffic on the other. The map tests a
//! representative TCP flow (port 443, ephemeral return port) against each routed
//! destination.
const std = @import("std");
const Ec2 = @import("../../../sdk/clients/ec2/client.zig");

/// Port the probed flow targets.
pub const service_port: u16 = 443;
/// Source port of the return traffic; falls inside every common ephemeral range.
pub const ephemeral_port: u16 = 50000;
/// Stand-in destination for the default route.
pub const internet_probe: [4]u8 = .{ 8, 8, 8, 8 };

pub const Cidr4 = struct {
    addr: [4]u8,
    prefix: u8,
};

pub fn parseCidr4(text: []const u8) ?Cidr4 {
    const slash = std.mem.findScalar(u8, text, '/') orelse return null;
    const prefix = std.fmt.parseInt(u8, text[slash + 1 ..], 10) catch return null;
    if (prefix > 32) return null;

    var addr: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, text[0..slash], '.');
    var n: usize = 0;
    while (it.next()) |part| : (n += 1) {
        if (n >= 4) return null;
        addr[n] = std.fmt.parseInt(u8, part, 10) catch return null;
    }
    if (n != 4) return null;
    return .{ .addr = addr, .prefix = prefix };
}

fn toInt(addr: [4]u8) u32 {
    return std.mem.readInt(u32, &addr, .big);
}

pub fn cidrContains(cidr: Cidr4, addr: [4]u8) bool {
    if (cidr.prefix == 0) return true;
    const shift: u5 = @intCast(32 - cidr.prefix);
    return (toInt(cidr.addr) >> shift) == (toInt(addr) >> shift);
}

/// A representative address inside a route destination, or null when it cannot be tested
/// (IPv6 or a prefix list).
pub fn probeAddress(destination: []const u8) ?[4]u8 {
    const cidr = parseCidr4(destination) orelse return null;
    if (cidr.prefix == 0) return internet_probe;
    var addr = cidr.addr;
    if (cidr.prefix <= 30) addr[3] +%= 1;
    return addr;
}

pub const Verdict = struct {
    allowed: bool,
    /// Rule that decided; 0 when no rule matched (implicit deny).
    rule: i32,
};

fn protocolMatchesTcp(protocol: []const u8) bool {
    return std.mem.eql(u8, protocol, "-1") or std.mem.eql(u8, protocol, "6") or std.ascii.eqlIgnoreCase(protocol, "tcp");
}

fn entryMatches(e: Ec2.NetworkAclEntry, egress: bool, addr: [4]u8, port: u16) bool {
    if (e.egress != egress) return false;
    const cidr = parseCidr4(e.cidr_block) orelse return false;
    if (!cidrContains(cidr, addr)) return false;
    if (!protocolMatchesTcp(e.protocol)) return false;
    if (std.mem.eql(u8, e.protocol, "-1")) return true;
    if (e.port_from) |from| {
        const to = e.port_to orelse from;
        return port >= from and port <= to;
    }
    return true;
}

/// First matching rule by ascending rule number decides, like AWS.
pub fn evaluate(entries: []const Ec2.NetworkAclEntry, egress: bool, addr: [4]u8, port: u16) Verdict {
    var best: ?Ec2.NetworkAclEntry = null;
    for (entries) |e| {
        if (!entryMatches(e, egress, addr, port)) continue;
        if (best == null or e.rule_number < best.?.rule_number) best = e;
    }
    if (best) |b| return .{ .allowed = b.allow, .rule = b.rule_number };
    return .{ .allowed = false, .rule = 0 };
}

pub const Flow = enum { outbound, inbound };

pub const Outcome = union(enum) {
    ok,
    /// Which leg failed and why; formatted for the detail line.
    blocked: Failure,
    /// The destination cannot be tested (IPv6, prefix list).
    unknown,
};

pub const Failure = struct {
    /// True when the failing leg is the return traffic.
    is_return: bool,
    /// Direction of the failing rule.
    egress: bool,
    verdict: Verdict,
    addr: [4]u8,
};

/// Tests the probe flow to or from `destination` against `acl`.
pub fn check(acl: Ec2.NetworkAcl, destination: []const u8, flow: Flow) Outcome {
    const addr = probeAddress(destination) orelse return .unknown;

    // Outbound: request leaves (egress), reply returns (ingress). Inbound is the mirror image.
    const request_egress = flow == .outbound;
    const request = evaluate(acl.entries, request_egress, addr, service_port);
    if (!request.allowed) return .{ .blocked = .{ .is_return = false, .egress = request_egress, .verdict = request, .addr = addr } };

    const reply = evaluate(acl.entries, !request_egress, addr, ephemeral_port);
    if (!reply.allowed) return .{ .blocked = .{ .is_return = true, .egress = !request_egress, .verdict = reply, .addr = addr } };

    return .ok;
}

// ─── Tests ───────────────────────────────────────────────────────────────────

fn entry(rule: i32, egress: bool, allow: bool, cidr: []const u8, protocol: []const u8, from: ?u32, to: ?u32) Ec2.NetworkAclEntry {
    return .{
        .rule_number = rule,
        .protocol = @constCast(protocol),
        .allow = allow,
        .egress = egress,
        .cidr_block = @constCast(cidr),
        .ipv6_cidr_block = @constCast(""),
        .port_from = from,
        .port_to = to,
    };
}

fn aclWith(entries: []Ec2.NetworkAclEntry) Ec2.NetworkAcl {
    return .{
        .allocator = std.testing.allocator,
        .network_acl_id = @constCast("acl-1"),
        .vpc_id = @constCast("vpc-1"),
        .owner_id = @constCast(""),
        .is_default = false,
        .name = @constCast(""),
        .tags = &.{},
        .associations = &.{},
        .entries = entries,
    };
}

test "parseCidr4 and cidrContains" {
    const c = parseCidr4("10.1.0.0/16").?;
    try std.testing.expect(cidrContains(c, .{ 10, 1, 200, 3 }));
    try std.testing.expect(!cidrContains(c, .{ 10, 2, 0, 1 }));
    try std.testing.expect(cidrContains(parseCidr4("0.0.0.0/0").?, .{ 8, 8, 8, 8 }));
    try std.testing.expect(parseCidr4("::/0") == null);
    try std.testing.expect(parseCidr4("10.0.0.0/33") == null);
    try std.testing.expect(parseCidr4("10.0.0/8") == null);
}

test "probeAddress picks an address inside the destination" {
    try std.testing.expectEqual(internet_probe, probeAddress("0.0.0.0/0").?);
    try std.testing.expectEqual([4]u8{ 10, 1, 0, 1 }, probeAddress("10.1.0.0/16").?);
    try std.testing.expectEqual([4]u8{ 10, 1, 0, 7 }, probeAddress("10.1.0.7/32").?);
    try std.testing.expect(probeAddress("pl-123") == null);
    try std.testing.expect(probeAddress("2600::/64") == null);
}

test "lowest rule number decides" {
    var entries = [_]Ec2.NetworkAclEntry{
        entry(200, true, true, "0.0.0.0/0", "-1", null, null),
        entry(100, true, false, "8.8.8.0/24", "6", 443, 443),
        entry(32767, true, false, "0.0.0.0/0", "-1", null, null),
    };
    const v = evaluate(&entries, true, .{ 8, 8, 8, 8 }, 443);
    try std.testing.expect(!v.allowed);
    try std.testing.expectEqual(@as(i32, 100), v.rule);
    // A different port skips the port-scoped deny and falls through to the allow.
    try std.testing.expect(evaluate(&entries, true, .{ 8, 8, 8, 8 }, 80).allowed);
}

test "no matching rule is an implicit deny" {
    var entries = [_]Ec2.NetworkAclEntry{entry(100, true, true, "10.0.0.0/8", "-1", null, null)};
    const v = evaluate(&entries, true, .{ 8, 8, 8, 8 }, 443);
    try std.testing.expect(!v.allowed);
    try std.testing.expectEqual(@as(i32, 0), v.rule);
}

test "stateless: return traffic must also be allowed" {
    var open = [_]Ec2.NetworkAclEntry{
        entry(100, true, true, "0.0.0.0/0", "-1", null, null),
        entry(100, false, true, "0.0.0.0/0", "-1", null, null),
    };
    try std.testing.expect(check(aclWith(&open), "0.0.0.0/0", .outbound) == .ok);

    // Egress open, ingress only allows 443: the ephemeral reply is dropped.
    var no_reply = [_]Ec2.NetworkAclEntry{
        entry(100, true, true, "0.0.0.0/0", "-1", null, null),
        entry(100, false, true, "0.0.0.0/0", "6", 443, 443),
        entry(32767, false, false, "0.0.0.0/0", "-1", null, null),
    };
    const out = check(aclWith(&no_reply), "0.0.0.0/0", .outbound);
    try std.testing.expect(out == .blocked);
    try std.testing.expect(out.blocked.is_return);
    try std.testing.expect(!out.blocked.egress);
    try std.testing.expectEqual(@as(i32, 32767), out.blocked.verdict.rule);
}

test "inbound flow checks ingress request then egress reply" {
    var entries = [_]Ec2.NetworkAclEntry{
        entry(100, false, true, "0.0.0.0/0", "6", 443, 443),
        entry(100, true, false, "0.0.0.0/0", "-1", null, null),
    };
    const out = check(aclWith(&entries), "0.0.0.0/0", .inbound);
    try std.testing.expect(out == .blocked);
    try std.testing.expect(out.blocked.is_return);
    try std.testing.expect(out.blocked.egress);
}

test "untestable destination is unknown" {
    var entries = [_]Ec2.NetworkAclEntry{entry(100, true, true, "0.0.0.0/0", "-1", null, null)};
    try std.testing.expect(check(aclWith(&entries), "pl-123", .outbound) == .unknown);
}
