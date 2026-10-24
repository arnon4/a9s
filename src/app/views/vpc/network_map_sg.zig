//! Security group evaluation for the network map. Pure functions over loaded rules.
//!
//! Security groups attach to network interfaces and are stateful, so only the direction in
//! which the flow starts matters: egress rules for outbound traffic, ingress rules for inbound.
//! The map probes TCP port 443 against each routed destination.
const std = @import("std");
const Ec2 = @import("../../../sdk/clients/ec2/client.zig");
const nacl = @import("network_map_nacl.zig");

pub const Outcome = union(enum) {
    /// A rule allows the flow.
    ok,
    /// No rule allows it; carries the probed address.
    blocked: [4]u8,
    /// Not decidable: IPv6 or prefix list destination, or only prefix list / group rules could match.
    unknown,
};

fn protocolMatchesTcp(protocol: []const u8) bool {
    return std.mem.eql(u8, protocol, "-1") or std.mem.eql(u8, protocol, "6") or std.ascii.eqlIgnoreCase(protocol, "tcp");
}

fn portCovers(rule: Ec2.SecurityGroupRule, port: u16) bool {
    if (std.mem.eql(u8, rule.protocol, "-1")) return true;
    const from = rule.from_port orelse return true;
    const to = rule.to_port orelse from;
    if (from < 0) return true;
    const p: i32 = port;
    return p >= from and p <= to;
}

const Match = enum { none, untestable, yes };

fn ruleMatch(rule: Ec2.SecurityGroupRule, addr: [4]u8) Match {
    if (!protocolMatchesTcp(rule.protocol) or !portCovers(rule, nacl.service_port)) return .none;
    for (rule.ipv4_ranges) |r| {
        const cidr = nacl.parseCidr4(r.cidr) orelse continue;
        if (nacl.cidrContains(cidr, addr)) return .yes;
    }
    // Prefix lists and group references cannot be resolved to addresses here.
    if (rule.prefix_lists.len > 0 or rule.groups.len > 0) return .untestable;
    return .none;
}

/// Tests whether any of `groups` lets the probe flow to or from `destination` through.
pub fn check(groups: []const Ec2.SecurityGroup, flow: nacl.Flow, destination: []const u8) Outcome {
    const addr = nacl.probeAddress(destination) orelse return .unknown;

    var untestable = false;
    for (groups) |g| {
        const rules = if (flow == .outbound) g.egress else g.ingress;
        for (rules) |r| switch (ruleMatch(r, addr)) {
            .yes => return .ok,
            .untestable => untestable = true,
            .none => {},
        };
    }
    return if (untestable) .unknown else .{ .blocked = addr };
}

// ─── Tests ───────────────────────────────────────────────────────────────────

fn range(cidr: []const u8) Ec2.SecurityGroupRange {
    return .{ .cidr = @constCast(cidr), .description = @constCast("") };
}

fn makeRule(protocol: []const u8, from: ?i32, to: ?i32, ranges: []Ec2.SecurityGroupRange) Ec2.SecurityGroupRule {
    return .{ .protocol = @constCast(protocol), .from_port = from, .to_port = to, .groups = &.{}, .ipv4_ranges = ranges, .ipv6_ranges = &.{}, .prefix_lists = &.{} };
}

fn group(ingress: []Ec2.SecurityGroupRule, egress: []Ec2.SecurityGroupRule) Ec2.SecurityGroup {
    return .{
        .allocator = std.testing.allocator,
        .group_id = @constCast("sg-1"),
        .group_name = @constCast("web"),
        .description = @constCast(""),
        .vpc_id = @constCast("vpc-1"),
        .owner_id = @constCast(""),
        .arn = @constCast(""),
        .name = @constCast(""),
        .tags = &.{},
        .ingress = ingress,
        .egress = egress,
    };
}

test "open egress lets outbound traffic through" {
    var open = [_]Ec2.SecurityGroupRange{range("0.0.0.0/0")};
    var egress = [_]Ec2.SecurityGroupRule{makeRule("-1", null, null, &open)};
    const groups = [_]Ec2.SecurityGroup{group(&.{}, &egress)};
    try std.testing.expect(check(&groups, .outbound, "0.0.0.0/0") == .ok);
}

test "no rule covering the port or address blocks" {
    var internal = [_]Ec2.SecurityGroupRange{range("10.0.0.0/8")};
    var wrong_port = [_]Ec2.SecurityGroupRange{range("0.0.0.0/0")};
    var egress = [_]Ec2.SecurityGroupRule{
        makeRule("tcp", 443, 443, &internal), // right port, wrong destination
        makeRule("tcp", 80, 80, &wrong_port), // right destination, wrong port
    };
    const groups = [_]Ec2.SecurityGroup{group(&.{}, &egress)};
    const out = check(&groups, .outbound, "0.0.0.0/0");
    try std.testing.expect(out == .blocked);
    try std.testing.expectEqual(nacl.internet_probe, out.blocked);
}

test "port ranges and the numeric protocol are honoured" {
    var open = [_]Ec2.SecurityGroupRange{range("0.0.0.0/0")};
    var ingress = [_]Ec2.SecurityGroupRule{makeRule("6", 400, 500, &open)};
    const groups = [_]Ec2.SecurityGroup{group(&ingress, &.{})};
    try std.testing.expect(check(&groups, .inbound, "0.0.0.0/0") == .ok);
}

test "udp rules do not match the tcp probe" {
    var open = [_]Ec2.SecurityGroupRange{range("0.0.0.0/0")};
    var egress = [_]Ec2.SecurityGroupRule{makeRule("udp", 0, 65535, &open)};
    const groups = [_]Ec2.SecurityGroup{group(&.{}, &egress)};
    try std.testing.expect(check(&groups, .outbound, "0.0.0.0/0") == .blocked);
}

test "direction selects egress or ingress rules" {
    var open = [_]Ec2.SecurityGroupRange{range("0.0.0.0/0")};
    var egress = [_]Ec2.SecurityGroupRule{makeRule("-1", null, null, &open)};
    const groups = [_]Ec2.SecurityGroup{group(&.{}, &egress)};
    try std.testing.expect(check(&groups, .outbound, "0.0.0.0/0") == .ok);
    try std.testing.expect(check(&groups, .inbound, "0.0.0.0/0") == .blocked);
}

test "any group allowing the flow is enough" {
    var closed = [_]Ec2.SecurityGroupRange{range("10.0.0.0/8")};
    var open = [_]Ec2.SecurityGroupRange{range("0.0.0.0/0")};
    var egress_a = [_]Ec2.SecurityGroupRule{makeRule("-1", null, null, &closed)};
    var egress_b = [_]Ec2.SecurityGroupRule{makeRule("-1", null, null, &open)};
    const groups = [_]Ec2.SecurityGroup{ group(&.{}, &egress_a), group(&.{}, &egress_b) };
    try std.testing.expect(check(&groups, .outbound, "0.0.0.0/0") == .ok);
}

test "prefix list and group rules make the result unknown, not blocked" {
    var prefix_only = [_]Ec2.SecurityGroupPrefixList{.{ .prefix_list_id = @constCast("pl-1"), .description = @constCast("") }};
    var egress = [_]Ec2.SecurityGroupRule{.{
        .protocol = @constCast("-1"),
        .from_port = null,
        .to_port = null,
        .groups = &.{},
        .ipv4_ranges = &.{},
        .ipv6_ranges = &.{},
        .prefix_lists = &prefix_only,
    }};
    const groups = [_]Ec2.SecurityGroup{group(&.{}, &egress)};
    try std.testing.expect(check(&groups, .outbound, "0.0.0.0/0") == .unknown);
}

test "untestable destinations are unknown" {
    var open = [_]Ec2.SecurityGroupRange{range("0.0.0.0/0")};
    var egress = [_]Ec2.SecurityGroupRule{makeRule("-1", null, null, &open)};
    const groups = [_]Ec2.SecurityGroup{group(&.{}, &egress)};
    try std.testing.expect(check(&groups, .outbound, "pl-123") == .unknown);
    try std.testing.expect(check(&groups, .outbound, "2600::/64") == .unknown);
}
