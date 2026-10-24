//! Pure model of the VPC network map: turns loaded EC2 resources into a grid of
//! cells (subnets -> route table -> targets -> beyond) with a reachability mark
//! on every hop. No I/O; the view owns fetching and rendering.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Ec2 = @import("../../../sdk/clients/ec2/client.zig");
const nacl = @import("network_map_nacl.zig");

pub const Direction = enum { outbound, inbound };

/// Reachability of one hop. `partial` is a subnet-level result where only some routed destinations pass.
pub const Mark = enum { ok, blocked, unknown, partial };

/// Whether each describe call used by the map succeeded. A failed call turns the
/// hops that depend on it into `unknown` instead of guessing.
pub const Availability = struct {
    igws: bool = true,
    nats: bool = true,
    peerings: bool = true,
    tgw_attachments: bool = true,
    vpces: bool = true,
    vgws: bool = true,
    eigws: bool = true,
    nacls: bool = true,
};

pub const Input = struct {
    vpc_id: []const u8,
    subnets: []const Ec2.Subnet = &.{},
    route_tables: []const Ec2.RouteTable = &.{},
    igws: []const Ec2.InternetGateway = &.{},
    nats: []const Ec2.NatGateway = &.{},
    peerings: []const Ec2.VpcPeeringConnection = &.{},
    tgw_attachments: []const Ec2.TransitGatewayVpcAttachment = &.{},
    vpces: []const Ec2.VpcEndpoint = &.{},
    vgws: []const Ec2.VpnGateway = &.{},
    eigws: []const Ec2.EgressOnlyInternetGateway = &.{},
    nacls: []const Ec2.NetworkAcl = &.{},
    available: Availability = .{},
};

/// What Enter opens for a cell.
pub const Ref = union(enum) {
    none,
    subnet: []const u8,
    route_table: []const u8,
    igw: []const u8,
    nat: []const u8,
};

/// Grid columns, left to right.
pub const Col = enum(u8) { subnet, subnet_hop, route_table, hop0, node0, hop1, node1, hop2, node2 };
pub const col_count = 9;

pub const Cell = struct {
    row: usize,
    col: Col,
    group: usize,
    /// Path within the group; null for cells shared by all paths.
    path: ?usize,
    /// Node label. Empty for hops.
    text: []const u8 = "",
    /// Hops only: branch glyphs drawn before the arrow, e.g. "┬─".
    pre: []const u8 = "",
    is_hop: bool = false,
    /// Hops only: false for the decorative bracket rows next to the subnets.
    body: bool = true,
    /// Hops only: null draws a bare arrow.
    mark: ?Mark = null,
    selectable: bool = true,
    /// Unreachable because an earlier hop on the path is blocked.
    dim: bool = false,
    /// Shown in the detail line when selected.
    reason: []const u8 = "",
    ref: Ref = .none,
};

pub const Graph = struct {
    arena: std.heap.ArenaAllocator,
    cells: []Cell,
    rows: usize,

    pub fn deinit(self: *Graph) void {
        self.arena.deinit();
    }
};

// ─── Targets ─────────────────────────────────────────────────────────────────

pub const TargetKind = enum { local, igw, nat, tgw, pcx, vgw, vpce, eigw, eni, instance, cagw, lgw, other };

pub fn classify(target: []const u8) TargetKind {
    if (std.mem.eql(u8, target, "local")) return .local;
    const prefixes = [_]struct { []const u8, TargetKind }{
        .{ "igw-", .igw },
        .{ "nat-", .nat },
        .{ "tgw-", .tgw },
        .{ "pcx-", .pcx },
        .{ "vgw-", .vgw },
        .{ "vpce-", .vpce },
        .{ "eigw-", .eigw },
        .{ "eni-", .eni },
        .{ "i-", .instance },
        .{ "cagw-", .cagw },
        .{ "lgw-", .lgw },
    };
    for (prefixes) |p| {
        if (std.mem.startsWith(u8, target, p[0])) return p[1];
    }
    return .other;
}

fn typeTag(kind: TargetKind) []const u8 {
    return switch (kind) {
        .local => "[local]",
        .igw => "[IGW]",
        .nat => "[NAT]",
        .tgw => "[TGW]",
        .pcx => "[PCX]",
        .vgw => "[VGW]",
        .vpce => "[VPCE]",
        .eigw => "[EIGW]",
        .eni => "[ENI]",
        .instance => "[EC2]",
        .cagw => "[CAGW]",
        .lgw => "[LGW]",
        .other => "[?]",
    };
}

const Hop = struct {
    mark: ?Mark,
    reason: []const u8,
    dim: bool = false,
};

const PathNode = struct {
    text: []const u8,
    ref: Ref = .none,
    /// Hop leading into this node.
    hop: Hop,
    dim: bool = false,
};

const Path = struct {
    nodes: [3]PathNode = undefined,
    len: usize = 0,
    /// Route destinations (CIDRs or prefix list IDs) that lead to this target.
    dests: []const []const u8 = &.{},
    /// False for traffic that never leaves the VPC, which NACLs are not tested against.
    probe: bool = true,

    fn push(self: *Path, node: PathNode) void {
        self.nodes[self.len] = node;
        self.len += 1;
    }

    /// Dims everything after the first blocked hop and propagates unknowns.
    fn finalize(self: *Path) void {
        var blocked = false;
        var unknown = false;
        for (self.nodes[0..self.len]) |*n| {
            if (blocked) {
                n.hop.mark = null;
                n.hop.dim = true;
                n.dim = true;
                continue;
            }
            if (n.hop.mark) |m| switch (m) {
                .blocked => blocked = true,
                .unknown => unknown = true,
                .partial => {},
                .ok => if (unknown) {
                    n.hop.mark = .unknown;
                    n.hop.reason = "Depends on an earlier hop that could not be evaluated";
                },
            };
        }
    }
};

const Builder = struct {
    a: Allocator,
    input: Input,
    direction: Direction,

    fn label(self: *Builder, kind: TargetKind, id: []const u8, name: []const u8) ![]const u8 {
        return self.a.print("{s} {s}", .{ typeTag(kind), if (name.len > 0) name else id });
    }

    fn findIgw(self: *const Builder, id: []const u8) ?Ec2.InternetGateway {
        for (self.input.igws) |g| {
            if (std.mem.eql(u8, g.internet_gateway_id, id)) return g;
        }
        return null;
    }

    fn igwAttached(self: *const Builder, g: Ec2.InternetGateway) bool {
        for (g.attachments) |at| {
            if (!std.mem.eql(u8, at.vpc_id, self.input.vpc_id)) continue;
            return std.mem.eql(u8, at.state, "available") or std.mem.eql(u8, at.state, "attached");
        }
        return false;
    }

    fn igwHop(self: *Builder, id: []const u8) !Hop {
        if (!self.input.available.igws) return .{ .mark = .unknown, .reason = "Cannot read internet gateways with these credentials" };
        const g = self.findIgw(id) orelse
            return .{ .mark = .blocked, .reason = try self.a.print("Internet gateway {s} is not attached to this VPC", .{id}) };
        if (!self.igwAttached(g))
            return .{ .mark = .blocked, .reason = try self.a.print("Internet gateway {s} is detached", .{id}) };
        return .{ .mark = .ok, .reason = try self.a.print("Internet gateway {s} is attached", .{id}) };
    }

    fn rtbForSubnet(self: *const Builder, subnet_id: []const u8) ?Ec2.RouteTable {
        for (self.input.route_tables) |t| {
            for (t.associations) |assoc| {
                if (std.mem.eql(u8, assoc.subnet_id, subnet_id)) return t;
            }
        }
        for (self.input.route_tables) |t| {
            if (t.isMain()) return t;
        }
        return null;
    }

    /// Internet gateway targeted by an active route of the table serving `subnet_id`.
    fn egressIgw(self: *const Builder, subnet_id: []const u8) ?[]const u8 {
        const t = self.rtbForSubnet(subnet_id) orelse return null;
        for (t.routes) |r| {
            if (classify(r.target) == .igw and !std.mem.eql(u8, r.state, "blackhole")) return r.target;
        }
        return null;
    }

    fn naclFor(self: *const Builder, subnet_id: []const u8) ?Ec2.NetworkAcl {
        for (self.input.nacls) |n| {
            for (n.associations) |assoc| {
                if (std.mem.eql(u8, assoc.subnet_id, subnet_id)) return n;
            }
        }
        for (self.input.nacls) |n| {
            if (n.is_default) return n;
        }
        return null;
    }

    fn describeFailure(self: *Builder, f: nacl.Failure) ![]const u8 {
        const dir: []const u8 = if (f.egress) "egress" else "ingress";
        const verb: []const u8 = if (f.verdict.rule == 0) "has no rule allowing" else "denies";
        const leg: []const u8 = if (f.is_return) "return traffic" else "traffic";
        const port: u16 = if (f.is_return) nacl.ephemeral_port else nacl.service_port;
        const preposition: []const u8 = if (f.egress) "to" else "from";
        if (f.verdict.rule == 0) {
            return self.a.print("{s} {s} {s} tcp/{d} {s} {d}.{d}.{d}.{d}", .{ dir, verb, leg, port, preposition, f.addr[0], f.addr[1], f.addr[2], f.addr[3] });
        }
        return self.a.print("{s} rule {d} {s} {s} tcp/{d} {s} {d}.{d}.{d}.{d}", .{ dir, f.verdict.rule, verb, leg, port, preposition, f.addr[0], f.addr[1], f.addr[2], f.addr[3] });
    }

    /// Hop from a subnet into its route table: the subnet's network ACL tested against every routed destination.
    fn subnetHop(self: *Builder, s: Ec2.Subnet, paths: []const Path) !Hop {
        const suffix = "; security groups on interfaces are not evaluated";
        if (!self.input.available.nacls) return .{ .mark = .unknown, .reason = "Cannot read network ACLs with these credentials" };
        const acl = self.naclFor(s.subnet_id) orelse return .{ .mark = .unknown, .reason = "No network ACL found for this subnet" };

        const flow: nacl.Flow = if (self.direction == .outbound) .outbound else .inbound;
        var ok: usize = 0;
        var blocked: usize = 0;
        var unknown: usize = 0;
        var first_failure: ?nacl.Failure = null;
        for (paths) |p| {
            if (!p.probe or p.len == 0) continue;
            if (p.nodes[0].hop.mark == .blocked) continue;
            for (p.dests) |dest| switch (nacl.check(acl, dest, flow)) {
                .ok => ok += 1,
                .unknown => unknown += 1,
                .blocked => |f| {
                    blocked += 1;
                    if (first_failure == null) first_failure = f;
                },
            };
        }

        const total = ok + blocked + unknown;
        if (total == 0) return .{ .mark = null, .reason = try self.a.print("NACL {s}: nothing is routed outside the VPC to test", .{acl.network_acl_id}) };

        if (blocked == 0 and unknown == 0) {
            return .{ .mark = .ok, .reason = try self.a.print("NACL {s} allows tcp/{d} and the return traffic for all {d} routed destinations{s}", .{ acl.network_acl_id, nacl.service_port, total, suffix }) };
        }
        if (blocked == 0) {
            return .{ .mark = .unknown, .reason = try self.a.print("NACL {s}: {d} routed destinations cannot be tested (IPv6 or prefix lists){s}", .{ acl.network_acl_id, unknown, suffix }) };
        }
        const detail = try self.describeFailure(first_failure.?);
        const mark: Mark = if (ok == 0 and unknown == 0) .blocked else .partial;
        return .{ .mark = mark, .reason = try self.a.print("NACL {s} {s} ({d} of {d} destinations blocked){s}", .{ acl.network_acl_id, detail, blocked, total, suffix }) };
    }

    const ok_internet = "Reaches the public internet (public IP, NACL and security groups are not evaluated)";

    fn buildPath(self: *Builder, route_state: []const u8, target: []const u8, kind: TargetKind) !Path {
        var path: Path = .{};
        const inbound = self.direction == .inbound;
        const blackhole = std.mem.eql(u8, route_state, "blackhole");
        const blackhole_hop: Hop = .{ .mark = .blocked, .reason = "Route state is blackhole: the target no longer exists" };

        switch (kind) {
            .local => {
                path.probe = false;
                path.push(.{ .text = "[local] VPC", .hop = .{ .mark = .ok, .reason = "Traffic stays inside the VPC" } });
            },
            .igw => {
                const g = self.findIgw(target);
                const hop = if (blackhole) blackhole_hop else try self.igwHop(target);
                path.push(.{ .text = try self.label(.igw, target, if (g) |x| x.name else ""), .ref = .{ .igw = target }, .hop = hop });
                path.push(.{ .text = "Internet", .hop = .{ .mark = .ok, .reason = ok_internet } });
            },
            .nat => {
                const found: ?Ec2.NatGateway = for (self.input.nats) |n| {
                    if (std.mem.eql(u8, n.id, target)) break n;
                } else null;
                var hop: Hop = undefined;
                if (blackhole) {
                    hop = blackhole_hop;
                } else if (inbound) {
                    hop = .{ .mark = .blocked, .reason = "NAT gateways do not accept unsolicited inbound connections" };
                } else if (!self.input.available.nats) {
                    hop = .{ .mark = .unknown, .reason = "Cannot read NAT gateways with these credentials" };
                } else if (found) |n| {
                    hop = if (std.mem.eql(u8, n.state, "available"))
                        .{ .mark = .ok, .reason = try self.a.print("NAT gateway {s} is available in {s}", .{ target, if (n.subnet_id.len > 0) n.subnet_id else "an unknown subnet" }) }
                    else if (n.failure_message.len > 0)
                        .{ .mark = .blocked, .reason = try self.a.print("NAT gateway {s} state: {s} ({s})", .{ target, n.state, n.failure_message }) }
                    else
                        .{ .mark = .blocked, .reason = try self.a.print("NAT gateway {s} state: {s}", .{ target, n.state }) };
                } else {
                    hop = .{ .mark = .blocked, .reason = try self.a.print("NAT gateway {s} was not found in this VPC", .{target}) };
                }
                path.push(.{ .text = try self.label(.nat, target, if (found) |n| n.name else ""), .ref = .{ .nat = target }, .hop = hop });

                const n = found orelse return finish(&path);
                if (std.mem.eql(u8, n.connectivity_type, "private")) return finish(&path);
                if (self.egressIgw(n.subnet_id)) |igw_id| {
                    const g = self.findIgw(igw_id);
                    path.push(.{ .text = try self.label(.igw, igw_id, if (g) |x| x.name else ""), .ref = .{ .igw = igw_id }, .hop = try self.igwHop(igw_id) });
                    path.push(.{ .text = "Internet", .hop = .{ .mark = .ok, .reason = ok_internet } });
                } else {
                    path.push(.{
                        .text = "no IGW route",
                        .hop = .{ .mark = .blocked, .reason = try self.a.print("The NAT gateway's subnet {s} has no route to an internet gateway", .{n.subnet_id}) },
                    });
                }
            },
            .pcx => {
                const found: ?Ec2.VpcPeeringConnection = for (self.input.peerings) |p| {
                    if (std.mem.eql(u8, p.id, target)) break p;
                } else null;
                var hop: Hop = undefined;
                if (blackhole) {
                    hop = blackhole_hop;
                } else if (!self.input.available.peerings) {
                    hop = .{ .mark = .unknown, .reason = "Cannot read peering connections with these credentials" };
                } else if (found) |p| {
                    hop = if (std.mem.eql(u8, p.state, "active"))
                        .{ .mark = .ok, .reason = try self.a.print("Peering connection {s} is active", .{target}) }
                    else
                        .{ .mark = .blocked, .reason = try self.a.print("Peering connection {s} status: {s}", .{ target, p.state }) };
                } else {
                    hop = .{ .mark = .blocked, .reason = try self.a.print("Peering connection {s} was not found", .{target}) };
                }
                path.push(.{ .text = try self.label(.pcx, target, if (found) |p| p.name else ""), .hop = hop });

                const p = found orelse return finish(&path);
                const peer = if (std.mem.eql(u8, p.requester_vpc_id, self.input.vpc_id)) p.accepter_vpc_id else p.requester_vpc_id;
                if (peer.len > 0) {
                    path.push(.{
                        .text = try self.a.print("[VPC] {s}", .{peer}),
                        .hop = if (inbound)
                            .{ .mark = .unknown, .reason = "The return route and ACLs in the peer VPC are not visible" }
                        else
                            .{ .mark = .ok, .reason = "Reaches the peer VPC (its security groups and ACLs are not evaluated)" },
                    });
                }
            },
            .tgw => {
                const found: ?Ec2.TransitGatewayVpcAttachment = for (self.input.tgw_attachments) |at| {
                    if (std.mem.eql(u8, at.transit_gateway_id, target)) break at;
                } else null;
                var hop: Hop = undefined;
                if (blackhole) {
                    hop = blackhole_hop;
                } else if (!self.input.available.tgw_attachments) {
                    hop = .{ .mark = .unknown, .reason = "Cannot read transit gateway attachments with these credentials" };
                } else if (found) |at| {
                    hop = if (std.mem.eql(u8, at.state, "available"))
                        .{ .mark = .ok, .reason = try self.a.print("Attachment {s} to {s} is available", .{ at.id, target }) }
                    else
                        .{ .mark = .blocked, .reason = try self.a.print("Attachment {s} to {s} state: {s}", .{ at.id, target, at.state }) };
                } else {
                    hop = .{ .mark = .blocked, .reason = try self.a.print("This VPC has no attachment to {s}", .{target}) };
                }
                path.push(.{ .text = try self.label(.tgw, target, ""), .hop = hop });
            },
            .vgw => {
                const found: ?Ec2.VpnGateway = for (self.input.vgws) |g| {
                    if (std.mem.eql(u8, g.id, target)) break g;
                } else null;
                var hop: Hop = undefined;
                if (blackhole) {
                    hop = blackhole_hop;
                } else if (!self.input.available.vgws) {
                    hop = .{ .mark = .unknown, .reason = "Cannot read virtual private gateways with these credentials" };
                } else if (found) |g| {
                    hop = if (std.mem.eql(u8, g.vpc_id, self.input.vpc_id) and std.mem.eql(u8, g.attachment_state, "attached"))
                        .{ .mark = .ok, .reason = try self.a.print("Virtual private gateway {s} is attached", .{target}) }
                    else
                        .{ .mark = .blocked, .reason = try self.a.print("Virtual private gateway {s} is not attached to this VPC", .{target}) };
                } else {
                    hop = .{ .mark = .blocked, .reason = try self.a.print("Virtual private gateway {s} is not attached to this VPC", .{target}) };
                }
                path.push(.{ .text = try self.label(.vgw, target, if (found) |g| g.name else ""), .hop = hop });
            },
            .vpce => {
                const found: ?Ec2.VpcEndpoint = for (self.input.vpces) |e| {
                    if (std.mem.eql(u8, e.id, target)) break e;
                } else null;
                var hop: Hop = undefined;
                if (blackhole) {
                    hop = blackhole_hop;
                } else if (inbound) {
                    hop = .{ .mark = .blocked, .reason = "VPC endpoints carry outbound traffic only" };
                } else if (!self.input.available.vpces) {
                    hop = .{ .mark = .unknown, .reason = "Cannot read VPC endpoints with these credentials" };
                } else if (found) |e| {
                    hop = if (std.mem.eql(u8, e.state, "available"))
                        .{ .mark = .ok, .reason = try self.a.print("VPC endpoint {s} is available", .{target}) }
                    else
                        .{ .mark = .blocked, .reason = try self.a.print("VPC endpoint {s} state: {s}", .{ target, e.state }) };
                } else {
                    hop = .{ .mark = .blocked, .reason = try self.a.print("VPC endpoint {s} was not found in this VPC", .{target}) };
                }
                path.push(.{ .text = try self.label(.vpce, target, if (found) |e| e.name else ""), .hop = hop });

                if (found) |e| {
                    const svc = if (std.mem.findScalarLast(u8, e.service_name, '.')) |i| e.service_name[i + 1 ..] else e.service_name;
                    if (svc.len > 0) {
                        path.push(.{
                            .text = try self.a.print("[SVC] {s}", .{svc}),
                            .hop = .{ .mark = .ok, .reason = try self.a.print("Reaches {s} privately", .{e.service_name}) },
                        });
                    }
                }
            },
            .eigw => {
                const found: ?Ec2.EgressOnlyInternetGateway = for (self.input.eigws) |g| {
                    if (std.mem.eql(u8, g.id, target)) break g;
                } else null;
                var hop: Hop = undefined;
                if (blackhole) {
                    hop = blackhole_hop;
                } else if (inbound) {
                    hop = .{ .mark = .blocked, .reason = "Egress-only gateways block inbound IPv6 connections" };
                } else if (!self.input.available.eigws) {
                    hop = .{ .mark = .unknown, .reason = "Cannot read egress-only gateways with these credentials" };
                } else if (found) |g| {
                    hop = if (std.mem.eql(u8, g.vpc_id, self.input.vpc_id) and std.mem.eql(u8, g.state, "attached"))
                        .{ .mark = .ok, .reason = try self.a.print("Egress-only gateway {s} is attached", .{target}) }
                    else
                        .{ .mark = .blocked, .reason = try self.a.print("Egress-only gateway {s} is not attached to this VPC", .{target}) };
                } else {
                    hop = .{ .mark = .blocked, .reason = try self.a.print("Egress-only gateway {s} was not found", .{target}) };
                }
                path.push(.{ .text = try self.label(.eigw, target, if (found) |g| g.name else ""), .hop = hop });
                path.push(.{ .text = "Internet (IPv6)", .hop = .{ .mark = .ok, .reason = "Reaches the internet over IPv6, outbound only" } });
            },
            .eni, .instance, .cagw, .lgw, .other => {
                const hop: Hop = if (blackhole) blackhole_hop else .{
                    .mark = .ok,
                    .reason = try self.a.print("Route is active; {s} is not inspected further", .{target}),
                };
                path.push(.{ .text = try self.label(kind, target, ""), .hop = hop });
            },
        }
        return finish(&path);
    }
};

fn finish(path: *Path) Path {
    path.finalize();
    return path.*;
}

// ─── Build ───────────────────────────────────────────────────────────────────

const GroupData = struct {
    rtb: Ec2.RouteTable,
    subnets: std.ArrayList(Ec2.Subnet) = .empty,
};

fn subnetName(s: Ec2.Subnet) []const u8 {
    return if (s.name.len > 0) s.name else s.subnet_id;
}

fn rtbName(t: Ec2.RouteTable) []const u8 {
    return if (t.name.len > 0) t.name else t.route_table_id;
}

fn subnetLess(_: void, x: Ec2.Subnet, y: Ec2.Subnet) bool {
    return std.mem.lessThan(u8, subnetName(x), subnetName(y));
}

fn groupLess(_: void, x: GroupData, y: GroupData) bool {
    return std.mem.lessThan(u8, rtbName(x.rtb), rtbName(y.rtb));
}

/// Builds the grid for `input`. Caller owns the result and must call deinit.
pub fn build(allocator: Allocator, input: Input, direction: Direction) !Graph {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();

    var b: Builder = .{ .a = a, .input = input, .direction = direction };

    var groups: std.ArrayList(GroupData) = .empty;
    for (input.route_tables) |t| try groups.append(a, .{ .rtb = t });

    for (input.subnets) |s| {
        const t = b.rtbForSubnet(s.subnet_id) orelse continue;
        for (groups.items) |*g| {
            if (std.mem.eql(u8, g.rtb.route_table_id, t.route_table_id)) {
                try g.subnets.append(a, s);
                break;
            }
        }
    }

    // Route tables nobody uses have nothing to show.
    var used: std.ArrayList(GroupData) = .empty;
    for (groups.items) |g| {
        if (g.subnets.items.len > 0) try used.append(a, g);
    }
    std.mem.sortUnstable(GroupData, used.items, {}, groupLess);

    var cells: std.ArrayList(Cell) = .empty;
    var row: usize = 0;

    for (used.items, 0..) |*g, gi| {
        if (gi > 0) row += 1;
        std.mem.sortUnstable(Ec2.Subnet, g.subnets.items, {}, subnetLess);

        var paths: std.ArrayList(Path) = .empty;
        var dest_lists: std.ArrayList(std.ArrayList([]const u8)) = .empty;
        var seen: std.ArrayList([]const u8) = .empty;
        for (g.rtb.routes) |r| {
            if (r.target.len == 0) continue;
            const existing: ?usize = for (seen.items, 0..) |t, ti| {
                if (std.mem.eql(u8, t, r.target)) break ti;
            } else null;
            if (existing) |ti| {
                try dest_lists.items[ti].append(a, r.destination);
                continue;
            }
            try seen.append(a, r.target);
            try paths.append(a, try b.buildPath(r.state, r.target, classify(r.target)));
            var dl: std.ArrayList([]const u8) = .empty;
            try dl.append(a, r.destination);
            try dest_lists.append(a, dl);
        }
        for (paths.items, dest_lists.items) |*p, dl| p.dests = dl.items;
        // "local" is noise unless it is all there is.
        if (paths.items.len > 1) {
            var w: usize = 0;
            for (paths.items, 0..) |p, i| {
                const is_local = p.len > 0 and std.mem.eql(u8, p.nodes[0].text, "[local] VPC");
                if (is_local) continue;
                paths.items[w] = paths.items[i];
                w += 1;
            }
            if (w > 0) paths.shrinkRetainingCapacity(w);
        }

        const k = g.subnets.items.len;
        const m = @max(paths.items.len, 1);
        const rtb_row = row + k - 1;

        for (g.subnets.items, 0..) |s, i| {
            const az = s.availability_zone;
            try cells.append(a, .{
                .row = row + i,
                .col = .subnet,
                .group = gi,
                .path = null,
                .text = try a.print("{s} {s}", .{ subnetName(s), if (az.len >= 2) az[az.len - 2 ..] else az }),
                .reason = try a.print("Subnet {s} ({s}, {s})", .{ s.subnet_id, s.cidr_block, s.availability_zone }),
                .ref = .{ .subnet = s.subnet_id },
            });
            const last = i == k - 1;
            const nacl_hop = try b.subnetHop(s, paths.items);
            try cells.append(a, .{
                .row = row + i,
                .col = .subnet_hop,
                .group = gi,
                .path = null,
                .is_hop = true,
                // Bracket glyph joining the subnets of one route table.
                .pre = if (k == 1) "─" else if (i == 0) "┐" else if (last) "┴" else "┤",
                .body = last,
                .mark = nacl_hop.mark,
                .reason = nacl_hop.reason,
            });
        }

        try cells.append(a, .{
            .row = rtb_row,
            .col = .route_table,
            .group = gi,
            .path = null,
            .text = try a.print("{s}{s}", .{ rtbName(g.rtb), if (g.rtb.isMain()) " (main)" else "" }),
            .reason = try a.print("Route table {s} ({d} routes)", .{ g.rtb.route_table_id, g.rtb.routes.len }),
            .ref = .{ .route_table = g.rtb.route_table_id },
        });

        for (paths.items, 0..) |p, j| {
            const prow = rtb_row + j;
            const hop_cols = [_]Col{ .hop0, .hop1, .hop2 };
            const node_cols = [_]Col{ .node0, .node1, .node2 };
            for (p.nodes[0..p.len], 0..) |n, ni| {
                try cells.append(a, .{
                    .row = prow,
                    .col = hop_cols[ni],
                    .group = gi,
                    .path = j,
                    .is_hop = true,
                    .pre = if (ni > 0 or m == 1) "──" else if (j == 0) "┬─" else if (j == m - 1) "└─" else "├─",
                    .mark = n.hop.mark,
                    .dim = n.hop.dim,
                    .reason = n.hop.reason,
                });
                try cells.append(a, .{
                    .row = prow,
                    .col = node_cols[ni],
                    .group = gi,
                    .path = j,
                    .text = n.text,
                    .dim = n.dim,
                    .reason = n.hop.reason,
                    .ref = n.ref,
                });
            }
        }

        row += k - 1 + m;
    }

    return .{
        .arena = arena,
        .cells = try cells.toOwnedSlice(a),
        .rows = row,
    };
}

// ─── Tests ───────────────────────────────────────────────────────────────────

const t_empty: []u8 = &.{};

fn testSubnet(id: []const u8, az: []const u8) Ec2.Subnet {
    return .{
        .allocator = std.testing.allocator,
        .subnet_id = @constCast(id),
        .subnet_arn = t_empty,
        .vpc_id = @constCast("vpc-1"),
        .owner_id = t_empty,
        .state = t_empty,
        .cidr_block = @constCast("10.0.0.0/24"),
        .availability_zone = @constCast(az),
        .availability_zone_id = t_empty,
        .available_ip_address_count = 0,
        .default_for_az = false,
        .map_public_ip_on_launch = false,
        .assign_ipv6_address_on_creation = false,
        .ipv6_native = false,
        .enable_dns64 = false,
        .outpost_arn = t_empty,
        .name = t_empty,
        .tags = &.{},
        .ipv6_cidr_associations = &.{},
    };
}

fn testRtb(id: []const u8, assocs: []Ec2.RouteTableAssociation, routes: []Ec2.Route) Ec2.RouteTable {
    return .{
        .allocator = std.testing.allocator,
        .route_table_id = @constCast(id),
        .vpc_id = @constCast("vpc-1"),
        .owner_id = t_empty,
        .name = t_empty,
        .tags = &.{},
        .associations = assocs,
        .routes = routes,
        .propagating_vgws = &.{},
    };
}

fn testRoute(target: []const u8, state: []const u8) Ec2.Route {
    return .{ .destination = @constCast("0.0.0.0/0"), .target = @constCast(target), .state = @constCast(state), .origin = t_empty };
}

fn cellAt(g: Graph, row: usize, col: Col) ?Cell {
    for (g.cells) |c| {
        if (c.row == row and c.col == col) return c;
    }
    return null;
}

test "public subnet routes to an attached internet gateway" {
    const subnets = [_]Ec2.Subnet{ testSubnet("subnet-a", "us-east-1a"), testSubnet("subnet-b", "us-east-1b") };
    var assocs = [_]Ec2.RouteTableAssociation{
        .{ .association_id = t_empty, .main = false, .subnet_id = @constCast("subnet-a"), .gateway_id = t_empty, .state = t_empty },
        .{ .association_id = t_empty, .main = false, .subnet_id = @constCast("subnet-b"), .gateway_id = t_empty, .state = t_empty },
    };
    var routes = [_]Ec2.Route{ testRoute("local", "active"), testRoute("igw-1", "active") };
    const rtbs = [_]Ec2.RouteTable{testRtb("rtb-pub", &assocs, &routes)};
    var igw_att = [_]Ec2.InternetGatewayAttachment{.{ .vpc_id = @constCast("vpc-1"), .state = @constCast("available") }};
    const igws = [_]Ec2.InternetGateway{.{
        .allocator = std.testing.allocator,
        .internet_gateway_id = @constCast("igw-1"),
        .owner_id = t_empty,
        .name = t_empty,
        .tags = &.{},
        .attachments = &igw_att,
    }};

    var g = try build(std.testing.allocator, .{ .vpc_id = "vpc-1", .subnets = &subnets, .route_tables = &rtbs, .igws = &igws }, .outbound);
    defer g.deinit();

    // Two subnets share the table; local is dropped because another path exists.
    try std.testing.expectEqual(@as(usize, 2), g.rows);
    try std.testing.expectEqualStrings("subnet-a 1a", cellAt(g, 0, .subnet).?.text);
    try std.testing.expectEqualStrings("┐", cellAt(g, 0, .subnet_hop).?.pre);
    try std.testing.expectEqualStrings("┴", cellAt(g, 1, .subnet_hop).?.pre);
    try std.testing.expectEqualStrings("rtb-pub", cellAt(g, 1, .route_table).?.text);
    try std.testing.expectEqualStrings("[IGW] igw-1", cellAt(g, 1, .node0).?.text);
    try std.testing.expectEqual(Mark.ok, cellAt(g, 1, .hop0).?.mark.?);
    try std.testing.expectEqualStrings("Internet", cellAt(g, 1, .node1).?.text);
    try std.testing.expectEqual(Mark.ok, cellAt(g, 1, .hop1).?.mark.?);
}

test "blackhole route blocks and dims downstream" {
    const subnets = [_]Ec2.Subnet{testSubnet("subnet-a", "us-east-1a")};
    var assocs = [_]Ec2.RouteTableAssociation{
        .{ .association_id = t_empty, .main = true, .subnet_id = t_empty, .gateway_id = t_empty, .state = t_empty },
    };
    var routes = [_]Ec2.Route{testRoute("pcx-9", "blackhole")};
    const rtbs = [_]Ec2.RouteTable{testRtb("rtb-main", &assocs, &routes)};

    var g = try build(std.testing.allocator, .{ .vpc_id = "vpc-1", .subnets = &subnets, .route_tables = &rtbs }, .outbound);
    defer g.deinit();

    try std.testing.expectEqual(@as(usize, 1), g.rows);
    try std.testing.expectEqual(Mark.blocked, cellAt(g, 0, .hop0).?.mark.?);
    try std.testing.expect(!cellAt(g, 0, .node0).?.dim);
}

test "inbound NAT is blocked and the subnet hop is unknown" {
    const subnets = [_]Ec2.Subnet{testSubnet("subnet-a", "us-east-1a")};
    var assocs = [_]Ec2.RouteTableAssociation{
        .{ .association_id = t_empty, .main = true, .subnet_id = t_empty, .gateway_id = t_empty, .state = t_empty },
    };
    var routes = [_]Ec2.Route{testRoute("nat-1", "active")};
    const rtbs = [_]Ec2.RouteTable{testRtb("rtb-main", &assocs, &routes)};

    var g = try build(std.testing.allocator, .{ .vpc_id = "vpc-1", .subnets = &subnets, .route_tables = &rtbs }, .inbound);
    defer g.deinit();

    try std.testing.expectEqual(Mark.unknown, cellAt(g, 0, .subnet_hop).?.mark.?);
    try std.testing.expectEqual(Mark.blocked, cellAt(g, 0, .hop0).?.mark.?);
}

test "unreadable describe call yields unknown" {
    const subnets = [_]Ec2.Subnet{testSubnet("subnet-a", "us-east-1a")};
    var assocs = [_]Ec2.RouteTableAssociation{
        .{ .association_id = t_empty, .main = true, .subnet_id = t_empty, .gateway_id = t_empty, .state = t_empty },
    };
    var routes = [_]Ec2.Route{testRoute("igw-1", "active")};
    const rtbs = [_]Ec2.RouteTable{testRtb("rtb-main", &assocs, &routes)};

    var g = try build(std.testing.allocator, .{
        .vpc_id = "vpc-1",
        .subnets = &subnets,
        .route_tables = &rtbs,
        .available = .{ .igws = false },
    }, .outbound);
    defer g.deinit();

    try std.testing.expectEqual(Mark.unknown, cellAt(g, 0, .hop0).?.mark.?);
    try std.testing.expectEqual(Mark.unknown, cellAt(g, 0, .hop1).?.mark.?);
}

fn testNacl(id: []const u8, entries: []Ec2.NetworkAclEntry, assocs: []Ec2.NetworkAclAssociation) Ec2.NetworkAcl {
    return .{
        .allocator = std.testing.allocator,
        .network_acl_id = @constCast(id),
        .vpc_id = @constCast("vpc-1"),
        .owner_id = t_empty,
        .is_default = false,
        .name = t_empty,
        .tags = &.{},
        .associations = assocs,
        .entries = entries,
    };
}

fn testEntry(rule: i32, egress: bool, allow: bool) Ec2.NetworkAclEntry {
    return .{
        .rule_number = rule,
        .protocol = @constCast("-1"),
        .allow = allow,
        .egress = egress,
        .cidr_block = @constCast("0.0.0.0/0"),
        .ipv6_cidr_block = t_empty,
        .port_from = null,
        .port_to = null,
    };
}

test "subnet hop reflects the subnet's network ACL" {
    const subnets = [_]Ec2.Subnet{ testSubnet("subnet-open", "us-east-1a"), testSubnet("subnet-shut", "us-east-1b") };
    var rtb_assocs = [_]Ec2.RouteTableAssociation{
        .{ .association_id = t_empty, .main = true, .subnet_id = t_empty, .gateway_id = t_empty, .state = t_empty },
    };
    var routes = [_]Ec2.Route{testRoute("igw-1", "active")};
    const rtbs = [_]Ec2.RouteTable{testRtb("rtb-main", &rtb_assocs, &routes)};
    var igw_att = [_]Ec2.InternetGatewayAttachment{.{ .vpc_id = @constCast("vpc-1"), .state = @constCast("available") }};
    const igws = [_]Ec2.InternetGateway{.{
        .allocator = std.testing.allocator,
        .internet_gateway_id = @constCast("igw-1"),
        .owner_id = t_empty,
        .name = t_empty,
        .tags = &.{},
        .attachments = &igw_att,
    }};

    var open_entries = [_]Ec2.NetworkAclEntry{ testEntry(100, true, true), testEntry(100, false, true) };
    var open_assoc = [_]Ec2.NetworkAclAssociation{.{ .association_id = t_empty, .subnet_id = @constCast("subnet-open") }};
    var shut_entries = [_]Ec2.NetworkAclEntry{ testEntry(100, true, false), testEntry(100, false, true) };
    var shut_assoc = [_]Ec2.NetworkAclAssociation{.{ .association_id = t_empty, .subnet_id = @constCast("subnet-shut") }};
    const nacls = [_]Ec2.NetworkAcl{
        testNacl("acl-open", &open_entries, &open_assoc),
        testNacl("acl-shut", &shut_entries, &shut_assoc),
    };

    var g = try build(std.testing.allocator, .{
        .vpc_id = "vpc-1",
        .subnets = &subnets,
        .route_tables = &rtbs,
        .igws = &igws,
        .nacls = &nacls,
    }, .outbound);
    defer g.deinit();

    // Subnets sort by name: subnet-open first.
    try std.testing.expectEqual(Mark.ok, cellAt(g, 0, .subnet_hop).?.mark.?);
    try std.testing.expectEqual(Mark.blocked, cellAt(g, 1, .subnet_hop).?.mark.?);
    try std.testing.expect(std.mem.find(u8, cellAt(g, 1, .subnet_hop).?.reason, "egress rule 100 denies") != null);
}

test "unreadable network ACLs yield unknown at the subnet hop" {
    const subnets = [_]Ec2.Subnet{testSubnet("subnet-a", "us-east-1a")};
    var assocs = [_]Ec2.RouteTableAssociation{
        .{ .association_id = t_empty, .main = true, .subnet_id = t_empty, .gateway_id = t_empty, .state = t_empty },
    };
    var routes = [_]Ec2.Route{testRoute("igw-1", "active")};
    const rtbs = [_]Ec2.RouteTable{testRtb("rtb-main", &assocs, &routes)};

    var g = try build(std.testing.allocator, .{
        .vpc_id = "vpc-1",
        .subnets = &subnets,
        .route_tables = &rtbs,
        .available = .{ .nacls = false },
    }, .outbound);
    defer g.deinit();

    try std.testing.expectEqual(Mark.unknown, cellAt(g, 0, .subnet_hop).?.mark.?);
}

test "NAT node links to its detail view and explains a failed gateway" {
    const subnets = [_]Ec2.Subnet{testSubnet("subnet-a", "us-east-1a")};
    var assocs = [_]Ec2.RouteTableAssociation{
        .{ .association_id = t_empty, .main = true, .subnet_id = t_empty, .gateway_id = t_empty, .state = t_empty },
    };
    var routes = [_]Ec2.Route{testRoute("nat-1", "active")};
    const rtbs = [_]Ec2.RouteTable{testRtb("rtb-main", &assocs, &routes)};
    const nats = [_]Ec2.NatGateway{.{
        .allocator = std.testing.allocator,
        .id = @constCast("nat-1"),
        .state = @constCast("failed"),
        .vpc_id = @constCast("vpc-1"),
        .subnet_id = @constCast("subnet-pub"),
        .connectivity_type = @constCast("public"),
        .create_time = t_empty,
        .delete_time = t_empty,
        .failure_code = @constCast("Gateway.NotAttached"),
        .failure_message = @constCast("no internet gateway attached"),
        .name = t_empty,
        .tags = &.{},
        .addresses = &.{},
    }};

    var g = try build(std.testing.allocator, .{ .vpc_id = "vpc-1", .subnets = &subnets, .route_tables = &rtbs, .nats = &nats }, .outbound);
    defer g.deinit();

    const node = cellAt(g, 0, .node0).?;
    try std.testing.expectEqualStrings("[NAT] nat-1", node.text);
    try std.testing.expectEqualStrings("nat-1", node.ref.nat);

    const hop = cellAt(g, 0, .hop0).?;
    try std.testing.expectEqual(Mark.blocked, hop.mark.?);
    try std.testing.expect(std.mem.find(u8, hop.reason, "no internet gateway attached") != null);
}
