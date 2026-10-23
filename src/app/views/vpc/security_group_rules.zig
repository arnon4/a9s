const std = @import("std");
const terminal = @import("../../../terminal/terminal.zig");
const Event = @import("../../../event.zig").Event;
const view_mod = @import("../../../ui/view.zig");
const Action = view_mod.Action;
const ViewContext = view_mod.ViewContext;
const Coord = terminal.Coord;
const Ec2 = @import("../../../sdk/clients/ec2/client.zig");
const constants = @import("../../../ui/constants.zig");
const ConfirmView = @import("../../../ui/confirm.zig");
const table = @import("../../../ui/static_table.zig");
const filter_mod = @import("../../../commands/filter.zig");

const RulesView = @This();

const spec_inbound = makeSpec("Source", "source");
const spec_outbound = makeSpec("Destination", "destination");

fn makeSpec(comptime peer_title: []const u8, comptime peer_key: []const u8) table.Spec {
    return .{
        .flex = 2,
        .columns = &.{
            .{ .title = "Protocol", .key = "protocol", .width = 11 },
            .{ .title = "Ports", .key = "ports", .width = 14 },
            .{ .title = peer_title, .key = peer_key, .alias = "cidr", .width = 0 },
            .{ .title = "Description", .key = "description", .width = 32, .min_term_width = 110 },
        },
    };
}

fn protocolName(protocol: []const u8) []const u8 {
    if (std.mem.eql(u8, protocol, "-1")) return "All";
    if (std.ascii.eqlIgnoreCase(protocol, "tcp") or std.mem.eql(u8, protocol, "6")) return "TCP";
    if (std.ascii.eqlIgnoreCase(protocol, "udp") or std.mem.eql(u8, protocol, "17")) return "UDP";
    if (std.ascii.eqlIgnoreCase(protocol, "icmp") or std.mem.eql(u8, protocol, "1")) return "ICMP";
    if (std.ascii.eqlIgnoreCase(protocol, "icmpv6") or std.mem.eql(u8, protocol, "58")) return "ICMPv6";
    return protocol;
}

fn isIcmp(protocol: []const u8) bool {
    return std.mem.eql(u8, protocolName(protocol), "ICMP") or std.mem.eql(u8, protocolName(protocol), "ICMPv6");
}

/// For TCP/UDP the range is ports; for ICMP it is type and code, where -1 means any.
fn portsText(allocator: std.mem.Allocator, p: Ec2.SecurityGroupRule) ![]u8 {
    if (std.mem.eql(u8, p.protocol, "-1")) return allocator.dupe(u8, "All");
    const from = p.from_port orelse return allocator.dupe(u8, "All");
    const to = p.to_port orelse from;
    if (isIcmp(p.protocol)) {
        if (from < 0) return allocator.dupe(u8, "All");
        if (to < 0) return allocator.print("type {d}", .{from});
        return allocator.print("type {d} code {d}", .{ from, to });
    }
    if (from < 0) return allocator.dupe(u8, "All");
    if (from == to) return allocator.print("{d}", .{from});
    return allocator.print("{d}-{d}", .{ from, to });
}

fn groupText(allocator: std.mem.Allocator, g: Ec2.SecurityGroupPair) ![]u8 {
    if (g.vpc_peering_connection_id.len > 0) {
        return allocator.print("{s} ({s} via {s})", .{ g.group_id, g.vpc_id, g.vpc_peering_connection_id });
    }
    if (g.vpc_id.len > 0) return allocator.print("{s} ({s})", .{ g.group_id, g.vpc_id });
    return allocator.dupe(u8, g.group_id);
}

// ─── View fields ─────────────────────────────────────────────────────────────

fg_color: []const u8,
bg_color: []const u8,
inbound: bool,
/// Row-major, 4 cells per row; every cell is owned.
cells: [][]u8,
state: table.State,
alloc: std.mem.Allocator,
breadcrumb_buf: [320]u8 = undefined,
breadcrumb_len: usize = 0,

const n_cols = 4;

fn specFor(inbound: bool) table.Spec {
    return if (inbound) spec_inbound else spec_outbound;
}

// ─── Init / deinit ───────────────────────────────────────────────────────────

const Builder = struct {
    a: std.mem.Allocator,
    cells: std.ArrayList([]u8) = .empty,

    fn deinit(self: *Builder) void {
        for (self.cells.items) |c| self.a.free(c);
        self.cells.deinit(self.a);
    }

    /// Appends one row; `ports` and `peer` are taken over, the rest are copied.
    fn row(self: *Builder, protocol: []const u8, ports: []u8, peer: []u8, description: []const u8) !void {
        errdefer self.a.free(ports);
        errdefer self.a.free(peer);

        const proto = try self.a.dupe(u8, protocolName(protocol));
        errdefer self.a.free(proto);
        const desc = try self.a.dupe(u8, description);
        errdefer self.a.free(desc);

        try self.cells.ensureUnusedCapacity(self.a, n_cols);
        self.cells.appendAssumeCapacity(proto);
        self.cells.appendAssumeCapacity(ports);
        self.cells.appendAssumeCapacity(peer);
        self.cells.appendAssumeCapacity(desc);
    }

    fn addPeer(self: *Builder, p: Ec2.SecurityGroupRule, text: []const u8, description: []const u8) !void {
        const ports = try portsText(self.a, p);
        const peer_text = self.a.dupe(u8, text) catch |e| {
            self.a.free(ports);
            return e;
        };
        // `row` takes over both strings, including on failure.
        try self.row(p.protocol, ports, peer_text, description);
    }
};

/// Flattens the rules of one direction into one row per source or destination.
pub fn init(
    allocator: std.mem.Allocator,
    group: Ec2.SecurityGroup,
    inbound: bool,
    fg_color: []const u8,
    bg_color: []const u8,
    parent_breadcrumb: []const u8,
) !RulesView {
    var b: Builder = .{ .a = allocator };
    errdefer b.deinit();

    for (if (inbound) group.ingress else group.egress) |p| {
        var any = false;
        for (p.ipv4_ranges) |r| {
            try b.addPeer(p, r.cidr, r.description);
            any = true;
        }
        for (p.ipv6_ranges) |r| {
            try b.addPeer(p, r.cidr, r.description);
            any = true;
        }
        for (p.prefix_lists) |r| {
            try b.addPeer(p, r.prefix_list_id, r.description);
            any = true;
        }
        for (p.groups) |g| {
            const ports = try portsText(allocator, p);
            const text = groupText(allocator, g) catch |e| {
                allocator.free(ports);
                return e;
            };
            try b.row(p.protocol, ports, text, "");
            any = true;
        }
        if (!any) try b.addPeer(p, "-", "");
    }

    var view = RulesView{
        .fg_color = fg_color,
        .bg_color = bg_color,
        .inbound = inbound,
        .cells = try b.cells.toOwnedSlice(allocator),
        .state = .init(allocator),
        .alloc = allocator,
    };
    const title = if (inbound) "Inbound Rules" else "Outbound Rules";
    const bc = std.fmt.bufPrint(&view.breadcrumb_buf, "{s} {s} {s}", .{ parent_breadcrumb, constants.SEP_ARROW, title }) catch view.breadcrumb_buf[0..0];
    view.breadcrumb_len = bc.len;
    return view;
}

pub fn breadcrumb(self: *RulesView) []const u8 {
    return self.breadcrumb_buf[0..self.breadcrumb_len];
}

pub fn deinit(self: *RulesView) void {
    self.state.deinit();
    for (self.cells) |c| self.alloc.free(c);
    self.alloc.free(self.cells);
}

// ─── Event handling ──────────────────────────────────────────────────────────

fn rowCount(self: *RulesView) usize {
    return self.state.visible(specFor(self.inbound), self.cells).len;
}

// ─── Filter / sort (driven by the command bar) ───────────────────────────────

pub fn setLiveFilter(self: *RulesView, text: []const u8) void {
    self.state.setLiveFilter(text);
}

pub fn commitFilter(self: *RulesView, text: []const u8) void {
    self.state.commitFilter(text);
}

pub fn setFilterExpr(self: *RulesView, result: filter_mod.ParseResult) void {
    self.state.setFilterExpr(result);
}

pub fn clearFilterExpr(self: *RulesView) void {
    self.state.clearFilterExpr();
}

/// Sorts by the given column indices (see `parseSortKey`).
pub fn setSort(self: *RulesView, keys: []const usize, dir: constants.SortDir) void {
    self.state.setSort(keys, dir);
}

/// Column index for a `:sort` name; both directions share the same column order.
pub fn parseSortKey(tok: []const u8) ?usize {
    return table.columnIndex(spec_inbound, tok) orelse table.columnIndex(spec_outbound, tok);
}

pub fn handleEvent(self: *RulesView, event: Event, _: ViewContext) !Action {
    switch (event) {
        .key => |k| switch (k) {
            .ctrl_c => return .quit,
            .escape => {
                if (self.state.clearOne()) return .none;
                return .pop;
            },
            .char => |c| {
                if (c == 'q') return .{ .push = .{ .confirm = ConfirmView.init(self.fg_color, self.bg_color) } };
                _ = self.state.handleChar(c, self.rowCount());
            },
            .down => self.state.moveDown(self.rowCount()),
            .up => self.state.moveUp(),
            else => {},
        },
        else => {},
    }
    return .none;
}

pub fn render(self: *RulesView, writer: *std.Io.Writer, size: Coord) !void {
    try table.render(writer, size, self.fg_color, self.bg_color, specFor(self.inbound), self.cells, &self.state);
}

// ============================================================================
// Tests
// ============================================================================

test "rules flatten to one row per source with readable ports" {
    var ranges = [_]Ec2.SecurityGroupRange{
        .{ .cidr = @constCast("10.0.0.0/8"), .description = @constCast("corp") },
        .{ .cidr = @constCast("192.168.0.0/16"), .description = @constCast("") },
    };
    var pairs = [_]Ec2.SecurityGroupPair{.{
        .group_id = @constCast("sg-peer"),
        .user_id = @constCast(""),
        .vpc_id = @constCast("vpc-2"),
        .vpc_peering_connection_id = @constCast("pcx-1"),
    }};
    var all_traffic = [_]Ec2.SecurityGroupRange{.{ .cidr = @constCast("0.0.0.0/0"), .description = @constCast("") }};
    var icmp_any = [_]Ec2.SecurityGroupRange{.{ .cidr = @constCast("0.0.0.0/0"), .description = @constCast("") }};
    var rules = [_]Ec2.SecurityGroupRule{
        .{ .protocol = @constCast("tcp"), .from_port = 443, .to_port = 443, .groups = &pairs, .ipv4_ranges = &ranges, .ipv6_ranges = &.{}, .prefix_lists = &.{} },
        .{ .protocol = @constCast("-1"), .from_port = null, .to_port = null, .groups = &.{}, .ipv4_ranges = &all_traffic, .ipv6_ranges = &.{}, .prefix_lists = &.{} },
        .{ .protocol = @constCast("icmp"), .from_port = -1, .to_port = -1, .groups = &.{}, .ipv4_ranges = &icmp_any, .ipv6_ranges = &.{}, .prefix_lists = &.{} },
        .{ .protocol = @constCast("tcp"), .from_port = 1024, .to_port = 2048, .groups = &.{}, .ipv4_ranges = &.{}, .ipv6_ranges = &.{}, .prefix_lists = &.{} },
    };
    const group: Ec2.SecurityGroup = .{
        .allocator = std.testing.allocator,
        .group_id = @constCast("sg-1"),
        .group_name = @constCast("web"),
        .description = @constCast(""),
        .vpc_id = @constCast("vpc-1"),
        .owner_id = @constCast(""),
        .arn = @constCast(""),
        .name = @constCast(""),
        .tags = &.{},
        .ingress = &rules,
        .egress = &.{},
    };

    var view = try init(std.testing.allocator, group, true, "", "", "VPC");
    defer view.deinit();

    // 2 ranges + 1 group + 1 all-traffic + 1 icmp + 1 empty rule.
    try std.testing.expectEqual(@as(usize, 6), view.rowCount());
    try std.testing.expectEqualStrings("TCP", view.cells[0]);
    try std.testing.expectEqualStrings("443", view.cells[1]);
    try std.testing.expectEqualStrings("10.0.0.0/8", view.cells[2]);
    try std.testing.expectEqualStrings("corp", view.cells[3]);
    try std.testing.expectEqualStrings("sg-peer (vpc-2 via pcx-1)", view.cells[2 * n_cols + 2]);
    try std.testing.expectEqualStrings("All", view.cells[3 * n_cols + 0]);
    try std.testing.expectEqualStrings("All", view.cells[3 * n_cols + 1]);
    try std.testing.expectEqualStrings("ICMP", view.cells[4 * n_cols + 0]);
    try std.testing.expectEqualStrings("All", view.cells[4 * n_cols + 1]);
    try std.testing.expectEqualStrings("1024-2048", view.cells[5 * n_cols + 1]);
    try std.testing.expectEqualStrings("-", view.cells[5 * n_cols + 2]);
}
