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
pub const name: []const u8 = "Rules";

const spec: table.Spec = .{
    .flex = 4,
    .columns = &.{
        .{ .title = "Rule", .key = "rule", .numeric = true, .width = 8 },
        .{ .title = "Direction", .key = "direction", .width = 12 },
        .{ .title = "Protocol", .key = "protocol", .width = 11, .min_term_width = 70 },
        .{ .title = "Ports", .key = "ports", .width = 14, .min_term_width = 90 },
        .{ .title = "Source / Destination", .key = "source", .alias = "cidr", .width = 0 },
        .{ .title = "Action", .key = "action", .width = 10 },
    },
};

/// The NACL's catch-all rule number.
const catch_all_rule: i32 = 32767;

fn protocolName(protocol: []const u8) []const u8 {
    if (std.mem.eql(u8, protocol, "-1")) return "All";
    if (std.mem.eql(u8, protocol, "6")) return "TCP";
    if (std.mem.eql(u8, protocol, "17")) return "UDP";
    if (std.mem.eql(u8, protocol, "1")) return "ICMP";
    if (std.mem.eql(u8, protocol, "58")) return "ICMPv6";
    return protocol;
}

fn portsText(allocator: std.mem.Allocator, e: Ec2.NetworkAclEntry) ![]u8 {
    const from = e.port_from orelse return allocator.dupe(u8, "All");
    const to = e.port_to orelse from;
    if (from == to) return allocator.print("{d}", .{from});
    return allocator.print("{d}-{d}", .{ from, to });
}

fn entryLess(_: void, a: Ec2.NetworkAclEntry, b: Ec2.NetworkAclEntry) bool {
    if (a.egress != b.egress) return !a.egress;
    return a.rule_number < b.rule_number;
}

// ─── View fields ─────────────────────────────────────────────────────────────

fg_color: []const u8,
bg_color: []const u8,
/// Row-major, spec.columns.len cells per row; every cell is owned.
cells: [][]u8,
state: table.State,
alloc: std.mem.Allocator,
breadcrumb_buf: [320]u8 = undefined,
breadcrumb_len: usize = 0,

// ─── Init / deinit ───────────────────────────────────────────────────────────

/// Copies the rules of `acl`, inbound first, each direction by rule number.
pub fn init(
    allocator: std.mem.Allocator,
    acl: Ec2.NetworkAcl,
    fg_color: []const u8,
    bg_color: []const u8,
    parent_breadcrumb: []const u8,
) !RulesView {
    const sorted = try allocator.dupe(Ec2.NetworkAclEntry, acl.entries);
    defer allocator.free(sorted);
    std.mem.sortUnstable(Ec2.NetworkAclEntry, sorted, {}, entryLess);

    const ncols = spec.columns.len;
    const cells = try allocator.alloc([]u8, sorted.len * ncols);
    var built: usize = 0;
    errdefer {
        for (cells[0..built]) |c| allocator.free(c);
        allocator.free(cells);
    }

    for (sorted) |e| {
        const rule = if (e.rule_number == catch_all_rule) try allocator.dupe(u8, "*") else try allocator.print("{d}", .{e.rule_number});
        cells[built] = rule;
        built += 1;
        cells[built] = try allocator.dupe(u8, if (e.egress) "Outbound" else "Inbound");
        built += 1;
        cells[built] = try allocator.dupe(u8, protocolName(e.protocol));
        built += 1;
        cells[built] = try portsText(allocator, e);
        built += 1;
        cells[built] = try allocator.dupe(u8, if (e.cidr_block.len > 0) e.cidr_block else e.ipv6_cidr_block);
        built += 1;
        cells[built] = try allocator.dupe(u8, if (e.allow) "Allow" else "Deny");
        built += 1;
    }

    var view = RulesView{
        .fg_color = fg_color,
        .bg_color = bg_color,
        .cells = cells,
        .state = .init(allocator),
        .alloc = allocator,
    };
    const bc = std.fmt.bufPrint(&view.breadcrumb_buf, "{s} {s} {s}", .{ parent_breadcrumb, constants.SEP_ARROW, name }) catch view.breadcrumb_buf[0..0];
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
    return self.state.visible(spec, self.cells).len;
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

/// Column index for a `:sort` name.
pub fn parseSortKey(tok: []const u8) ?usize {
    return table.columnIndex(spec, tok);
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
    try table.render(writer, size, self.fg_color, self.bg_color, spec, self.cells, &self.state);
}

// ============================================================================
// Tests
// ============================================================================

fn testEntry(rule: i32, egress: bool, allow: bool, protocol: []const u8, from: ?u32, to: ?u32) Ec2.NetworkAclEntry {
    return .{
        .rule_number = rule,
        .protocol = @constCast(protocol),
        .allow = allow,
        .egress = egress,
        .cidr_block = @constCast("10.0.0.0/8"),
        .ipv6_cidr_block = @constCast(""),
        .port_from = from,
        .port_to = to,
    };
}

test "rules are listed inbound first, by rule number, with readable fields" {
    var entries = [_]Ec2.NetworkAclEntry{
        testEntry(32767, true, false, "-1", null, null),
        testEntry(200, false, true, "17", 53, 53),
        testEntry(100, false, false, "6", 1024, 65535),
        testEntry(50, true, true, "1", null, null),
    };
    const acl: Ec2.NetworkAcl = .{
        .allocator = std.testing.allocator,
        .network_acl_id = @constCast("acl-1"),
        .vpc_id = @constCast("vpc-1"),
        .owner_id = @constCast(""),
        .is_default = false,
        .name = @constCast(""),
        .tags = &.{},
        .associations = &.{},
        .entries = &entries,
    };

    var view = try init(std.testing.allocator, acl, "", "", "VPC");
    defer view.deinit();

    try std.testing.expectEqual(@as(usize, 4), view.rowCount());
    const n = spec.columns.len;
    try std.testing.expectEqualStrings("100", view.cells[0 * n + 0]);
    try std.testing.expectEqualStrings("Inbound", view.cells[0 * n + 1]);
    try std.testing.expectEqualStrings("TCP", view.cells[0 * n + 2]);
    try std.testing.expectEqualStrings("1024-65535", view.cells[0 * n + 3]);
    try std.testing.expectEqualStrings("Deny", view.cells[0 * n + 5]);
    try std.testing.expectEqualStrings("UDP", view.cells[1 * n + 2]);
    try std.testing.expectEqualStrings("53", view.cells[1 * n + 3]);
    try std.testing.expectEqualStrings("50", view.cells[2 * n + 0]);
    try std.testing.expectEqualStrings("Outbound", view.cells[2 * n + 1]);
    try std.testing.expectEqualStrings("All", view.cells[2 * n + 3]);
    try std.testing.expectEqualStrings("*", view.cells[3 * n + 0]);
    try std.testing.expectEqualStrings("All", view.cells[3 * n + 2]);
}
