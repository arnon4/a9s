const std = @import("std");
const Credentials = @import("../../../sdk/credentials/fetcher.zig").Credentials;
const terminal = @import("../../../terminal/terminal.zig");
const Event = @import("../../../event.zig").Event;
const view_mod = @import("../../../ui/view.zig");
const Action = view_mod.Action;
const ViewContext = view_mod.ViewContext;
const Coord = terminal.Coord;
const Ec2 = @import("../../../sdk/clients/ec2/client.zig");
const constants = @import("../../../ui/constants.zig");
const ConfirmView = @import("../../../ui/confirm.zig");
const InternetGatewayView = @import("internet_gateway.zig");

const RoutesView = @This();
pub const name: []const u8 = "Routes";

/// Breadcrumb of the internet gateway list; a gateway reached from here is shown as if opened from it.
const igws_breadcrumb = "VPC " ++ constants.SEP_ARROW ++ " Internet Gateways";

const propagation_origin = "EnableVgwRoutePropagation";

const Mode = enum {
    wide, //   >=110: Destination | Target | Status | Propagated | Route Origin
    medium, //   >=80: Destination | Target | Status
    narrow, //   <80: Destination | Target
};

const Column = enum { target, status, propagated, origin };

fn columnsFor(mode: Mode) []const Column {
    return switch (mode) {
        .wide => &.{ .target, .status, .propagated, .origin },
        .medium => &.{ .target, .status },
        .narrow => &.{.target},
    };
}

fn columnWidth(col: Column) usize {
    return switch (col) {
        .target => 30,
        .status => 11,
        .propagated => 12,
        .origin => 28,
    };
}

fn columnTitle(col: Column) []const u8 {
    return switch (col) {
        .target => "Target",
        .status => "Status",
        .propagated => "Propagated",
        .origin => "Route Origin",
    };
}

// ─── Local item ──────────────────────────────────────────────────────────────

const RouteItem = struct {
    destination: []u8,
    target: []u8,
    status: []u8,
    propagated: []const u8,
    origin: []u8,
    /// Name tag of the targeted internet gateway; empty when not an internet gateway or unnamed.
    igw_name: []u8,

    fn deinit(self: RouteItem, a: std.mem.Allocator) void {
        a.free(self.destination);
        a.free(self.target);
        a.free(self.status);
        a.free(self.origin);
        a.free(self.igw_name);
    }

    fn isIgw(self: RouteItem) bool {
        return std.mem.startsWith(u8, self.target, "igw-");
    }

    fn column(self: RouteItem, col: Column) []const u8 {
        return switch (col) {
            .target => if (self.target.len > 0) self.target else "-",
            .status => if (self.status.len > 0) self.status else "-",
            .propagated => self.propagated,
            .origin => if (self.origin.len > 0) self.origin else "-",
        };
    }
};

fn igwNameFor(igws: ?Ec2.DescribeInternetGatewaysResult, id: []const u8) []const u8 {
    const r = igws orelse return "";
    for (r.internet_gateways) |g| {
        if (std.mem.eql(u8, g.internet_gateway_id, id)) return g.name;
    }
    return "";
}

fn routeToItem(a: std.mem.Allocator, r: Ec2.Route, igws: ?Ec2.DescribeInternetGatewaysResult) !RouteItem {
    const destination = try a.dupe(u8, r.destination);
    errdefer a.free(destination);
    const target = try a.dupe(u8, r.target);
    errdefer a.free(target);
    const status = try a.dupe(u8, r.state);
    errdefer a.free(status);
    const origin = try a.dupe(u8, r.origin);
    errdefer a.free(origin);
    const igw_name = try a.dupe(u8, igwNameFor(igws, r.target));
    errdefer a.free(igw_name);

    return .{
        .destination = destination,
        .target = target,
        .status = status,
        .propagated = if (std.mem.eql(u8, r.origin, propagation_origin)) "Yes" else "No",
        .origin = origin,
        .igw_name = igw_name,
    };
}

// ─── View fields ─────────────────────────────────────────────────────────────

fg_color: []const u8,
bg_color: []const u8,
items: []RouteItem,
selected: usize = 0,
scroll_offset: usize = 0,
pending_g: bool = false,
alloc: std.mem.Allocator,
credentials: Credentials,
region: []u8,
breadcrumb_buf: [320]u8 = undefined,
breadcrumb_len: usize = 0,

// ─── Init / deinit ───────────────────────────────────────────────────────────

/// Copies `routes` (and the gateway names it needs), so the view outlives its parent's fetch result.
pub fn init(
    allocator: std.mem.Allocator,
    credentials: Credentials,
    region: []const u8,
    routes: []const Ec2.Route,
    igws: ?Ec2.DescribeInternetGatewaysResult,
    fg_color: []const u8,
    bg_color: []const u8,
    parent_breadcrumb: []const u8,
) !RoutesView {
    const items = try allocator.alloc(RouteItem, routes.len);
    var built: usize = 0;
    errdefer {
        for (items[0..built]) |it| it.deinit(allocator);
        allocator.free(items);
    }
    for (routes) |r| {
        items[built] = try routeToItem(allocator, r, igws);
        built += 1;
    }

    const region_owned = try allocator.dupe(u8, region);
    errdefer allocator.free(region_owned);

    var view = RoutesView{
        .fg_color = fg_color,
        .bg_color = bg_color,
        .items = items,
        .alloc = allocator,
        .credentials = credentials,
        .region = region_owned,
    };
    const bc = std.fmt.bufPrint(&view.breadcrumb_buf, "{s} {s} {s}", .{ parent_breadcrumb, constants.SEP_ARROW, name }) catch view.breadcrumb_buf[0..0];
    view.breadcrumb_len = bc.len;
    return view;
}

pub fn breadcrumb(self: *RoutesView) []const u8 {
    return self.breadcrumb_buf[0..self.breadcrumb_len];
}

pub fn deinit(self: *RoutesView) void {
    for (self.items) |it| it.deinit(self.alloc);
    self.alloc.free(self.items);
    self.alloc.free(self.region);
}

// ─── Event handling ──────────────────────────────────────────────────────────

fn resetSelection(self: *RoutesView) void {
    self.selected = 0;
    self.scroll_offset = 0;
}

pub fn handleEvent(self: *RoutesView, event: Event, ctx: ViewContext) !Action {
    const count = self.items.len;

    switch (event) {
        .key => |k| switch (k) {
            .ctrl_c => return .quit,
            .char => |c| switch (c) {
                'q' => return .{ .push = .{ .confirm = ConfirmView.init(self.fg_color, self.bg_color) } },
                'j' => if (count > 0 and self.selected < count - 1) {
                    self.selected += 1;
                },
                'k' => if (self.selected > 0) {
                    self.selected -= 1;
                },
                'g' => {
                    if (self.pending_g) {
                        self.resetSelection();
                        self.pending_g = false;
                    } else {
                        self.pending_g = true;
                    }
                },
                'G' => {
                    self.pending_g = false;
                    if (count > 0) self.selected = count - 1;
                },
                else => self.pending_g = false,
            },
            .down => if (count > 0 and self.selected < count - 1) {
                self.selected += 1;
            },
            .up => if (self.selected > 0) {
                self.selected -= 1;
            },
            .enter => {
                if (self.selected >= count) return .none;
                const item = self.items[self.selected];
                if (!item.isIgw()) return .none;
                const v = try InternetGatewayView.init(
                    ctx.allocator,
                    ctx.io,
                    self.credentials,
                    self.region,
                    item.target,
                    if (item.igw_name.len > 0) item.igw_name else item.target,
                    self.fg_color,
                    self.bg_color,
                    igws_breadcrumb,
                );
                return .{ .push = .{ .vpc_internet_gateway = v } };
            },
            .escape => return .pop,
            else => {},
        },
        else => {},
    }
    return .none;
}

// ─── Rendering ───────────────────────────────────────────────────────────────

fn modeFor(width: i16) Mode {
    if (width >= 110) return .wide;
    if (width >= 80) return .medium;
    return .narrow;
}

fn destWidth(inner: usize, mode: Mode) usize {
    var fixed: usize = 0;
    for (columnsFor(mode)) |col| fixed += columnWidth(col) + 1;
    return if (inner > fixed + 2) inner - fixed else 2;
}

fn writePaddedCell(writer: *std.Io.Writer, text: []const u8, cell_w: usize) !void {
    const content_w = if (cell_w >= 2) cell_w - 2 else 0;
    try writer.writeByte(' ');
    const shown = if (text.len > content_w) text[0..content_w] else text;
    try writer.writeAll(shown);
    for (shown.len..content_w) |_| try writer.writeByte(' ');
    try writer.writeByte(' ');
}

fn writeVert(self: *RoutesView, writer: *std.Io.Writer, selected: bool, reset: bool) !void {
    if (selected) {
        try writer.writeAll(self.bg_color);
        try writer.writeAll(terminal.FG_BLACK);
    } else {
        try writer.writeAll(self.fg_color);
    }
    try writer.writeAll(constants.VERTICAL);
    if (reset) try writer.writeAll(terminal.RESET);
}

fn writeSepRow(self: *RoutesView, writer: *std.Io.Writer, dest_w: usize, mode: Mode, bottom: bool) !void {
    const left = if (bottom) constants.BOTTOM_LEFT else constants.LEFT_T;
    const mid = if (bottom) constants.BOTTOM_T else constants.CROSS;
    const right = if (bottom) constants.BOTTOM_RIGHT else constants.RIGHT_T;

    try writer.writeAll(self.fg_color);
    try writer.writeAll(left);
    for (0..dest_w) |_| try writer.writeAll(constants.HORIZONTAL);
    for (columnsFor(mode)) |col| {
        try writer.writeAll(mid);
        for (0..columnWidth(col)) |_| try writer.writeAll(constants.HORIZONTAL);
    }
    try writer.writeAll(right);
    try writer.writeAll(terminal.RESET);
}

fn writeHeaderCell(self: *RoutesView, writer: *std.Io.Writer, text: []const u8, cell_w: usize) !void {
    const content_w = if (cell_w >= 2) cell_w - 2 else 0;
    const text_len = @min(text.len, content_w);
    const pad = content_w - text_len;
    const left_pad = pad / 2;
    const right_pad = pad - left_pad;
    try writer.writeByte(' ');
    try writer.writeAll(self.bg_color);
    try writer.writeAll(terminal.FG_BLACK);
    for (0..left_pad) |_| try writer.writeByte(' ');
    try writer.writeAll(text[0..text_len]);
    for (0..right_pad) |_| try writer.writeByte(' ');
    try writer.writeAll(terminal.RESET);
    try writer.writeByte(' ');
}

fn writeHeaderRow(self: *RoutesView, writer: *std.Io.Writer, dest_w: usize, mode: Mode) !void {
    try self.writeVert(writer, false, true);
    try self.writeHeaderCell(writer, "Destination", dest_w);
    for (columnsFor(mode)) |col| {
        try self.writeVert(writer, false, true);
        try self.writeHeaderCell(writer, columnTitle(col), columnWidth(col));
    }
    try self.writeVert(writer, false, true);
}

fn writeItemRow(self: *RoutesView, writer: *std.Io.Writer, item: RouteItem, sel: bool, dest_w: usize, mode: Mode) !void {
    try self.writeVert(writer, sel, !sel);

    const content_w = if (dest_w >= 2) dest_w - 2 else 0;
    const max_dest = if (content_w >= 2) content_w - 2 else 0;
    const display = if (item.destination.len > 0) item.destination else "-";
    try writer.writeByte(' ');
    try writer.writeAll(if (sel) "▸ " else "  ");
    const shown = if (display.len > max_dest) display[0..max_dest] else display;
    try writer.writeAll(shown);
    for (shown.len..max_dest) |_| try writer.writeByte(' ');
    try writer.writeByte(' ');

    for (columnsFor(mode)) |col| {
        try self.writeVert(writer, sel, !sel);
        try writePaddedCell(writer, item.column(col), columnWidth(col));
    }

    try self.writeVert(writer, sel, true);
}

fn writeEmptyRow(self: *RoutesView, writer: *std.Io.Writer, dest_w: usize, mode: Mode) !void {
    try self.writeVert(writer, false, true);
    for (0..dest_w) |_| try writer.writeByte(' ');
    for (columnsFor(mode)) |col| {
        try self.writeVert(writer, false, true);
        for (0..columnWidth(col)) |_| try writer.writeByte(' ');
    }
    try self.writeVert(writer, false, true);
}

pub fn render(self: *RoutesView, writer: *std.Io.Writer, size: Coord) !void {
    if (size.x < 10 or size.y < 4) return;
    const w: usize = @intCast(size.x);
    const h: usize = @intCast(size.y);
    const inner = w - 2;
    const mode = modeFor(size.x);
    const dest_w = destWidth(inner, mode);
    const show_header = h >= 6;
    const data_rows = if (show_header) h - 3 else h - 1;

    if (show_header) {
        try self.writeHeaderRow(writer, dest_w, mode);
        try writer.writeAll("\r\n");
        try self.writeSepRow(writer, dest_w, mode, false);
        try writer.writeAll("\r\n");
    }

    const total = self.items.len;
    if (total > 0) {
        if (self.selected >= total) self.selected = total - 1;
        if (self.selected < self.scroll_offset) self.scroll_offset = self.selected;
        if (data_rows > 0 and self.selected >= self.scroll_offset + data_rows)
            self.scroll_offset = self.selected - data_rows + 1;
    } else {
        self.resetSelection();
    }

    var rendered: usize = 0;
    var idx = self.scroll_offset;
    while (idx < total and rendered < data_rows) : (idx += 1) {
        try self.writeItemRow(writer, self.items[idx], idx == self.selected, dest_w, mode);
        try writer.writeAll("\r\n");
        rendered += 1;
    }
    for (rendered..data_rows) |_| {
        try self.writeEmptyRow(writer, dest_w, mode);
        try writer.writeAll("\r\n");
    }

    try self.writeSepRow(writer, dest_w, mode, true);
}

// ============================================================================
// Tests
// ============================================================================

test "modeFor thresholds" {
    try std.testing.expectEqual(Mode.wide, modeFor(110));
    try std.testing.expectEqual(Mode.medium, modeFor(80));
    try std.testing.expectEqual(Mode.narrow, modeFor(79));
}

test "destWidth shrinks with columns" {
    try std.testing.expect(destWidth(150, .narrow) < 150);
    try std.testing.expect(destWidth(150, .wide) < destWidth(150, .medium));
    try std.testing.expectEqual(@as(usize, 2), destWidth(10, .wide));
}

test "routeToItem marks propagated routes and resolves gateway names" {
    const a = std.testing.allocator;
    const route: Ec2.Route = .{
        .destination = @constCast("0.0.0.0/0"),
        .target = @constCast("igw-1"),
        .state = @constCast("active"),
        .origin = @constCast("EnableVgwRoutePropagation"),
    };
    const item = try routeToItem(a, route, null);
    defer item.deinit(a);
    try std.testing.expectEqualStrings("Yes", item.propagated);
    try std.testing.expect(item.isIgw());
    try std.testing.expectEqualStrings("", item.igw_name);
}
