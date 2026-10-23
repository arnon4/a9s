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
const table = @import("../../../ui/static_table.zig");
const filter_mod = @import("../../../commands/filter.zig");
const InternetGatewayView = @import("internet_gateway.zig");

const RoutesView = @This();
pub const name: []const u8 = "Routes";

/// Breadcrumb of the internet gateway list; a gateway reached from here is shown as if opened from it.
const igws_breadcrumb = "VPC " ++ constants.SEP_ARROW ++ " Internet Gateways";

const propagation_origin = "EnableVgwRoutePropagation";

const spec: table.Spec = .{
    .flex = 0,
    .columns = &.{
        .{ .title = "Destination", .key = "destination", .width = 0 },
        .{ .title = "Target", .key = "target", .width = 30 },
        .{ .title = "Status", .key = "status", .width = 11, .min_term_width = 80 },
        .{ .title = "Propagated", .key = "propagated", .width = 12, .min_term_width = 110 },
        .{ .title = "Route Origin", .key = "origin", .width = 28, .min_term_width = 110 },
    },
};

// ─── Local item ──────────────────────────────────────────────────────────────

const RouteItem = struct {
    destination: []u8,
    target: []u8,
    status: []u8,
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

    fn propagated(self: RouteItem) []const u8 {
        return if (std.mem.eql(u8, self.origin, propagation_origin)) "Yes" else "No";
    }
};

fn dash(s: []const u8) []const u8 {
    return if (s.len > 0) s else "-";
}

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
        .origin = origin,
        .igw_name = igw_name,
    };
}

// ─── View fields ─────────────────────────────────────────────────────────────

fg_color: []const u8,
bg_color: []const u8,
items: []RouteItem,
/// Row-major view of `items` for the table; points into the items' strings.
cells: [][]const u8,
state: table.State,
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

    const cells = try allocator.alloc([]const u8, items.len * spec.columns.len);
    errdefer allocator.free(cells);
    for (items, 0..) |it, i| {
        const row = cells[i * spec.columns.len ..][0..spec.columns.len];
        row[0] = dash(it.destination);
        row[1] = dash(it.target);
        row[2] = dash(it.status);
        row[3] = it.propagated();
        row[4] = dash(it.origin);
    }

    const region_owned = try allocator.dupe(u8, region);
    errdefer allocator.free(region_owned);

    var view = RoutesView{
        .fg_color = fg_color,
        .bg_color = bg_color,
        .items = items,
        .cells = cells,
        .state = .init(allocator),
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
    self.state.deinit();
    for (self.items) |it| it.deinit(self.alloc);
    self.alloc.free(self.items);
    self.alloc.free(self.cells);
    self.alloc.free(self.region);
}

// ─── Filter / sort (driven by the command bar) ───────────────────────────────

pub fn setLiveFilter(self: *RoutesView, text: []const u8) void {
    self.state.setLiveFilter(text);
}

pub fn commitFilter(self: *RoutesView, text: []const u8) void {
    self.state.commitFilter(text);
}

pub fn setFilterExpr(self: *RoutesView, result: filter_mod.ParseResult) void {
    self.state.setFilterExpr(result);
}

pub fn clearFilterExpr(self: *RoutesView) void {
    self.state.clearFilterExpr();
}

/// Sorts by the given column indices (see `parseSortKey`).
pub fn setSort(self: *RoutesView, keys: []const usize, dir: constants.SortDir) void {
    self.state.setSort(keys, dir);
}

/// Column index for a `:sort` name.
pub fn parseSortKey(tok: []const u8) ?usize {
    return table.columnIndex(spec, tok);
}

// ─── Event handling ──────────────────────────────────────────────────────────

fn rowCount(self: *RoutesView) usize {
    return self.state.visible(spec, self.cells).len;
}

pub fn handleEvent(self: *RoutesView, event: Event, ctx: ViewContext) !Action {
    switch (event) {
        .key => |k| switch (k) {
            .ctrl_c => return .quit,
            .char => |c| {
                if (c == 'q') return .{ .push = .{ .confirm = ConfirmView.init(self.fg_color, self.bg_color) } };
                _ = self.state.handleChar(c, self.rowCount());
            },
            .down => self.state.moveDown(self.rowCount()),
            .up => self.state.moveUp(),
            .enter => {
                const row = self.state.selectedRow(spec, self.cells) orelse return .none;
                const item = self.items[row];
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
            .escape => {
                if (self.state.clearOne()) return .none;
                return .pop;
            },
            else => {},
        },
        else => {},
    }
    return .none;
}

pub fn render(self: *RoutesView, writer: *std.Io.Writer, size: Coord) !void {
    try table.render(writer, size, self.fg_color, self.bg_color, spec, self.cells, &self.state);
}

// ============================================================================
// Tests
// ============================================================================

fn testRoute(destination: []const u8, target: []const u8, origin: []const u8) Ec2.Route {
    return .{
        .destination = @constCast(destination),
        .target = @constCast(target),
        .state = @constCast("active"),
        .origin = @constCast(origin),
    };
}

test "routes view marks propagated routes and keeps gateway targets selectable" {
    const routes = [_]Ec2.Route{
        testRoute("10.0.0.0/16", "local", "CreateRouteTable"),
        testRoute("0.0.0.0/0", "igw-1", "CreateRoute"),
        testRoute("192.168.0.0/16", "vgw-1", "EnableVgwRoutePropagation"),
    };
    var view = try init(std.testing.allocator, undefined, "us-east-1", &routes, null, "", "", "VPC");
    defer view.deinit();

    try std.testing.expectEqual(@as(usize, 3), view.rowCount());
    const n = spec.columns.len;
    try std.testing.expectEqualStrings("No", view.cells[1 * n + 3]);
    try std.testing.expectEqualStrings("Yes", view.cells[2 * n + 3]);
    try std.testing.expect(view.items[1].isIgw());
    try std.testing.expect(!view.items[0].isIgw());
}

test "sorting and filtering resolve the selected row back to its route" {
    const routes = [_]Ec2.Route{
        testRoute("10.0.0.0/16", "local", "CreateRouteTable"),
        testRoute("0.0.0.0/0", "igw-1", "CreateRoute"),
        testRoute("192.168.0.0/16", "vgw-1", "EnableVgwRoutePropagation"),
    };
    var view = try init(std.testing.allocator, undefined, "us-east-1", &routes, null, "", "", "VPC");
    defer view.deinit();

    view.setSort(&.{parseSortKey("destination").?}, .asc);
    try std.testing.expectEqual(@as(?usize, 1), view.state.selectedRow(spec, view.cells));

    view.commitFilter("vgw");
    try std.testing.expectEqual(@as(usize, 1), view.rowCount());
    try std.testing.expectEqual(@as(?usize, 2), view.state.selectedRow(spec, view.cells));
}
