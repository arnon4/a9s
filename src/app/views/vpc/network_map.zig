const std = @import("std");
const Credentials = @import("../../../sdk/credentials/fetcher.zig").Credentials;
const terminal = @import("../../../terminal/terminal.zig");
const input = @import("../../../terminal/input.zig");
const Event = @import("../../../event.zig").Event;
const view_mod = @import("../../../ui/view.zig");
const Action = view_mod.Action;
const ViewContext = view_mod.ViewContext;
const Coord = terminal.Coord;
const Ec2 = @import("../../../sdk/clients/ec2/client.zig");
const constants = @import("../../../ui/constants.zig");
const ConfirmView = @import("../../../ui/confirm.zig");
const graph_mod = @import("network_map_graph.zig");
const Graph = graph_mod.Graph;
const Cell = graph_mod.Cell;
const Col = graph_mod.Col;
const Direction = graph_mod.Direction;
const Mark = graph_mod.Mark;
const SubnetView = @import("subnet.zig");
const RouteTableView = @import("route_table.zig");
const InternetGatewayView = @import("internet_gateway.zig");

const NetworkMapView = @This();
pub const name: []const u8 = "Network Map";

/// Width of a hop: two branch glyphs plus a four-character arrow.
const hop_width = 6;

// ─── Background fetch context ────────────────────────────────────────────────

const FetchCtx = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    credentials: Credentials,
    region: []u8,
    vpc_id: []u8,
    subnets: ?Ec2.DescribeSubnetsResult = null,
    route_tables: ?Ec2.DescribeRouteTablesResult = null,
    igws: ?Ec2.DescribeInternetGatewaysResult = null,
    nats: ?Ec2.DescribeNatGatewaysResult = null,
    /// Peerings where this VPC is the requester / the accepter.
    peerings_requester: ?Ec2.DescribeVpcPeeringConnectionsResult = null,
    peerings_accepter: ?Ec2.DescribeVpcPeeringConnectionsResult = null,
    tgw_attachments: ?Ec2.DescribeTransitGatewayVpcAttachmentsResult = null,
    vpces: ?Ec2.DescribeVpcEndpointsResult = null,
    vgws: ?Ec2.DescribeVpnGatewaysResult = null,
    eigws: ?Ec2.DescribeEgressOnlyInternetGatewaysResult = null,
    available: graph_mod.Availability = .{},
    err: ?anyerror = null,
    done: std.atomic.Value(bool) = .init(false),
    thread: std.Thread = undefined,
};

/// Runs `call`; a failure marks the dependent hops as unknown instead of aborting the map.
fn optional(call: anytype, available: *bool) ?@typeInfo(@TypeOf(call)).error_union.payload {
    return call catch {
        available.* = false;
        return null;
    };
}

fn fetchThread(ctx: *FetchCtx) void {
    defer {
        ctx.done.store(true, .release);
        input.notify();
    }

    var client = Ec2.Client.init(ctx.allocator, .{
        .region = ctx.region,
        .io = ctx.io,
        .credentials = ctx.credentials,
    }) catch |e| {
        ctx.err = e;
        return;
    };
    defer client.deinit();

    const vpc_ids = [_][]const u8{ctx.vpc_id};
    const by_vpc = [_]Ec2.Filter{.{ .name = "vpc-id", .values = &vpc_ids }};
    const by_attachment = [_]Ec2.Filter{.{ .name = "attachment.vpc-id", .values = &vpc_ids }};

    ctx.subnets = client.describeSubnets(.{ .params = .{ .filters = &by_vpc } }) catch |e| {
        ctx.err = e;
        return;
    };
    ctx.route_tables = client.describeRouteTables(.{ .params = .{ .filters = &by_vpc } }) catch |e| {
        ctx.err = e;
        return;
    };

    // Only ask about target types that routes actually use.
    var need_igw = false;
    var need_nat = false;
    var need_pcx = false;
    var need_tgw = false;
    var need_vpce = false;
    var need_vgw = false;
    var need_eigw = false;
    for (ctx.route_tables.?.route_tables) |t| {
        for (t.routes) |r| switch (graph_mod.classify(r.target)) {
            .igw => need_igw = true,
            .nat => {
                need_nat = true;
                need_igw = true;
            },
            .pcx => need_pcx = true,
            .tgw => need_tgw = true,
            .vpce => need_vpce = true,
            .vgw => need_vgw = true,
            .eigw => need_eigw = true,
            else => {},
        };
    }

    if (need_igw) ctx.igws = optional(client.describeInternetGateways(.{ .params = .{ .filters = &by_attachment } }), &ctx.available.igws);
    if (need_nat) ctx.nats = optional(client.describeNatGateways(.{ .params = .{ .filters = &by_vpc } }), &ctx.available.nats);
    if (need_pcx) {
        const as_requester = [_]Ec2.Filter{.{ .name = "requester-vpc-info.vpc-id", .values = &vpc_ids }};
        const as_accepter = [_]Ec2.Filter{.{ .name = "accepter-vpc-info.vpc-id", .values = &vpc_ids }};
        var req_ok = true;
        var acc_ok = true;
        ctx.peerings_requester = optional(client.describeVpcPeeringConnections(.{ .params = .{ .filters = &as_requester } }), &req_ok);
        ctx.peerings_accepter = optional(client.describeVpcPeeringConnections(.{ .params = .{ .filters = &as_accepter } }), &acc_ok);
        ctx.available.peerings = req_ok or acc_ok;
    }
    if (need_tgw) ctx.tgw_attachments = optional(client.describeTransitGatewayVpcAttachments(.{ .params = .{ .filters = &by_vpc } }), &ctx.available.tgw_attachments);
    if (need_vpce) ctx.vpces = optional(client.describeVpcEndpoints(.{ .params = .{ .filters = &by_vpc } }), &ctx.available.vpces);
    if (need_vgw) ctx.vgws = optional(client.describeVpnGateways(.{ .params = .{ .filters = &by_attachment } }), &ctx.available.vgws);
    if (need_eigw) ctx.eigws = optional(client.describeEgressOnlyInternetGateways(.{}), &ctx.available.eigws);
}

fn deinitOptional(r: anytype) void {
    if (r) |x| x.deinit();
}

// ─── View fields ─────────────────────────────────────────────────────────────

fg_color: []const u8,
bg_color: []const u8,
ctx: *FetchCtx,
alloc: std.mem.Allocator,
direction: Direction = .outbound,
/// Built once the fetch finishes; rebuilt when the direction toggles.
graph: ?Graph = null,
/// Peerings from both queries, shallow-copied so the graph sees one slice.
peerings: []Ec2.VpcPeeringConnection = &.{},
/// Index into graph.cells of the selected cell.
sel: usize = 0,
/// (row, col) -> cell index, rows * col_count entries.
grid: []?u32 = &.{},
col_w: [graph_mod.col_count]usize = @splat(0),
scroll_row: usize = 0,
scroll_col: usize = 0,
pending_g: bool = false,
display_name: []u8,
breadcrumb_buf: [320]u8 = undefined,
breadcrumb_len: usize = 0,

// ─── Init / deinit ───────────────────────────────────────────────────────────

pub fn init(
    allocator: std.mem.Allocator,
    io: std.Io,
    credentials: Credentials,
    region: []const u8,
    vpc_id: []const u8,
    display_name: []const u8,
    fg_color: []const u8,
    bg_color: []const u8,
    parent_breadcrumb: []const u8,
) !NetworkMapView {
    const display_owned = try allocator.dupe(u8, display_name);
    errdefer allocator.free(display_owned);

    const ctx = try allocator.create(FetchCtx);
    errdefer allocator.destroy(ctx);
    const region_owned = try allocator.dupe(u8, region);
    errdefer allocator.free(region_owned);
    const vpc_owned = try allocator.dupe(u8, vpc_id);
    errdefer allocator.free(vpc_owned);

    ctx.* = .{
        .allocator = allocator,
        .io = io,
        .credentials = credentials,
        .region = region_owned,
        .vpc_id = vpc_owned,
    };
    ctx.thread = try std.Thread.spawn(.{}, fetchThread, .{ctx});

    var view = NetworkMapView{
        .fg_color = fg_color,
        .bg_color = bg_color,
        .ctx = ctx,
        .alloc = allocator,
        .display_name = display_owned,
    };
    const bc = std.fmt.bufPrint(&view.breadcrumb_buf, "{s} {s} {s}", .{ parent_breadcrumb, constants.SEP_ARROW, name }) catch view.breadcrumb_buf[0..0];
    view.breadcrumb_len = bc.len;
    return view;
}

pub fn breadcrumb(self: *NetworkMapView) []const u8 {
    return self.breadcrumb_buf[0..self.breadcrumb_len];
}

pub fn deinit(self: *NetworkMapView) void {
    const c = self.ctx;
    c.thread.join();
    self.freeGraph();
    deinitOptional(c.subnets);
    deinitOptional(c.route_tables);
    deinitOptional(c.igws);
    deinitOptional(c.nats);
    deinitOptional(c.peerings_requester);
    deinitOptional(c.peerings_accepter);
    deinitOptional(c.tgw_attachments);
    deinitOptional(c.vpces);
    deinitOptional(c.vgws);
    deinitOptional(c.eigws);
    const alloc = c.allocator;
    alloc.free(c.region);
    alloc.free(c.vpc_id);
    alloc.destroy(c);
    self.alloc.free(self.display_name);
    if (self.peerings.len > 0) self.alloc.free(self.peerings);
}

fn freeGraph(self: *NetworkMapView) void {
    if (self.graph) |*g| g.deinit();
    self.graph = null;
    if (self.grid.len > 0) self.alloc.free(self.grid);
    self.grid = &.{};
}

// ─── Graph ───────────────────────────────────────────────────────────────────

fn resultSlice(comptime field: []const u8, r: anytype) []const @typeInfo(@TypeOf(@field(r.?, field))).pointer.child {
    return if (r) |x| @field(x, field) else &.{};
}

/// (Re)builds the graph and its lookup grid from the fetched data. Keeps the selection index.
fn rebuild(self: *NetworkMapView) !void {
    const c = self.ctx;

    if (self.peerings.len == 0) {
        const a = resultSlice("vpc_peering_connections", c.peerings_requester);
        const b = resultSlice("vpc_peering_connections", c.peerings_accepter);
        if (a.len + b.len > 0) {
            const all = try self.alloc.alloc(Ec2.VpcPeeringConnection, a.len + b.len);
            @memcpy(all[0..a.len], a);
            @memcpy(all[a.len..], b);
            self.peerings = all;
        }
    }

    const data: graph_mod.Input = .{
        .vpc_id = c.vpc_id,
        .subnets = resultSlice("subnets", c.subnets),
        .route_tables = resultSlice("route_tables", c.route_tables),
        .igws = resultSlice("internet_gateways", c.igws),
        .nats = resultSlice("nat_gateways", c.nats),
        .peerings = self.peerings,
        .tgw_attachments = resultSlice("transit_gateway_vpc_attachments", c.tgw_attachments),
        .vpces = resultSlice("vpc_endpoints", c.vpces),
        .vgws = resultSlice("vpn_gateways", c.vgws),
        .eigws = resultSlice("egress_only_internet_gateways", c.eigws),
        .available = c.available,
    };

    const first_build = self.graph == null;
    var g = try graph_mod.build(self.alloc, data, self.direction);
    errdefer g.deinit();

    const grid = try self.alloc.alloc(?u32, @max(g.rows * graph_mod.col_count, 1));
    errdefer self.alloc.free(grid);
    @memset(grid, null);

    var widths: [graph_mod.col_count]usize = @splat(0);
    for (g.cells, 0..) |cell, i| {
        grid[cell.row * graph_mod.col_count + @backingInt(cell.col)] = @intCast(i);
        const ci = @backingInt(cell.col);
        const wd = if (cell.is_hop) hop_width else textCols(cell.text) + 1;
        widths[ci] = @max(widths[ci], wd);
    }

    self.freeGraph();
    self.graph = g;
    self.grid = grid;
    self.col_w = widths;

    if (first_build or self.sel >= g.cells.len) {
        self.sel = 0;
        for (g.cells, 0..) |cell, i| {
            if (cell.selectable) {
                self.sel = i;
                break;
            }
        }
    }
}

fn cpLen(b: u8) usize {
    return if (b < 0x80) 1 else if (b < 0xE0) 2 else if (b < 0xF0) 3 else 4;
}

fn textCols(text: []const u8) usize {
    var n: usize = 0;
    var i: usize = 0;
    while (i < text.len) : (n += 1) i += cpLen(text[i]);
    return n;
}

// ─── Selection ───────────────────────────────────────────────────────────────

fn absDiff(a: usize, b: usize) usize {
    return if (a > b) a - b else b - a;
}

/// Moves to the nearest selectable cell above (-1) or below (+1) in the same column.
fn moveV(self: *NetworkMapView, delta: i32) void {
    const g = self.graph orelse return;
    const cur = g.cells[self.sel];
    var best: ?usize = null;
    var best_dist: usize = std.math.maxInt(usize);
    for (g.cells, 0..) |c, i| {
        if (!c.selectable or c.col != cur.col) continue;
        if (delta > 0 and c.row <= cur.row) continue;
        if (delta < 0 and c.row >= cur.row) continue;
        const d = absDiff(c.row, cur.row);
        if (d < best_dist) {
            best_dist = d;
            best = i;
        }
    }
    if (best) |b| self.sel = b;
}

/// Moves to the nearest column in the given direction that has a selectable cell,
/// preferring the same group and the closest row.
fn moveH(self: *NetworkMapView, delta: i32) void {
    const g = self.graph orelse return;
    const cur = g.cells[self.sel];
    var col: i32 = @as(i32, @backingInt(cur.col)) + delta;
    while (col >= 0 and col < graph_mod.col_count) : (col += delta) {
        var best: ?usize = null;
        var best_key: [2]usize = .{ std.math.maxInt(usize), std.math.maxInt(usize) };
        for (g.cells, 0..) |c, i| {
            if (!c.selectable or @backingInt(c.col) != col) continue;
            const key: [2]usize = .{ @intFromBool(c.group != cur.group), absDiff(c.row, cur.row) };
            if (key[0] < best_key[0] or (key[0] == best_key[0] and key[1] < best_key[1])) {
                best_key = key;
                best = i;
            }
        }
        if (best) |b| {
            self.sel = b;
            return;
        }
    }
}

fn toggleDirection(self: *NetworkMapView) void {
    self.direction = if (self.direction == .outbound) .inbound else .outbound;
    self.rebuild() catch {};
}

// ─── Event handling ──────────────────────────────────────────────────────────

fn subnetDisplay(self: *const NetworkMapView, id: []const u8) []const u8 {
    if (self.ctx.subnets) |r| for (r.subnets) |s| {
        if (std.mem.eql(u8, s.subnet_id, id)) return if (s.name.len > 0) s.name else id;
    };
    return id;
}

fn rtbDisplay(self: *const NetworkMapView, id: []const u8) []const u8 {
    if (self.ctx.route_tables) |r| for (r.route_tables) |t| {
        if (std.mem.eql(u8, t.route_table_id, id)) return if (t.name.len > 0) t.name else id;
    };
    return id;
}

fn igwDisplay(self: *const NetworkMapView, id: []const u8) []const u8 {
    if (self.ctx.igws) |r| for (r.internet_gateways) |g| {
        if (std.mem.eql(u8, g.internet_gateway_id, id)) return if (g.name.len > 0) g.name else id;
    };
    return id;
}

pub fn handleEvent(self: *NetworkMapView, event: Event, ctx: ViewContext) !Action {
    switch (event) {
        .key => |k| switch (k) {
            .ctrl_c => return .quit,
            .escape => return .pop,
            .char => |c| switch (c) {
                'q' => return .{ .push = .{ .confirm = ConfirmView.init(self.fg_color, self.bg_color) } },
                'j' => self.moveV(1),
                'k' => self.moveV(-1),
                'h' => self.moveH(-1),
                'l' => self.moveH(1),
                'i' => self.toggleDirection(),
                else => {},
            },
            .down => self.moveV(1),
            .up => self.moveV(-1),
            .left => self.moveH(-1),
            .right => self.moveH(1),
            .enter => {
                const g = self.graph orelse return .none;
                if (self.sel >= g.cells.len) return .none;
                const credentials = self.ctx.credentials;
                const region = self.ctx.region;
                switch (g.cells[self.sel].ref) {
                    .none => {},
                    .subnet => |id| {
                        const v = try SubnetView.init(ctx.allocator, ctx.io, credentials, region, id, self.subnetDisplay(id), self.fg_color, self.bg_color, self.breadcrumb());
                        return .{ .push = .{ .vpc_subnet = v } };
                    },
                    .route_table => |id| {
                        const v = try RouteTableView.init(ctx.allocator, ctx.io, credentials, region, id, self.rtbDisplay(id), self.fg_color, self.bg_color, self.breadcrumb());
                        return .{ .push = .{ .vpc_route_table = v } };
                    },
                    .igw => |id| {
                        const v = try InternetGatewayView.init(ctx.allocator, ctx.io, credentials, region, id, self.igwDisplay(id), self.fg_color, self.bg_color, self.breadcrumb());
                        return .{ .push = .{ .vpc_internet_gateway = v } };
                    },
                }
            },
            else => {},
        },
        else => {},
    }
    return .none;
}

// ─── Rendering ───────────────────────────────────────────────────────────────

/// Writes one terminal line, clipping to `left` visible columns after skipping `skip`.
const Line = struct {
    writer: *std.Io.Writer,
    skip: usize = 0,
    left: usize,

    fn put(self: *Line, text: []const u8) !void {
        var i: usize = 0;
        while (i < text.len and self.left > 0) {
            const end = @min(i + cpLen(text[i]), text.len);
            if (self.skip > 0) {
                self.skip -= 1;
            } else {
                try self.writer.writeAll(text[i..end]);
                self.left -= 1;
            }
            i = end;
        }
    }

    fn raw(self: *Line, codes: []const u8) !void {
        try self.writer.writeAll(codes);
    }

    fn spaces(self: *Line, n: usize) !void {
        for (0..n) |_| try self.put(" ");
    }

    fn fill(self: *Line) !void {
        try self.writer.writeAll(terminal.RESET);
        try self.spaces(self.left);
    }
};

fn markGlyph(m: Mark) []const u8 {
    return switch (m) {
        .ok => "✓",
        .blocked => "✗",
        .unknown => "?",
    };
}

fn markColor(m: Mark) []const u8 {
    return switch (m) {
        .ok => terminal.FG_GREEN,
        .blocked => terminal.FG_RED,
        .unknown => terminal.FG_YELLOW,
    };
}

/// A cell is related to the selection when it shares its group and path (shared cells relate to every path).
fn related(c: Cell, s: Cell) bool {
    if (c.group != s.group) return false;
    return c.path == null or s.path == null or c.path.? == s.path.?;
}

fn writeCell(self: *NetworkMapView, line: *Line, cell: Cell, selected: bool, sel_cell: Cell) !void {
    const faded = cell.dim or !related(cell, sel_cell);
    if (!cell.is_hop) {
        const width = self.col_w[@backingInt(cell.col)];
        if (selected) {
            try line.raw(self.bg_color);
            try line.raw(terminal.FG_BLACK);
        } else {
            try line.raw(self.fg_color);
            if (faded) try line.raw(terminal.DIM);
        }
        try line.put(cell.text);
        try line.raw(terminal.RESET);
        try line.spaces(width -| textCols(cell.text));
        return;
    }

    // Hop: branch glyphs, then the arrow with its mark.
    try line.raw(self.fg_color);
    if (faded) try line.raw(terminal.DIM);
    try line.put(cell.pre);
    if (!cell.body) {
        try line.raw(terminal.RESET);
        try line.spaces(hop_width - textCols(cell.pre));
        return;
    }
    const inbound = self.direction == .inbound;
    try line.put(if (inbound) "◀" else "─");
    if (selected) {
        try line.raw(terminal.RESET);
        try line.raw(self.bg_color);
        try line.raw(terminal.FG_BLACK);
    }
    if (cell.mark) |m| {
        if (!selected) try line.raw(markColor(m));
        try line.put(markGlyph(m));
        if (!selected) {
            try line.raw(terminal.RESET);
            try line.raw(self.fg_color);
            if (faded) try line.raw(terminal.DIM);
        }
    } else {
        try line.put("─");
    }
    if (selected) {
        try line.raw(terminal.RESET);
        try line.raw(self.fg_color);
        if (faded) try line.raw(terminal.DIM);
    }
    try line.put(if (inbound) "──" else "─▶");
    try line.raw(terminal.RESET);
}

fn writeDetail(self: *NetworkMapView, line: *Line, g: Graph) !void {
    const cell = g.cells[self.sel];
    var mark: ?Mark = cell.mark;
    if (!cell.is_hop and cell.col != .subnet and cell.col != .route_table) {
        // A node's explanation is that of the hop leading into it.
        const hop_col = @backingInt(cell.col) - 1;
        if (g.rows > 0) {
            if (self.grid[cell.row * graph_mod.col_count + hop_col]) |hi| mark = g.cells[hi].mark;
        }
    }
    if (mark) |m| {
        try line.raw(markColor(m));
        try line.put(markGlyph(m));
        try line.raw(terminal.RESET);
        try line.put(" ");
    }
    try line.put(cell.reason);
    try line.fill();
}

fn writeFooter(self: *NetworkMapView, line: *Line) !void {
    try line.raw(self.bg_color);
    try line.raw(terminal.FG_BLACK);
    try line.put(if (self.direction == .outbound) " outbound ▸ " else " inbound ◂ ");
    try line.raw(terminal.RESET);
    try line.put(if (self.direction == .outbound) " [i] switch to inbound   " else " [i] switch to outbound   ");
    try line.raw(terminal.FG_GREEN);
    try line.put("✓");
    try line.raw(terminal.RESET);
    try line.put(" ok  ");
    try line.raw(terminal.FG_RED);
    try line.put("✗");
    try line.raw(terminal.RESET);
    try line.put(" blocked  ");
    try line.raw(terminal.FG_YELLOW);
    try line.put("?");
    try line.raw(terminal.RESET);
    try line.put(" unknown   hjkl move  Enter open");
    try line.fill();
}

fn writeMessage(self: *NetworkMapView, writer: *std.Io.Writer, w: usize, h: usize, msg: []const u8) !void {
    for (0..h) |row| {
        var line: Line = .{ .writer = writer, .left = w };
        if (row == 0) {
            try line.raw(self.fg_color);
            try line.put(" ");
            try line.put(msg);
        }
        try line.fill();
        if (row + 1 < h) try writer.writeAll("\r\n");
    }
}

pub fn render(self: *NetworkMapView, writer: *std.Io.Writer, size: Coord) !void {
    if (size.x < 10 or size.y < 3) return;
    const w: usize = @intCast(size.x);
    const h: usize = @intCast(size.y);

    if (!self.ctx.done.load(.acquire)) return self.writeMessage(writer, w, h, "Loading network map…");
    if (self.ctx.err) |e| {
        var buf: [128]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "Error: {s}", .{@errorName(e)}) catch "Error loading network map";
        return self.writeMessage(writer, w, h, msg);
    }
    if (self.graph == null) self.rebuild() catch |e| {
        var buf: [128]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "Error: {s}", .{@errorName(e)}) catch "Error building network map";
        return self.writeMessage(writer, w, h, msg);
    };
    const g = self.graph.?;
    if (g.cells.len == 0) return self.writeMessage(writer, w, h, "No subnets with route tables in this VPC");

    const sel_cell = g.cells[self.sel];
    const data_rows = h - 2;

    // Keep the selection on screen.
    if (sel_cell.row < self.scroll_row) self.scroll_row = sel_cell.row;
    if (sel_cell.row >= self.scroll_row + data_rows) self.scroll_row = sel_cell.row + 1 - data_rows;
    var x_start: usize = 0;
    for (self.col_w[0..@backingInt(sel_cell.col)]) |cw| x_start += cw;
    const x_end = x_start + self.col_w[@backingInt(sel_cell.col)];
    if (x_end > self.scroll_col + w) self.scroll_col = x_end - w;
    if (x_start < self.scroll_col) self.scroll_col = x_start;

    for (0..data_rows) |i| {
        const row = self.scroll_row + i;
        var line: Line = .{ .writer = writer, .skip = self.scroll_col, .left = w };
        if (row < g.rows) {
            for (0..graph_mod.col_count) |col| {
                const width = self.col_w[col];
                if (width == 0) continue;
                if (self.grid[row * graph_mod.col_count + col]) |ci| {
                    try self.writeCell(&line, g.cells[ci], ci == self.sel, sel_cell);
                } else {
                    try line.spaces(width);
                }
            }
        }
        try line.fill();
        try writer.writeAll("\r\n");
    }

    var detail: Line = .{ .writer = writer, .left = w };
    try detail.put(" ");
    try self.writeDetail(&detail, g);
    try writer.writeAll("\r\n");

    var footer: Line = .{ .writer = writer, .left = w };
    try self.writeFooter(&footer);
}

// ============================================================================
// Tests
// ============================================================================

test "textCols counts codepoints" {
    try std.testing.expectEqual(@as(usize, 3), textCols("abc"));
    try std.testing.expectEqual(@as(usize, 3), textCols("─✓▶"));
}

test "related shares group and path" {
    const shared: Cell = .{ .row = 0, .col = .subnet, .group = 1, .path = null };
    const p0: Cell = .{ .row = 0, .col = .node0, .group = 1, .path = 0 };
    const p1: Cell = .{ .row = 1, .col = .node0, .group = 1, .path = 1 };
    const other: Cell = .{ .row = 5, .col = .node0, .group = 2, .path = 0 };
    try std.testing.expect(related(p0, shared));
    try std.testing.expect(related(shared, p1));
    try std.testing.expect(!related(p0, p1));
    try std.testing.expect(!related(other, p0));
}
