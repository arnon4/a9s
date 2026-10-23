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
const props_mod = @import("../../../ui/props.zig");
const constants = @import("../../../ui/constants.zig");
const ConfirmView = @import("../../../ui/confirm.zig");
const RouteTableView = @import("route_table.zig");

const SubnetView = @This();
pub const name: []const u8 = "Subnet";

const MAX_TAG_PROPS = 50;
const MAX_PROPS = 24 + MAX_TAG_PROPS;

// ─── Background fetch context ────────────────────────────────────────────────

const FetchCtx = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    credentials: Credentials,
    region: []u8,
    subnet_id: []u8,
    result: ?Ec2.DescribeSubnetsResult = null,
    /// Route table governing the subnet: explicit association, else the VPC's main table.
    route_table: ?Ec2.DescribeRouteTablesResult = null,
    err: ?anyerror = null,
    done: std.atomic.Value(bool) = .init(false),
    thread: std.Thread = undefined,
};

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

    const ids = [_][]const u8{ctx.subnet_id};
    const result = client.describeSubnets(.{ .params = .{ .subnet_ids = &ids } }) catch |e| {
        ctx.err = e;
        return;
    };
    ctx.result = result;
    if (result.subnets.len == 0) {
        ctx.err = error.SubnetNotFound;
        return;
    }

    const explicit = [_]Ec2.Filter{.{ .name = "association.subnet-id", .values = &ids }};
    if (client.describeRouteTables(.{ .params = .{ .filters = &explicit } })) |r| {
        if (r.route_tables.len > 0) {
            ctx.route_table = r;
            return;
        }
        r.deinit();
    } else |_| {}

    const main_filters = [_]Ec2.Filter{
        .{ .name = "vpc-id", .values = &.{result.subnets[0].vpc_id} },
        .{ .name = "association.main", .values = &.{"true"} },
    };
    ctx.route_table = client.describeRouteTables(.{ .params = .{ .filters = &main_filters } }) catch null;
}

/// Route table of this subnet once the fetch has finished; null while loading or when none was found.
fn routeTable(self: *const SubnetView) ?Ec2.RouteTable {
    if (!self.ctx.done.load(.acquire)) return null;
    const r = self.ctx.route_table orelse return null;
    if (r.route_tables.len == 0) return null;
    return r.route_tables[0];
}

// ─── View fields ─────────────────────────────────────────────────────────────

fg_color: []const u8,
bg_color: []const u8,
scroll: usize = 0,
pending_g: bool = false,
display_name: []u8,
ctx: *FetchCtx,
alloc: std.mem.Allocator,
breadcrumb_buf: [320]u8 = undefined,
breadcrumb_len: usize = 0,

// ─── Init / deinit ───────────────────────────────────────────────────────────

pub fn init(
    allocator: std.mem.Allocator,
    io: std.Io,
    credentials: Credentials,
    region: []const u8,
    subnet_id: []const u8,
    display_name: []const u8,
    fg_color: []const u8,
    bg_color: []const u8,
    parent_breadcrumb: []const u8,
) !SubnetView {
    const display_owned = try allocator.dupe(u8, display_name);
    errdefer allocator.free(display_owned);

    const ctx = try allocator.create(FetchCtx);
    errdefer allocator.destroy(ctx);
    const region_owned = try allocator.dupe(u8, region);
    errdefer allocator.free(region_owned);
    const subnet_id_owned = try allocator.dupe(u8, subnet_id);
    errdefer allocator.free(subnet_id_owned);

    ctx.* = .{
        .allocator = allocator,
        .io = io,
        .credentials = credentials,
        .region = region_owned,
        .subnet_id = subnet_id_owned,
    };
    ctx.thread = try std.Thread.spawn(.{}, fetchThread, .{ctx});

    var view = SubnetView{
        .fg_color = fg_color,
        .bg_color = bg_color,
        .display_name = display_owned,
        .ctx = ctx,
        .alloc = allocator,
    };
    const bc = std.fmt.bufPrint(&view.breadcrumb_buf, "{s} {s} {s}", .{ parent_breadcrumb, constants.SEP_ARROW, display_name }) catch view.breadcrumb_buf[0..0];
    view.breadcrumb_len = bc.len;
    return view;
}

pub fn breadcrumb(self: *SubnetView) []const u8 {
    return self.breadcrumb_buf[0..self.breadcrumb_len];
}

pub fn deinit(self: *SubnetView) void {
    const alloc = self.ctx.allocator;
    self.ctx.thread.join();
    if (self.ctx.result) |r| r.deinit();
    if (self.ctx.route_table) |r| r.deinit();
    alloc.free(self.ctx.region);
    alloc.free(self.ctx.subnet_id);
    alloc.destroy(self.ctx);
    self.alloc.free(self.display_name);
}

// ─── Event handling ──────────────────────────────────────────────────────────

pub fn handleEvent(self: *SubnetView, event: Event, ctx: ViewContext) !Action {
    switch (event) {
        .key => |k| switch (k) {
            .ctrl_c => return .quit,
            .char => |c| switch (c) {
                'q' => return .{ .push = .{ .confirm = ConfirmView.init(self.fg_color, self.bg_color) } },
                'j' => self.scroll += 1,
                'k' => if (self.scroll > 0) {
                    self.scroll -= 1;
                },
                'g' => {
                    if (self.pending_g) {
                        self.scroll = 0;
                        self.pending_g = false;
                    } else {
                        self.pending_g = true;
                    }
                },
                'G' => {
                    self.pending_g = false;
                    // render clamps to the real row count
                    self.scroll = MAX_PROPS;
                },
                else => self.pending_g = false,
            },
            .down => self.scroll += 1,
            .up => if (self.scroll > 0) {
                self.scroll -= 1;
            },
            .enter => {
                const t = self.routeTable() orelse return .none;
                const v = try RouteTableView.init(
                    ctx.allocator,
                    ctx.io,
                    self.ctx.credentials,
                    self.ctx.region,
                    t.route_table_id,
                    if (t.name.len > 0) t.name else t.route_table_id,
                    self.fg_color,
                    self.bg_color,
                    self.breadcrumb(),
                );
                return .{ .push = .{ .vpc_route_table = v } };
            },
            .escape => return .pop,
            else => {},
        },
        else => {},
    }
    return .none;
}

// ─── Rendering ───────────────────────────────────────────────────────────────

/// Bump-allocates formatted text from a fixed buffer; yields "…" when full.
const TextBuf = struct {
    buf: []u8,
    off: usize = 0,

    fn print(self: *TextBuf, comptime fmt: []const u8, args: anytype) []const u8 {
        const out = std.fmt.bufPrint(self.buf[self.off..], fmt, args) catch return "…";
        self.off += out.len;
        return out;
    }
};

fn orDash(s: []const u8) []const u8 {
    return if (s.len > 0) s else "-";
}

fn yesNo(b: bool) []const u8 {
    return if (b) "Yes" else "No";
}

fn joinCidrs(text: *TextBuf, items: []const Ec2.VpcCidrAssociation) []const u8 {
    if (items.len == 0) return "-";
    const start = text.off;
    for (items, 0..) |c, i| {
        const sep: []const u8 = if (i > 0) ", " else "";
        _ = text.print("{s}{s} ({s})", .{ sep, c.cidr_block, c.state });
    }
    return text.buf[start..text.off];
}

pub fn render(self: *SubnetView, writer: *std.Io.Writer, size: Coord) !void {
    if (size.x < 10 or size.y < 2) return;
    const w: usize = @intCast(size.x);
    const h: usize = @intCast(size.y);

    const done = self.ctx.done.load(.acquire);
    const subnet: ?Ec2.Subnet = if (done and self.ctx.err == null) self.ctx.result.?.subnets[0] else null;

    var text_storage: [4096]u8 = undefined;
    var text: TextBuf = .{ .buf = &text_storage };

    const dash = "-";
    const pending: []const u8 = if (done) dash else "…";

    var props_buf: [MAX_PROPS]props_mod.Prop = undefined;
    var n: usize = 0;

    props_buf[n] = .{ .label = "Name", .value = if (subnet) |s| orDash(s.name) else orDash(self.display_name) };
    n += 1;
    props_buf[n] = .{ .label = "Subnet ID", .value = self.ctx.subnet_id };
    n += 1;
    props_buf[n] = .{ .label = "Region", .value = self.ctx.region };
    n += 1;

    if (self.ctx.err) |e| {
        if (done) {
            props_buf[n] = .{ .label = "Error", .value = @errorName(e) };
            n += 1;
        }
    }

    props_buf[n] = .{ .label = "ARN", .value = if (subnet) |s| orDash(s.subnet_arn) else pending };
    n += 1;
    props_buf[n] = .{ .label = "State", .value = if (subnet) |s| orDash(s.state) else pending };
    n += 1;
    props_buf[n] = .{ .label = "VPC ID", .value = if (subnet) |s| orDash(s.vpc_id) else pending };
    n += 1;
    props_buf[n] = .{ .label = "Account", .value = if (subnet) |s| orDash(s.owner_id) else pending };
    n += 1;
    props_buf[n] = .{ .label = "IPv4 CIDR", .value = if (subnet) |s| orDash(s.cidr_block) else pending };
    n += 1;
    props_buf[n] = .{ .label = "IPv6 CIDRs", .value = if (subnet) |s| joinCidrs(&text, s.ipv6_cidr_associations) else pending };
    n += 1;
    props_buf[n] = .{
        .label = "Route Table",
        .value = if (self.routeTable()) |t| text.print("{s}{s}{s}", .{
            t.route_table_id,
            if (t.name.len > 0) " " else "",
            t.name,
        }) else pending,
        .highlight = if (self.routeTable() != null) self.bg_color else "",
    };
    n += 1;
    props_buf[n] = .{ .label = "Availability Zone", .value = if (subnet) |s| orDash(s.availability_zone) else pending };
    n += 1;
    props_buf[n] = .{ .label = "AZ ID", .value = if (subnet) |s| orDash(s.availability_zone_id) else pending };
    n += 1;
    props_buf[n] = .{
        .label = "Free IPv4 Addresses",
        .value = if (subnet) |s| text.print("{d}", .{s.available_ip_address_count}) else pending,
    };
    n += 1;
    props_buf[n] = .{ .label = "Default for AZ", .value = if (subnet) |s| yesNo(s.default_for_az) else pending };
    n += 1;
    props_buf[n] = .{ .label = "Auto-assign Public IP", .value = if (subnet) |s| yesNo(s.map_public_ip_on_launch) else pending };
    n += 1;
    props_buf[n] = .{ .label = "Auto-assign IPv6", .value = if (subnet) |s| yesNo(s.assign_ipv6_address_on_creation) else pending };
    n += 1;
    props_buf[n] = .{ .label = "IPv6 Native", .value = if (subnet) |s| yesNo(s.ipv6_native) else pending };
    n += 1;
    props_buf[n] = .{ .label = "DNS64", .value = if (subnet) |s| yesNo(s.enable_dns64) else pending };
    n += 1;
    props_buf[n] = .{ .label = "Outpost ARN", .value = if (subnet) |s| orDash(s.outpost_arn) else pending };
    n += 1;

    if (subnet) |s| {
        if (s.tags.len == 0) {
            props_buf[n] = .{ .label = "Tags", .value = dash };
            n += 1;
        }
        for (s.tags[0..@min(s.tags.len, MAX_TAG_PROPS)], 0..) |t, i| {
            props_buf[n] = .{
                .label = if (i == 0) "Tags" else "",
                .value = text.print("{s} = {s}", .{ t.key, t.value }),
            };
            n += 1;
        }
    }

    const total = n;
    const data_rows = if (h >= 1) h - 1 else 0;
    if (data_rows > 0 and self.scroll + data_rows > total) {
        self.scroll = if (total > data_rows) total - data_rows else 0;
    }

    try props_mod.render(writer, props_buf[0..n], self.scroll, w, h, self.fg_color);
}
