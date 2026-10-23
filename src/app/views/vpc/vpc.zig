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

const VpcView = @This();
pub const name: []const u8 = "VPC";

const MAX_TAG_PROPS = 50;
const MAX_PROPS = 16 + MAX_TAG_PROPS;

// ─── Background fetch context ────────────────────────────────────────────────

const FetchCtx = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    credentials: Credentials,
    region: []u8,
    vpc_id: []u8,
    result: ?Ec2.DescribeVpcsResult = null,
    dns_support: ?bool = null,
    dns_hostnames: ?bool = null,
    network_address_usage_metrics: ?bool = null,
    err: ?anyerror = null,
    done: std.atomic.Value(bool) = .init(false),
    thread: std.Thread = undefined,
};

fn fetchAttribute(client: *Ec2.Client, vpc_id: []const u8, attribute: Ec2.VpcAttribute) ?bool {
    const r = client.describeVpcAttribute(.{ .params = .{ .vpc_id = vpc_id, .attribute = attribute } }) catch return null;
    defer r.deinit();
    return r.value;
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

    const ids = [_][]const u8{ctx.vpc_id};
    const result = client.describeVpcs(.{ .params = .{ .vpc_ids = &ids } }) catch |e| {
        ctx.err = e;
        return;
    };
    ctx.result = result;
    if (result.vpcs.len == 0) {
        ctx.err = error.VpcNotFound;
        return;
    }

    ctx.dns_support = fetchAttribute(&client, ctx.vpc_id, .enable_dns_support);
    ctx.dns_hostnames = fetchAttribute(&client, ctx.vpc_id, .enable_dns_hostnames);
    ctx.network_address_usage_metrics = fetchAttribute(&client, ctx.vpc_id, .enable_network_address_usage_metrics);
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
    vpc_id: []const u8,
    display_name: []const u8,
    fg_color: []const u8,
    bg_color: []const u8,
    parent_breadcrumb: []const u8,
) !VpcView {
    const display_owned = try allocator.dupe(u8, display_name);
    errdefer allocator.free(display_owned);

    const ctx = try allocator.create(FetchCtx);
    errdefer allocator.destroy(ctx);
    const region_owned = try allocator.dupe(u8, region);
    errdefer allocator.free(region_owned);
    const vpc_id_owned = try allocator.dupe(u8, vpc_id);
    errdefer allocator.free(vpc_id_owned);

    ctx.* = .{
        .allocator = allocator,
        .io = io,
        .credentials = credentials,
        .region = region_owned,
        .vpc_id = vpc_id_owned,
    };
    ctx.thread = try std.Thread.spawn(.{}, fetchThread, .{ctx});

    var view = VpcView{
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

pub fn breadcrumb(self: *VpcView) []const u8 {
    return self.breadcrumb_buf[0..self.breadcrumb_len];
}

pub fn deinit(self: *VpcView) void {
    const alloc = self.ctx.allocator;
    self.ctx.thread.join();
    if (self.ctx.result) |r| r.deinit();
    alloc.free(self.ctx.region);
    alloc.free(self.ctx.vpc_id);
    alloc.destroy(self.ctx);
    self.alloc.free(self.display_name);
}

// ─── Event handling ──────────────────────────────────────────────────────────

pub fn handleEvent(self: *VpcView, event: Event, _: ViewContext) !Action {
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

fn boolLabel(v: ?bool, loading: bool) []const u8 {
    if (v) |b| return if (b) "Enabled" else "Disabled";
    return if (loading) "…" else "-";
}

fn orDash(s: []const u8) []const u8 {
    return if (s.len > 0) s else "-";
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

pub fn render(self: *VpcView, writer: *std.Io.Writer, size: Coord) !void {
    if (size.x < 10 or size.y < 2) return;
    const w: usize = @intCast(size.x);
    const h: usize = @intCast(size.y);

    const done = self.ctx.done.load(.acquire);
    const loading = !done;
    const vpc: ?Ec2.Vpc = if (done and self.ctx.err == null) self.ctx.result.?.vpcs[0] else null;

    var text_storage: [4096]u8 = undefined;
    var text: TextBuf = .{ .buf = &text_storage };

    const ellipsis = "…";
    const dash = "-";
    const pending: []const u8 = if (loading) ellipsis else dash;

    var props_buf: [MAX_PROPS]props_mod.Prop = undefined;
    var n: usize = 0;

    props_buf[n] = .{ .label = "Name", .value = if (vpc) |v| orDash(v.name) else orDash(self.display_name) };
    n += 1;
    props_buf[n] = .{ .label = "VPC ID", .value = self.ctx.vpc_id };
    n += 1;
    props_buf[n] = .{ .label = "Region", .value = self.ctx.region };
    n += 1;

    if (self.ctx.err) |e| {
        if (done) {
            props_buf[n] = .{ .label = "Error", .value = @errorName(e) };
            n += 1;
        }
    }

    props_buf[n] = .{ .label = "State", .value = if (vpc) |v| orDash(v.state) else pending };
    n += 1;
    props_buf[n] = .{ .label = "Default VPC", .value = if (vpc) |v| (if (v.is_default) "Yes" else "No") else pending };
    n += 1;
    props_buf[n] = .{ .label = "Account", .value = if (vpc) |v| orDash(v.owner_id) else pending };
    n += 1;
    props_buf[n] = .{ .label = "IPv4 CIDRs", .value = if (vpc) |v| joinCidrs(&text, v.cidr_associations) else pending };
    n += 1;
    props_buf[n] = .{ .label = "IPv6 CIDRs", .value = if (vpc) |v| joinCidrs(&text, v.ipv6_cidr_associations) else pending };
    n += 1;
    props_buf[n] = .{ .label = "DHCP Options", .value = if (vpc) |v| orDash(v.dhcp_options_id) else pending };
    n += 1;
    props_buf[n] = .{ .label = "Tenancy", .value = if (vpc) |v| orDash(v.instance_tenancy) else pending };
    n += 1;
    props_buf[n] = .{ .label = "DNS Resolution", .value = boolLabel(self.ctx.dns_support, loading) };
    n += 1;
    props_buf[n] = .{ .label = "DNS Hostnames", .value = boolLabel(self.ctx.dns_hostnames, loading) };
    n += 1;
    props_buf[n] = .{ .label = "Addr Usage Metrics", .value = boolLabel(self.ctx.network_address_usage_metrics, loading) };
    n += 1;

    if (vpc) |v| {
        if (v.tags.len == 0) {
            props_buf[n] = .{ .label = "Tags", .value = dash };
            n += 1;
        }
        for (v.tags[0..@min(v.tags.len, MAX_TAG_PROPS)], 0..) |t, i| {
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
