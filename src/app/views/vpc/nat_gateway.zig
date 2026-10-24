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
const VpcView = @import("vpc.zig");
const SubnetView = @import("subnet.zig");

const NatGatewayView = @This();
pub const name: []const u8 = "NAT Gateway";

/// Breadcrumbs of the VPC and subnet lists; an entry reached from here is shown as if opened from them.
const vpcs_breadcrumb = "VPC " ++ constants.SEP_ARROW ++ " VPCs";
const subnets_breadcrumb = "VPC " ++ constants.SEP_ARROW ++ " Subnets";

const MAX_TAG_PROPS = 50;
const MAX_ADDRESS_PROPS = 20;
const MAX_PROPS = 16 + MAX_TAG_PROPS + MAX_ADDRESS_PROPS;

// ─── Background fetch context ────────────────────────────────────────────────

const FetchCtx = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    credentials: Credentials,
    region: []u8,
    nat_gateway_id: []u8,
    result: ?Ec2.DescribeNatGatewaysResult = null,
    /// Name tags of the owning VPC and subnet, when they have one; they label the breadcrumb.
    vpc_name: ?[]u8 = null,
    subnet_name: ?[]u8 = null,
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

    const ids = [_][]const u8{ctx.nat_gateway_id};
    const result = client.describeNatGateways(.{ .params = .{ .nat_gateway_ids = &ids } }) catch |e| {
        ctx.err = e;
        return;
    };
    ctx.result = result;
    if (result.nat_gateways.len == 0) {
        ctx.err = error.NatGatewayNotFound;
        return;
    }
    const nat = result.nat_gateways[0];

    // Best effort: Name tags only improve the breadcrumb.
    if (nat.vpc_id.len > 0) {
        const vpc_ids = [_][]const u8{nat.vpc_id};
        if (client.describeVpcs(.{ .params = .{ .vpc_ids = &vpc_ids } })) |r| {
            defer r.deinit();
            if (r.vpcs.len > 0 and r.vpcs[0].name.len > 0) ctx.vpc_name = ctx.allocator.dupe(u8, r.vpcs[0].name) catch null;
        } else |_| {}
    }
    if (nat.subnet_id.len > 0) {
        const subnet_ids = [_][]const u8{nat.subnet_id};
        if (client.describeSubnets(.{ .params = .{ .subnet_ids = &subnet_ids } })) |r| {
            defer r.deinit();
            if (r.subnets.len > 0 and r.subnets[0].name.len > 0) ctx.subnet_name = ctx.allocator.dupe(u8, r.subnets[0].name) catch null;
        } else |_| {}
    }
}

// ─── View fields ─────────────────────────────────────────────────────────────

fg_color: []const u8,
bg_color: []const u8,
scroll: usize = 0,
pending_g: bool = false,
sel: usize = 0,
/// Row of the selected entry and visible row count, as of the last render.
sel_row: usize = 0,
view_rows: usize = 0,
/// Scroll to keep the selected entry on screen at the next render.
follow_sel: bool = false,
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
    nat_gateway_id: []const u8,
    display_name: []const u8,
    fg_color: []const u8,
    bg_color: []const u8,
    parent_breadcrumb: []const u8,
) !NatGatewayView {
    const display_owned = try allocator.dupe(u8, display_name);
    errdefer allocator.free(display_owned);

    const ctx = try allocator.create(FetchCtx);
    errdefer allocator.destroy(ctx);
    const region_owned = try allocator.dupe(u8, region);
    errdefer allocator.free(region_owned);
    const id_owned = try allocator.dupe(u8, nat_gateway_id);
    errdefer allocator.free(id_owned);

    ctx.* = .{
        .allocator = allocator,
        .io = io,
        .credentials = credentials,
        .region = region_owned,
        .nat_gateway_id = id_owned,
    };
    ctx.thread = try std.Thread.spawn(.{}, fetchThread, .{ctx});

    var view = NatGatewayView{
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

pub fn breadcrumb(self: *NatGatewayView) []const u8 {
    return self.breadcrumb_buf[0..self.breadcrumb_len];
}

pub fn deinit(self: *NatGatewayView) void {
    const alloc = self.ctx.allocator;
    self.ctx.thread.join();
    if (self.ctx.result) |r| r.deinit();
    if (self.ctx.vpc_name) |n| alloc.free(n);
    if (self.ctx.subnet_name) |n| alloc.free(n);
    alloc.free(self.ctx.region);
    alloc.free(self.ctx.nat_gateway_id);
    alloc.destroy(self.ctx);
    self.alloc.free(self.display_name);
}

// ─── Selection ───────────────────────────────────────────────────────────────

/// Selectable entries: the VPC and the subnet, each only when known.
const Selection = enum { vpc, subnet };

/// The gateway, once the fetch has finished without error.
fn loaded(self: *const NatGatewayView) ?Ec2.NatGateway {
    if (!self.ctx.done.load(.acquire) or self.ctx.err != null) return null;
    return self.ctx.result.?.nat_gateways[0];
}

fn vpcId(self: *const NatGatewayView) ?[]const u8 {
    const n = self.loaded() orelse return null;
    return if (n.vpc_id.len > 0) n.vpc_id else null;
}

fn subnetId(self: *const NatGatewayView) ?[]const u8 {
    const n = self.loaded() orelse return null;
    return if (n.subnet_id.len > 0) n.subnet_id else null;
}

fn selectableCount(self: *const NatGatewayView) usize {
    return @as(usize, @intFromBool(self.vpcId() != null)) + @intFromBool(self.subnetId() != null);
}

fn selection(self: *const NatGatewayView) ?Selection {
    const count = self.selectableCount();
    if (count == 0) return null;
    const i = @min(self.sel, count - 1);
    if (self.vpcId() != null and i == 0) return .vpc;
    return .subnet;
}

/// Moves the selection when the selected row is on screen.
/// Returns false when it cannot move, so the caller scrolls instead.
fn moveSel(self: *NatGatewayView, delta: i32) bool {
    self.pending_g = false;
    const count = self.selectableCount();
    if (count == 0 or self.view_rows == 0) return false;
    if (self.sel_row < self.scroll or self.sel_row >= self.scroll + self.view_rows) return false;
    if (delta < 0) {
        if (self.sel == 0) return false;
        self.sel -= 1;
    } else {
        if (self.sel + 1 >= count) return false;
        self.sel += 1;
    }
    self.follow_sel = true;
    return true;
}

// ─── Event handling ──────────────────────────────────────────────────────────

pub fn handleEvent(self: *NatGatewayView, event: Event, ctx: ViewContext) !Action {
    switch (event) {
        .key => |k| switch (k) {
            .ctrl_c => return .quit,
            .char => |c| switch (c) {
                'q' => return .{ .push = .{ .confirm = ConfirmView.init(self.fg_color, self.bg_color) } },
                'j' => if (!self.moveSel(1)) {
                    self.scroll += 1;
                },
                'k' => if (!self.moveSel(-1)) {
                    if (self.scroll > 0) self.scroll -= 1;
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
            .down => if (!self.moveSel(1)) {
                self.scroll += 1;
            },
            .up => if (!self.moveSel(-1)) {
                if (self.scroll > 0) self.scroll -= 1;
            },
            .enter => switch (self.selection() orelse return .none) {
                .vpc => {
                    const id = self.vpcId() orelse return .none;
                    const v = try VpcView.init(
                        ctx.allocator,
                        ctx.io,
                        self.ctx.credentials,
                        self.ctx.region,
                        id,
                        self.ctx.vpc_name orelse id,
                        self.fg_color,
                        self.bg_color,
                        vpcs_breadcrumb,
                    );
                    return .{ .push = .{ .vpc_vpc = v } };
                },
                .subnet => {
                    const id = self.subnetId() orelse return .none;
                    const v = try SubnetView.init(
                        ctx.allocator,
                        ctx.io,
                        self.ctx.credentials,
                        self.ctx.region,
                        id,
                        self.ctx.subnet_name orelse id,
                        self.fg_color,
                        self.bg_color,
                        subnets_breadcrumb,
                    );
                    return .{ .push = .{ .vpc_subnet = v } };
                },
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

fn addressLabel(text: *TextBuf, a: Ec2.NatGatewayAddress) []const u8 {
    const public = if (a.public_ip.len > 0) a.public_ip else "no public IP";
    const private = if (a.private_ip.len > 0) a.private_ip else "no private IP";
    return text.print("{s} / {s}  ({s}{s}{s}{s}{s})", .{
        public,
        private,
        if (a.is_primary) "primary" else "secondary",
        if (a.network_interface_id.len > 0) ", " else "",
        a.network_interface_id,
        if (a.status.len > 0) ", " else "",
        a.status,
    });
}

pub fn render(self: *NatGatewayView, writer: *std.Io.Writer, size: Coord) !void {
    if (size.x < 10 or size.y < 2) return;
    const w: usize = @intCast(size.x);
    const h: usize = @intCast(size.y);

    const done = self.ctx.done.load(.acquire);
    const nat = self.loaded();

    var text_storage: [8192]u8 = undefined;
    var text: TextBuf = .{ .buf = &text_storage };

    const dash = "-";
    const pending: []const u8 = if (done) dash else "…";

    var props_buf: [MAX_PROPS]props_mod.Prop = undefined;
    var n: usize = 0;

    props_buf[n] = .{ .label = "Name", .value = if (nat) |g| orDash(g.name) else orDash(self.display_name) };
    n += 1;
    props_buf[n] = .{ .label = "NAT Gateway ID", .value = self.ctx.nat_gateway_id };
    n += 1;
    props_buf[n] = .{ .label = "Region", .value = self.ctx.region };
    n += 1;

    if (self.ctx.err) |e| {
        if (done) {
            props_buf[n] = .{ .label = "Error", .value = @errorName(e) };
            n += 1;
        }
    }

    props_buf[n] = .{ .label = "State", .value = if (nat) |g| orDash(g.state) else pending };
    n += 1;
    props_buf[n] = .{ .label = "Type", .value = if (nat) |g| (if (g.connectivity_type.len > 0) g.connectivity_type else "public") else pending };
    n += 1;

    const selected = self.selection();
    const vpc_row = n;
    props_buf[n] = .{
        .label = "VPC ID",
        .value = if (nat) |g| orDash(g.vpc_id) else pending,
        .highlight = if (selected != null and selected.? == .vpc) self.bg_color else "",
    };
    n += 1;
    const subnet_row = n;
    props_buf[n] = .{
        .label = "Subnet ID",
        .value = if (nat) |g| orDash(g.subnet_id) else pending,
        .highlight = if (selected != null and selected.? == .subnet) self.bg_color else "",
    };
    n += 1;

    props_buf[n] = .{ .label = "Created", .value = if (nat) |g| orDash(g.create_time) else pending };
    n += 1;

    if (nat) |g| {
        if (g.delete_time.len > 0) {
            props_buf[n] = .{ .label = "Deleted", .value = g.delete_time };
            n += 1;
        }
        if (g.failure_code.len > 0 or g.failure_message.len > 0) {
            props_buf[n] = .{ .label = "Failure", .value = text.print("{s}{s}{s}", .{ g.failure_code, if (g.failure_code.len > 0 and g.failure_message.len > 0) ": " else "", g.failure_message }) };
            n += 1;
        }

        if (g.addresses.len == 0) {
            props_buf[n] = .{ .label = "Addresses", .value = dash };
            n += 1;
        }
        for (g.addresses[0..@min(g.addresses.len, MAX_ADDRESS_PROPS)], 0..) |a, i| {
            props_buf[n] = .{ .label = if (i == 0) "Addresses" else "", .value = addressLabel(&text, a) };
            n += 1;
            if (a.failure_message.len > 0) {
                props_buf[n] = .{ .label = "", .value = text.print("failed: {s}", .{a.failure_message}) };
                n += 1;
            }
        }

        if (g.tags.len == 0) {
            props_buf[n] = .{ .label = "Tags", .value = dash };
            n += 1;
        }
        for (g.tags[0..@min(g.tags.len, MAX_TAG_PROPS)], 0..) |tag, i| {
            props_buf[n] = .{
                .label = if (i == 0) "Tags" else "",
                .value = text.print("{s} = {s}", .{ tag.key, tag.value }),
            };
            n += 1;
        }
    } else {
        props_buf[n] = .{ .label = "Addresses", .value = pending };
        n += 1;
    }

    const total = n;
    const data_rows = if (h >= 1) h - 1 else 0;
    self.view_rows = data_rows;
    self.sel_row = if (selected != null and selected.? == .subnet) subnet_row else vpc_row;
    if (self.selectableCount() > 0 and self.sel >= self.selectableCount()) self.sel = self.selectableCount() - 1;
    if (self.follow_sel and data_rows > 0) {
        self.follow_sel = false;
        if (self.sel_row < self.scroll) self.scroll = self.sel_row;
        if (self.sel_row >= self.scroll + data_rows) self.scroll = self.sel_row + 1 - data_rows;
    }
    if (data_rows > 0 and self.scroll + data_rows > total) {
        self.scroll = if (total > data_rows) total - data_rows else 0;
    }

    try props_mod.render(writer, props_buf[0..n], self.scroll, w, h, self.fg_color);
}
