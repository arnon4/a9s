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

const InternetGatewayView = @This();
pub const name: []const u8 = "Internet Gateway";

/// Breadcrumb of the VPC list; a VPC reached from here is shown as if opened from it.
const vpcs_breadcrumb = "VPC " ++ constants.SEP_ARROW ++ " VPCs";

const MAX_TAG_PROPS = 50;
const MAX_PROPS = 8 + MAX_TAG_PROPS;

// ─── Background fetch context ────────────────────────────────────────────────

const FetchCtx = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    credentials: Credentials,
    region: []u8,
    internet_gateway_id: []u8,
    result: ?Ec2.DescribeInternetGatewaysResult = null,
    /// Name tag of the owning VPC, when it has one.
    vpc_name: ?[]u8 = null,
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

    const ids = [_][]const u8{ctx.internet_gateway_id};
    const result = client.describeInternetGateways(.{ .params = .{ .internet_gateway_ids = &ids } }) catch |e| {
        ctx.err = e;
        return;
    };
    ctx.result = result;
    if (result.internet_gateways.len == 0) {
        ctx.err = error.InternetGatewayNotFound;
        return;
    }

    // Best effort: the VPC's Name tag labels the breadcrumb when drilling into it.
    const attached = result.internet_gateways[0].attachments;
    if (attached.len == 0) return;
    const vpc_ids = [_][]const u8{attached[0].vpc_id};
    const vpc_result = client.describeVpcs(.{ .params = .{ .vpc_ids = &vpc_ids } }) catch return;
    defer vpc_result.deinit();
    if (vpc_result.vpcs.len > 0 and vpc_result.vpcs[0].name.len > 0) {
        ctx.vpc_name = ctx.allocator.dupe(u8, vpc_result.vpcs[0].name) catch null;
    }
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
    internet_gateway_id: []const u8,
    display_name: []const u8,
    fg_color: []const u8,
    bg_color: []const u8,
    parent_breadcrumb: []const u8,
) !InternetGatewayView {
    const display_owned = try allocator.dupe(u8, display_name);
    errdefer allocator.free(display_owned);

    const ctx = try allocator.create(FetchCtx);
    errdefer allocator.destroy(ctx);
    const region_owned = try allocator.dupe(u8, region);
    errdefer allocator.free(region_owned);
    const id_owned = try allocator.dupe(u8, internet_gateway_id);
    errdefer allocator.free(id_owned);

    ctx.* = .{
        .allocator = allocator,
        .io = io,
        .credentials = credentials,
        .region = region_owned,
        .internet_gateway_id = id_owned,
    };
    ctx.thread = try std.Thread.spawn(.{}, fetchThread, .{ctx});

    var view = InternetGatewayView{
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

pub fn breadcrumb(self: *InternetGatewayView) []const u8 {
    return self.breadcrumb_buf[0..self.breadcrumb_len];
}

pub fn deinit(self: *InternetGatewayView) void {
    const alloc = self.ctx.allocator;
    self.ctx.thread.join();
    if (self.ctx.result) |r| r.deinit();
    if (self.ctx.vpc_name) |n| alloc.free(n);
    alloc.free(self.ctx.region);
    alloc.free(self.ctx.internet_gateway_id);
    alloc.destroy(self.ctx);
    self.alloc.free(self.display_name);
}

// ─── Event handling ──────────────────────────────────────────────────────────

/// VPC this gateway is attached to once the fetch has finished; null while loading, on error or when absent.
fn vpcId(self: *const InternetGatewayView) ?[]const u8 {
    if (!self.ctx.done.load(.acquire) or self.ctx.err != null) return null;
    const attached = self.ctx.result.?.internet_gateways[0].attachments;
    if (attached.len == 0 or attached[0].vpc_id.len == 0) return null;
    return attached[0].vpc_id;
}

pub fn handleEvent(self: *InternetGatewayView, event: Event, ctx: ViewContext) !Action {
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

pub fn render(self: *InternetGatewayView, writer: *std.Io.Writer, size: Coord) !void {
    if (size.x < 10 or size.y < 2) return;
    const w: usize = @intCast(size.x);
    const h: usize = @intCast(size.y);

    const done = self.ctx.done.load(.acquire);
    const table: ?Ec2.InternetGateway = if (done and self.ctx.err == null) self.ctx.result.?.internet_gateways[0] else null;

    var text_storage: [32768]u8 = undefined;
    var text: TextBuf = .{ .buf = &text_storage };

    const dash = "-";
    const pending: []const u8 = if (done) dash else "…";

    var props_buf: [MAX_PROPS]props_mod.Prop = undefined;
    var n: usize = 0;

    props_buf[n] = .{ .label = "Name", .value = if (table) |t| orDash(t.name) else orDash(self.display_name) };
    n += 1;
    props_buf[n] = .{ .label = "Internet Gateway ID", .value = self.ctx.internet_gateway_id };
    n += 1;
    props_buf[n] = .{ .label = "Region", .value = self.ctx.region };
    n += 1;

    if (self.ctx.err) |e| {
        if (done) {
            props_buf[n] = .{ .label = "Error", .value = @errorName(e) };
            n += 1;
        }
    }

    props_buf[n] = .{ .label = "State", .value = if (table) |t| (if (t.attachments.len > 0) "attached" else "detached") else pending };
    n += 1;
    props_buf[n] = .{
        .label = "Attached VPC",
        .value = if (self.vpcId()) |id| id else if (table != null) dash else pending,
        .highlight = if (self.vpcId() != null) self.bg_color else "",
    };
    n += 1;
    props_buf[n] = .{ .label = "Account", .value = if (table) |t| orDash(t.owner_id) else pending };
    n += 1;

    if (table) |t| {
        if (t.tags.len == 0) {
            props_buf[n] = .{ .label = "Tags", .value = dash };
            n += 1;
        }
        for (t.tags[0..@min(t.tags.len, MAX_TAG_PROPS)], 0..) |tag, i| {
            props_buf[n] = .{
                .label = if (i == 0) "Tags" else "",
                .value = text.print("{s} = {s}", .{ tag.key, tag.value }),
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
