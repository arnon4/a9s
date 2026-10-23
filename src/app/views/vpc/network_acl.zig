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
const RulesView = @import("network_acl_rules.zig");

const NetworkAclView = @This();
pub const name: []const u8 = "Network ACL";

/// Breadcrumb of the VPC list; a VPC reached from here is shown as if opened from it.
const vpcs_breadcrumb = "VPC " ++ constants.SEP_ARROW ++ " VPCs";

const MAX_TAG_PROPS = 50;
const MAX_SUBNET_PROPS = 100;
const MAX_PROPS = 10 + MAX_TAG_PROPS + MAX_SUBNET_PROPS;

// ─── Background fetch context ────────────────────────────────────────────────

const FetchCtx = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    credentials: Credentials,
    region: []u8,
    network_acl_id: []u8,
    result: ?Ec2.DescribeNetworkAclsResult = null,
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

    const ids = [_][]const u8{ctx.network_acl_id};
    const result = client.describeNetworkAcls(.{ .params = .{ .network_acl_ids = &ids } }) catch |e| {
        ctx.err = e;
        return;
    };
    ctx.result = result;
    if (result.network_acls.len == 0) {
        ctx.err = error.NetworkAclNotFound;
        return;
    }

    // Best effort: the VPC's Name tag labels the breadcrumb when drilling into it.
    const vpc_ids = [_][]const u8{result.network_acls[0].vpc_id};
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
sel: usize = 0,
/// Row of the VPC entry and visible row count, as of the last render.
sel_row: usize = 0,
view_rows: usize = 0,
/// Scroll to keep the VPC row on screen at the next render.
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
    network_acl_id: []const u8,
    display_name: []const u8,
    fg_color: []const u8,
    bg_color: []const u8,
    parent_breadcrumb: []const u8,
) !NetworkAclView {
    const display_owned = try allocator.dupe(u8, display_name);
    errdefer allocator.free(display_owned);

    const ctx = try allocator.create(FetchCtx);
    errdefer allocator.destroy(ctx);
    const region_owned = try allocator.dupe(u8, region);
    errdefer allocator.free(region_owned);
    const id_owned = try allocator.dupe(u8, network_acl_id);
    errdefer allocator.free(id_owned);

    ctx.* = .{
        .allocator = allocator,
        .io = io,
        .credentials = credentials,
        .region = region_owned,
        .network_acl_id = id_owned,
    };
    ctx.thread = try std.Thread.spawn(.{}, fetchThread, .{ctx});

    var view = NetworkAclView{
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

pub fn breadcrumb(self: *NetworkAclView) []const u8 {
    return self.breadcrumb_buf[0..self.breadcrumb_len];
}

pub fn deinit(self: *NetworkAclView) void {
    const alloc = self.ctx.allocator;
    self.ctx.thread.join();
    if (self.ctx.result) |r| r.deinit();
    if (self.ctx.vpc_name) |n| alloc.free(n);
    alloc.free(self.ctx.region);
    alloc.free(self.ctx.network_acl_id);
    alloc.destroy(self.ctx);
    self.alloc.free(self.display_name);
}

// ─── Selection ───────────────────────────────────────────────────────────────

/// Selectable entries: the VPC (when known), then the "View Rules" button.
const Selection = enum { vpc, view_rules };

/// The ACL, once the fetch has finished without error.
fn loadedAcl(self: *const NetworkAclView) ?Ec2.NetworkAcl {
    if (!self.ctx.done.load(.acquire) or self.ctx.err != null) return null;
    return self.ctx.result.?.network_acls[0];
}

fn vpcId(self: *const NetworkAclView) ?[]const u8 {
    const acl = self.loadedAcl() orelse return null;
    return if (acl.vpc_id.len > 0) acl.vpc_id else null;
}

fn vpcOffset(self: *const NetworkAclView) usize {
    return @intFromBool(self.vpcId() != null);
}

fn selection(self: *const NetworkAclView) Selection {
    const count = self.vpcOffset() + 1;
    const i = @min(self.sel, count - 1);
    return if (self.vpcOffset() == 1 and i == 0) .vpc else .view_rules;
}

/// Moves the selection between the VPC row and the button.
/// Returns false when it cannot move, so the caller scrolls instead.
fn moveSel(self: *NetworkAclView, delta: i32) bool {
    self.pending_g = false;
    if (self.vpcOffset() == 0) return false;
    switch (self.selection()) {
        .vpc => {
            if (delta <= 0) return false;
            if (self.view_rows == 0 or self.sel_row < self.scroll or self.sel_row >= self.scroll + self.view_rows) return false;
            self.sel = 1;
        },
        .view_rules => {
            if (delta >= 0) return false;
            self.sel = 0;
            self.follow_sel = true;
        },
    }
    return true;
}

// ─── Event handling ──────────────────────────────────────────────────────────

pub fn handleEvent(self: *NetworkAclView, event: Event, ctx: ViewContext) !Action {
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
            .enter => switch (self.selection()) {
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
                .view_rules => {
                    const acl = self.loadedAcl() orelse return .none;
                    const v = try RulesView.init(ctx.allocator, acl, self.fg_color, self.bg_color, self.breadcrumb());
                    return .{ .push = .{ .vpc_network_acl_rules = v } };
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

fn yesNo(b: bool) []const u8 {
    return if (b) "Yes" else "No";
}

pub fn render(self: *NetworkAclView, writer: *std.Io.Writer, size: Coord) !void {
    if (size.x < 10 or size.y < 2) return;
    const w: usize = @intCast(size.x);
    const h: usize = @intCast(size.y);

    const done = self.ctx.done.load(.acquire);
    const acl = self.loadedAcl();

    var text_storage: [8192]u8 = undefined;
    var text: TextBuf = .{ .buf = &text_storage };

    const dash = "-";
    const pending: []const u8 = if (done) dash else "…";

    var props_buf: [MAX_PROPS]props_mod.Prop = undefined;
    var n: usize = 0;

    props_buf[n] = .{ .label = "Name", .value = if (acl) |a| orDash(a.name) else orDash(self.display_name) };
    n += 1;
    props_buf[n] = .{ .label = "Network ACL ID", .value = self.ctx.network_acl_id };
    n += 1;
    props_buf[n] = .{ .label = "Region", .value = self.ctx.region };
    n += 1;

    if (self.ctx.err) |e| {
        if (done) {
            props_buf[n] = .{ .label = "Error", .value = @errorName(e) };
            n += 1;
        }
    }

    props_buf[n] = .{
        .label = "VPC ID",
        .value = if (acl) |a| orDash(a.vpc_id) else pending,
        .highlight = if (self.vpcOffset() == 1 and self.selection() == .vpc) self.bg_color else "",
    };
    const vpc_row = n;
    n += 1;
    props_buf[n] = .{ .label = "Account", .value = if (acl) |a| orDash(a.owner_id) else pending };
    n += 1;
    props_buf[n] = .{ .label = "Default", .value = if (acl) |a| yesNo(a.is_default) else pending };
    n += 1;

    if (acl) |a| {
        var inbound: usize = 0;
        for (a.entries) |e| {
            if (!e.egress) inbound += 1;
        }
        props_buf[n] = .{ .label = "Rules", .value = text.print("{d} inbound, {d} outbound", .{ inbound, a.entries.len - inbound }) };
        n += 1;

        if (a.associations.len == 0) {
            props_buf[n] = .{ .label = "Subnets", .value = dash };
            n += 1;
        }
        for (a.associations[0..@min(a.associations.len, MAX_SUBNET_PROPS)], 0..) |assoc, i| {
            props_buf[n] = .{ .label = if (i == 0) "Subnets" else "", .value = orDash(assoc.subnet_id) };
            n += 1;
        }

        if (a.tags.len == 0) {
            props_buf[n] = .{ .label = "Tags", .value = dash };
            n += 1;
        }
        for (a.tags[0..@min(a.tags.len, MAX_TAG_PROPS)], 0..) |tag, i| {
            props_buf[n] = .{
                .label = if (i == 0) "Tags" else "",
                .value = text.print("{s} = {s}", .{ tag.key, tag.value }),
            };
            n += 1;
        }
    } else {
        props_buf[n] = .{ .label = "Subnets", .value = pending };
        n += 1;
    }

    const total = n;
    const props_h = if (h >= 2) h - 1 else h;
    const data_rows = if (props_h >= 1) props_h - 1 else 0;
    self.view_rows = data_rows;
    self.sel_row = vpc_row;
    if (self.follow_sel and data_rows > 0) {
        self.follow_sel = false;
        if (self.sel_row < self.scroll) self.scroll = self.sel_row;
        if (self.sel_row >= self.scroll + data_rows) self.scroll = self.sel_row + 1 - data_rows;
    }
    if (data_rows > 0 and self.scroll + data_rows > total) {
        self.scroll = if (total > data_rows) total - data_rows else 0;
    }

    try props_mod.render(writer, props_buf[0..n], self.scroll, w, props_h, self.fg_color);

    if (h >= 2) {
        try writer.writeAll("\r\n");
        try self.renderActionBar(writer, w);
    }
}

fn renderActionBar(self: *NetworkAclView, writer: *std.Io.Writer, w: usize) !void {
    const btn = " [ View Rules ] ";
    if (self.loadedAcl() == null) {
        try writer.writeAll(terminal.DIM);
        try writer.writeAll(self.fg_color);
    } else if (self.selection() == .view_rules) {
        try writer.writeAll(self.bg_color);
        try writer.writeAll(terminal.FG_BLACK);
    } else {
        try writer.writeAll(self.fg_color);
    }
    try writer.writeAll(btn);
    try writer.writeAll(terminal.RESET);
    if (w > btn.len) {
        for (0..w - btn.len) |_| try writer.writeByte(' ');
    }
}
