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
const RulesView = @import("security_group_rules.zig");

const SecurityGroupView = @This();
pub const name: []const u8 = "Security Group";

/// Breadcrumb of the VPC list; a VPC reached from here is shown as if opened from it.
const vpcs_breadcrumb = "VPC " ++ constants.SEP_ARROW ++ " VPCs";

const MAX_TAG_PROPS = 50;
const MAX_REFERENCE_PROPS = 50;
const MAX_PROPS = 12 + MAX_TAG_PROPS + MAX_REFERENCE_PROPS;

// ─── Background fetch context ────────────────────────────────────────────────

const FetchCtx = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    credentials: Credentials,
    region: []u8,
    group_id: []u8,
    result: ?Ec2.DescribeSecurityGroupsResult = null,
    /// Rules in peer VPCs that reference this group; best effort.
    references: ?Ec2.DescribeSecurityGroupReferencesResult = null,
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

    const ids = [_][]const u8{ctx.group_id};
    const result = client.describeSecurityGroups(.{ .params = .{ .group_ids = &ids } }) catch |e| {
        ctx.err = e;
        return;
    };
    ctx.result = result;
    if (result.security_groups.len == 0) {
        ctx.err = error.SecurityGroupNotFound;
        return;
    }

    ctx.references = client.describeSecurityGroupReferences(.{ .params = .{ .group_ids = &ids } }) catch null;

    // Best effort: the VPC's Name tag labels the breadcrumb when drilling into it.
    const vpc_ids = [_][]const u8{result.security_groups[0].vpc_id};
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
    group_id: []const u8,
    display_name: []const u8,
    fg_color: []const u8,
    bg_color: []const u8,
    parent_breadcrumb: []const u8,
) !SecurityGroupView {
    const display_owned = try allocator.dupe(u8, display_name);
    errdefer allocator.free(display_owned);

    const ctx = try allocator.create(FetchCtx);
    errdefer allocator.destroy(ctx);
    const region_owned = try allocator.dupe(u8, region);
    errdefer allocator.free(region_owned);
    const id_owned = try allocator.dupe(u8, group_id);
    errdefer allocator.free(id_owned);

    ctx.* = .{
        .allocator = allocator,
        .io = io,
        .credentials = credentials,
        .region = region_owned,
        .group_id = id_owned,
    };
    ctx.thread = try std.Thread.spawn(.{}, fetchThread, .{ctx});

    var view = SecurityGroupView{
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

pub fn breadcrumb(self: *SecurityGroupView) []const u8 {
    return self.breadcrumb_buf[0..self.breadcrumb_len];
}

pub fn deinit(self: *SecurityGroupView) void {
    const alloc = self.ctx.allocator;
    self.ctx.thread.join();
    if (self.ctx.result) |r| r.deinit();
    if (self.ctx.references) |r| r.deinit();
    if (self.ctx.vpc_name) |n| alloc.free(n);
    alloc.free(self.ctx.region);
    alloc.free(self.ctx.group_id);
    alloc.destroy(self.ctx);
    self.alloc.free(self.display_name);
}

// ─── Selection ───────────────────────────────────────────────────────────────

/// Selectable entries: the VPC (when known), then the two rule buttons.
const Selection = enum { vpc, inbound, outbound };

/// The group, once the fetch has finished without error.
fn loadedGroup(self: *const SecurityGroupView) ?Ec2.SecurityGroup {
    if (!self.ctx.done.load(.acquire) or self.ctx.err != null) return null;
    return self.ctx.result.?.security_groups[0];
}

fn vpcId(self: *const SecurityGroupView) ?[]const u8 {
    const g = self.loadedGroup() orelse return null;
    return if (g.vpc_id.len > 0) g.vpc_id else null;
}

fn vpcOffset(self: *const SecurityGroupView) usize {
    return @intFromBool(self.vpcId() != null);
}

fn selection(self: *const SecurityGroupView) Selection {
    const off = self.vpcOffset();
    const i = @min(self.sel, off + 1);
    if (off == 1 and i == 0) return .vpc;
    return if (i - off == 0) .inbound else .outbound;
}

/// Moves between the VPC row and the buttons.
/// Returns false when it cannot move, so the caller scrolls instead.
fn moveSel(self: *SecurityGroupView, delta: i32) bool {
    self.pending_g = false;
    if (self.vpcOffset() == 0) return false;
    switch (self.selection()) {
        .vpc => {
            if (delta <= 0) return false;
            if (self.view_rows == 0 or self.sel_row < self.scroll or self.sel_row >= self.scroll + self.view_rows) return false;
            self.sel = 1;
        },
        .inbound, .outbound => {
            if (delta >= 0) return false;
            self.sel = 0;
            self.follow_sel = true;
        },
    }
    return true;
}

/// Left/right switch between the two rule buttons.
fn moveButton(self: *SecurityGroupView, right: bool) void {
    self.pending_g = false;
    const off = self.vpcOffset();
    switch (self.selection()) {
        .inbound => if (right) {
            self.sel = off + 1;
        },
        .outbound => if (!right) {
            self.sel = off;
        },
        .vpc => {},
    }
}

// ─── Event handling ──────────────────────────────────────────────────────────

fn openRules(self: *SecurityGroupView, ctx: ViewContext, inbound: bool) !Action {
    const g = self.loadedGroup() orelse return .none;
    const v = try RulesView.init(ctx.allocator, g, inbound, self.fg_color, self.bg_color, self.breadcrumb());
    return .{ .push = .{ .vpc_security_group_rules = v } };
}

pub fn handleEvent(self: *SecurityGroupView, event: Event, ctx: ViewContext) !Action {
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
                'h' => self.moveButton(false),
                'l' => self.moveButton(true),
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
            .left => self.moveButton(false),
            .right => self.moveButton(true),
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
                .inbound => return self.openRules(ctx, true),
                .outbound => return self.openRules(ctx, false),
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

/// Number of rows the rule list expands to: one per source or destination.
pub fn ruleCount(rules: []const Ec2.SecurityGroupRule) usize {
    var n: usize = 0;
    for (rules) |r| {
        const sources = r.ipv4_ranges.len + r.ipv6_ranges.len + r.prefix_lists.len + r.groups.len;
        n += @max(sources, 1);
    }
    return n;
}

pub fn render(self: *SecurityGroupView, writer: *std.Io.Writer, size: Coord) !void {
    if (size.x < 10 or size.y < 2) return;
    const w: usize = @intCast(size.x);
    const h: usize = @intCast(size.y);

    const done = self.ctx.done.load(.acquire);
    const group = self.loadedGroup();

    var text_storage: [8192]u8 = undefined;
    var text: TextBuf = .{ .buf = &text_storage };

    const dash = "-";
    const pending: []const u8 = if (done) dash else "…";

    var props_buf: [MAX_PROPS]props_mod.Prop = undefined;
    var n: usize = 0;

    props_buf[n] = .{ .label = "Name", .value = if (group) |g| orDash(g.name) else orDash(self.display_name) };
    n += 1;
    props_buf[n] = .{ .label = "Group ID", .value = self.ctx.group_id };
    n += 1;
    props_buf[n] = .{ .label = "Group Name", .value = if (group) |g| orDash(g.group_name) else pending };
    n += 1;
    props_buf[n] = .{ .label = "Description", .value = if (group) |g| orDash(g.description) else pending };
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
        .value = if (group) |g| orDash(g.vpc_id) else pending,
        .highlight = if (self.vpcOffset() == 1 and self.selection() == .vpc) self.bg_color else "",
    };
    const vpc_row = n;
    n += 1;
    props_buf[n] = .{ .label = "Account", .value = if (group) |g| orDash(g.owner_id) else pending };
    n += 1;
    props_buf[n] = .{ .label = "ARN", .value = if (group) |g| orDash(g.arn) else pending };
    n += 1;

    if (group) |g| {
        props_buf[n] = .{ .label = "Inbound Rules", .value = text.print("{d}", .{ruleCount(g.ingress)}) };
        n += 1;
        props_buf[n] = .{ .label = "Outbound Rules", .value = text.print("{d}", .{ruleCount(g.egress)}) };
        n += 1;

        if (self.ctx.references) |refs| {
            if (refs.references.len == 0) {
                props_buf[n] = .{ .label = "Referenced By", .value = dash };
                n += 1;
            }
            for (refs.references[0..@min(refs.references.len, MAX_REFERENCE_PROPS)], 0..) |r, i| {
                const via = if (r.vpc_peering_connection_id.len > 0) r.vpc_peering_connection_id else r.transit_gateway_id;
                props_buf[n] = .{
                    .label = if (i == 0) "Referenced By" else "",
                    .value = if (via.len > 0) text.print("{s} via {s}", .{ r.referencing_vpc_id, via }) else orDash(r.referencing_vpc_id),
                };
                n += 1;
            }
        } else {
            props_buf[n] = .{ .label = "Referenced By", .value = dash };
            n += 1;
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

fn renderActionBar(self: *SecurityGroupView, writer: *std.Io.Writer, w: usize) !void {
    const enabled = self.loadedGroup() != null;
    const sel = self.selection();
    const buttons = [_]struct { label: []const u8, which: Selection }{
        .{ .label = " [ Inbound Rules ] ", .which = .inbound },
        .{ .label = " [ Outbound Rules ] ", .which = .outbound },
    };
    var used: usize = 0;
    for (buttons) |b| {
        if (!enabled) {
            try writer.writeAll(terminal.DIM);
            try writer.writeAll(self.fg_color);
        } else if (sel == b.which) {
            try writer.writeAll(self.bg_color);
            try writer.writeAll(terminal.FG_BLACK);
        } else {
            try writer.writeAll(self.fg_color);
        }
        try writer.writeAll(b.label);
        try writer.writeAll(terminal.RESET);
        used += b.label.len;
    }
    if (w > used) {
        for (0..w - used) |_| try writer.writeByte(' ');
    }
}

// ============================================================================
// Tests
// ============================================================================

test "ruleCount expands one row per source and counts empty rules once" {
    var ranges = [_]Ec2.SecurityGroupRange{
        .{ .cidr = @constCast("10.0.0.0/8"), .description = @constCast("") },
        .{ .cidr = @constCast("192.168.0.0/16"), .description = @constCast("") },
    };
    const rules = [_]Ec2.SecurityGroupRule{
        .{ .protocol = @constCast("tcp"), .from_port = 22, .to_port = 22, .groups = &.{}, .ipv4_ranges = &ranges, .ipv6_ranges = &.{}, .prefix_lists = &.{} },
        .{ .protocol = @constCast("-1"), .from_port = null, .to_port = null, .groups = &.{}, .ipv4_ranges = &.{}, .ipv6_ranges = &.{}, .prefix_lists = &.{} },
    };
    try std.testing.expectEqual(@as(usize, 3), ruleCount(&rules));
}
