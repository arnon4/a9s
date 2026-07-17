const std = @import("std");
const colors_mod = @import("../../../ui/colors.zig");
const fetcher = @import("../../../sdk/credentials/fetcher.zig");
const Credentials = fetcher.Credentials;
const terminal = @import("../../../terminal/terminal.zig");
const input = @import("../../../terminal/input.zig");
const Event = @import("../../../event.zig").Event;
const view_mod = @import("../../../ui/view.zig");
const Action = view_mod.Action;
const ViewContext = view_mod.ViewContext;
const Coord = terminal.Coord;
const Iam = @import("../../../sdk/clients/iam/client.zig");
const props_mod = @import("../../../ui/props.zig");
const constants = @import("../../../ui/constants.zig");
const ConfirmView = @import("../../../ui/confirm.zig");

const IamRolePoliciesView = @import("role_policies.zig");
const IamRoleTrustPolicyView = @import("trust_policy.zig");

const IamRoleView = @This();
pub const name: []const u8 = "IAM Role";

// ─── Background GetRole context ──────────────────────────────────────────────

const GetRoleCtx = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    credentials: Credentials,
    role_name: []u8,
    result: ?Iam.GetRoleResult = null,
    trusted_entities: ?[]u8 = null,
    /// Attached managed policies (name + arn, parallel arrays). Owned.
    policy_names: [][]u8 = &.{},
    policy_arns: [][]u8 = &.{},
    err: ?anyerror = null,
    done: std.atomic.Value(bool) = .init(false),
    thread: std.Thread = undefined,
};

fn fetchAttachedPolicies(ctx: *GetRoleCtx, client: *Iam.Client) void {
    var names: std.ArrayList([]u8) = .empty;
    errdefer {
        for (names.items) |n| ctx.allocator.free(n);
        names.deinit(ctx.allocator);
    }
    var arns: std.ArrayList([]u8) = .empty;
    errdefer {
        for (arns.items) |a| ctx.allocator.free(a);
        arns.deinit(ctx.allocator);
    }

    var marker: ?[]u8 = null;
    defer if (marker) |m| ctx.allocator.free(m);

    while (true) {
        const result = client.listAttachedRolePolicies(.{
            .role_name = ctx.role_name,
            .params = .{ .marker = marker },
        }) catch return;
        defer result.deinit();

        for (result.policies) |p| {
            const pname = ctx.allocator.dupe(u8, p.policy_name) catch continue;
            const arn = ctx.allocator.dupe(u8, p.policy_arn) catch {
                ctx.allocator.free(pname);
                continue;
            };
            names.append(ctx.allocator, pname) catch {
                ctx.allocator.free(pname);
                ctx.allocator.free(arn);
                continue;
            };
            arns.append(ctx.allocator, arn) catch {
                ctx.allocator.free(arn);
                continue;
            };
        }

        if (marker) |m| ctx.allocator.free(m);
        marker = if (result.next_marker) |m| ctx.allocator.dupe(u8, m) catch null else null;
        if (result.next_marker == null) break;
    }

    ctx.policy_names = names.toOwnedSlice(ctx.allocator) catch &.{};
    ctx.policy_arns = arns.toOwnedSlice(ctx.allocator) catch &.{};
}

fn getThread(ctx: *GetRoleCtx) void {
    defer {
        ctx.done.store(true, .release);
        input.notify();
    }

    var client = Iam.Client.init(ctx.allocator, .{
        .io = ctx.io,
        .credentials = ctx.credentials,
    }) catch |e| {
        ctx.err = e;
        return;
    };
    defer client.deinit();

    const result = client.getRole(.{ .role_name = ctx.role_name }) catch |e| {
        ctx.err = e;
        return;
    };
    ctx.trusted_entities = Iam.extractTrustedEntities(ctx.allocator, result.assume_role_policy_document) catch null;
    ctx.result = result;

    fetchAttachedPolicies(ctx, &client);
}

// ─── View fields ─────────────────────────────────────────────────────────────

fg_color: []const u8,
bg_color: []const u8,
scroll: usize = 0,
pending_g: bool = false,
action_idx: usize = 0,
arn: []u8,
create_date: []u8,
ctx: *GetRoleCtx,
alloc: std.mem.Allocator,
breadcrumb_buf: [320]u8 = undefined,
breadcrumb_len: usize = 0,

// ─── Init / deinit ───────────────────────────────────────────────────────────

pub fn init(
    allocator: std.mem.Allocator,
    io: std.Io,
    credentials: Credentials,
    role_name: []const u8,
    arn: []const u8,
    create_date: []const u8,
    color_support: terminal.ColorSupport,
    parent_breadcrumb: []const u8,
) !IamRoleView {
    const colors = colors_mod.iam(color_support);

    const arn_owned = try allocator.dupe(u8, arn);
    errdefer allocator.free(arn_owned);
    const create_date_owned = try allocator.dupe(u8, create_date);
    errdefer allocator.free(create_date_owned);

    const ctx = try allocator.create(GetRoleCtx);
    errdefer allocator.destroy(ctx);
    const role_name_owned = try allocator.dupe(u8, role_name);
    errdefer allocator.free(role_name_owned);

    ctx.* = .{
        .allocator = allocator,
        .io = io,
        .credentials = credentials,
        .role_name = role_name_owned,
    };
    ctx.thread = try std.Thread.spawn(.{}, getThread, .{ctx});

    var view = IamRoleView{
        .fg_color = colors.fg,
        .bg_color = colors.bg,
        .arn = arn_owned,
        .create_date = create_date_owned,
        .ctx = ctx,
        .alloc = allocator,
    };
    const bc = std.fmt.bufPrint(&view.breadcrumb_buf, "{s} {s} {s}", .{ parent_breadcrumb, constants.SEP_ARROW, role_name }) catch view.breadcrumb_buf[0..0];
    view.breadcrumb_len = bc.len;
    return view;
}

pub fn breadcrumb(self: *IamRoleView) []const u8 {
    return self.breadcrumb_buf[0..self.breadcrumb_len];
}

pub fn deinit(self: *IamRoleView) void {
    const alloc = self.ctx.allocator;
    if (!self.ctx.done.load(.acquire)) self.ctx.thread.join();
    if (self.ctx.trusted_entities) |t| alloc.free(t);
    if (self.ctx.result) |r| r.deinit();
    for (self.ctx.policy_names) |n| alloc.free(n);
    alloc.free(self.ctx.policy_names);
    for (self.ctx.policy_arns) |a| alloc.free(a);
    alloc.free(self.ctx.policy_arns);
    alloc.free(self.ctx.role_name);
    alloc.destroy(self.ctx);
    self.alloc.free(self.arn);
    self.alloc.free(self.create_date);
}

// ─── Event handling ──────────────────────────────────────────────────────────

pub fn handleEvent(self: *IamRoleView, event: Event, vctx: ViewContext) !Action {
    const total_props = 8;
    switch (event) {
        .key => |k| switch (k) {
            .ctrl_c => return .quit,
            .char => |c| switch (c) {
                'q' => return .{ .push = .{ .confirm = ConfirmView.init(self.fg_color, self.bg_color) } },
                'j' => self.scroll += 1,
                'k' => if (self.scroll > 0) { self.scroll -= 1; },
                'h' => if (self.action_idx > 0) { self.action_idx -= 1; },
                'l' => if (self.action_idx < 1) { self.action_idx += 1; },
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
                    self.scroll = total_props;
                },
                else => self.pending_g = false,
            },
            .down => self.scroll += 1,
            .up => if (self.scroll > 0) { self.scroll -= 1; },
            .left => if (self.action_idx > 0) { self.action_idx -= 1; },
            .right => if (self.action_idx < 1) { self.action_idx += 1; },
            .enter => {
                if (!self.ctx.done.load(.acquire)) return .none;
                if (self.action_idx == 0) {
                    if (self.ctx.policy_names.len == 0) return .none;
                    const view = try IamRolePoliciesView.init(
                        vctx.allocator,
                        vctx.io,
                        self.ctx.credentials,
                        self.ctx.policy_names,
                        self.ctx.policy_arns,
                        self.fg_color,
                        self.bg_color,
                        self.breadcrumb(),
                    );
                    return .{ .push = .{ .iam_role_policies = view } };
                } else {
                    const result = self.ctx.result orelse return .none;
                    const view = try IamRoleTrustPolicyView.init(
                        vctx.allocator,
                        result.assume_role_policy_document,
                        self.fg_color,
                        self.bg_color,
                        self.breadcrumb(),
                    );
                    return .{ .push = .{ .iam_role_trust_policy = view } };
                }
            },
            .escape => return .pop,
            else => {},
        },
        else => {},
    }
    return .none;
}

// ─── Rendering ───────────────────────────────────────────────────────────────

fn formatDuration(buf: []u8, seconds: u32) []const u8 {
    const h = seconds / 3600;
    const m = (seconds % 3600) / 60;
    if (h > 0 and m == 0) {
        return std.fmt.bufPrint(buf, "{d}h", .{h}) catch buf[0..0];
    } else if (h > 0) {
        return std.fmt.bufPrint(buf, "{d}h {d}m", .{ h, m }) catch buf[0..0];
    } else if (m > 0) {
        return std.fmt.bufPrint(buf, "{d}m", .{m}) catch buf[0..0];
    }
    return std.fmt.bufPrint(buf, "{d}s", .{seconds}) catch buf[0..0];
}

pub fn render(self: *IamRoleView, writer: *std.Io.Writer, size: Coord) !void {
    if (size.x < 10 or size.y < 2) return;
    const w: usize = @intCast(size.x);
    const h: usize = @intCast(size.y);

    const done = self.ctx.done.load(.acquire);
    const loading = !done;
    const res: ?Iam.GetRoleResult = if (done) self.ctx.result else null;

    const ellipsis = "…";
    const dash = "-";

    // Last activity
    var act_buf: [80]u8 = undefined;
    const act_str: []const u8 = if (res) |r|
        if (r.last_used_date) |d|
            if (r.last_used_region) |rgn|
                std.fmt.bufPrint(&act_buf, "{s} ({s})", .{ d, rgn }) catch d
            else
                d
        else
            "Never"
    else if (loading) ellipsis else dash;

    // Max session duration
    var dur_buf: [32]u8 = undefined;
    const dur_str: []const u8 = if (res) |r|
        if (r.max_session_duration > 0) formatDuration(&dur_buf, r.max_session_duration) else dash
    else if (loading) ellipsis else dash;

    // Trusted entities (pre-computed by thread)
    const trusted_str: []const u8 =
        if (self.ctx.trusted_entities) |t| t else if (loading) ellipsis else dash;

    // Description
    const desc_str: []const u8 = if (res) |r|
        if (r.description.len > 0) r.description else dash
    else if (loading) ellipsis else dash;

    // Attached managed policies (fetched after GetRole, in the same background thread)
    var policies_buf: [64]u8 = undefined;
    const policies_str: []const u8 = if (loading)
        ellipsis
    else if (self.ctx.policy_names.len == 0)
        dash
    else
        std.fmt.bufPrint(&policies_buf, "{d} attached (Enter to view)", .{self.ctx.policy_names.len}) catch dash;

    var props_buf: [8]props_mod.Prop = undefined;
    var n: usize = 0;
    props_buf[n] = .{ .label = "Role Name", .value = self.ctx.role_name };
    n += 1;
    props_buf[n] = .{ .label = "ARN", .value = self.arn };
    n += 1;
    props_buf[n] = .{ .label = "Created", .value = self.create_date };
    n += 1;
    props_buf[n] = .{ .label = "Last Activity", .value = act_str };
    n += 1;
    props_buf[n] = .{ .label = "Max Session Duration", .value = dur_str };
    n += 1;
    props_buf[n] = .{ .label = "Trusted Entities", .value = trusted_str };
    n += 1;
    props_buf[n] = .{ .label = "Description", .value = desc_str };
    n += 1;
    props_buf[n] = .{ .label = "Permission Policies", .value = policies_str };
    n += 1;

    const total = n;
    const data_rows = if (h >= 1) h - 1 else 0;
    if (data_rows > 0 and self.scroll + data_rows > total) {
        self.scroll = if (total > data_rows) total - data_rows else 0;
    }

    const props_h = if (h >= 2) h - 1 else h;
    try props_mod.render(writer, props_buf[0..n], self.scroll, w, props_h, self.fg_color);

    if (h >= 2) {
        try writer.writeAll("\r\n");
        try self.renderActionBar(writer, w, loading);
    }
}

fn renderActionBar(self: *IamRoleView, writer: *std.Io.Writer, w: usize, loading: bool) !void {
    const policies_disabled = loading or self.ctx.policy_names.len == 0;
    const trust_disabled = loading or self.ctx.result == null;

    if (policies_disabled) {
        try writer.writeAll(terminal.DIM);
        try writer.writeAll(self.fg_color);
    } else if (self.action_idx == 0) {
        try writer.writeAll(self.bg_color);
        try writer.writeAll(terminal.FG_BLACK);
    } else {
        try writer.writeAll(self.fg_color);
    }
    const policies_btn = " [ View Policies ] ";
    try writer.writeAll(policies_btn);
    try writer.writeAll(terminal.RESET);

    if (trust_disabled) {
        try writer.writeAll(terminal.DIM);
        try writer.writeAll(self.fg_color);
    } else if (self.action_idx == 1) {
        try writer.writeAll(self.bg_color);
        try writer.writeAll(terminal.FG_BLACK);
    } else {
        try writer.writeAll(self.fg_color);
    }
    const trust_btn = " [ View Trust Policy ] ";
    try writer.writeAll(trust_btn);
    try writer.writeAll(terminal.RESET);

    const used = policies_btn.len + trust_btn.len;
    if (w > used) {
        for (0..w - used) |_| try writer.writeByte(' ');
    }
}
