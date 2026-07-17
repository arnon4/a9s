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
const IamGroupInlinePoliciesView = @import("group_inline_policies.zig");

const IamGroupView = @This();
pub const name: []const u8 = "IAM Group";

// ─── Background policy-fetch context ─────────────────────────────────────────

const FetchCtx = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    credentials: Credentials,
    group_name: []u8,
    /// Attached managed policies (name + arn, parallel arrays). Owned.
    attached_names: [][]u8 = &.{},
    attached_arns: [][]u8 = &.{},
    /// Inline policy names embedded directly in the group. Owned.
    inline_names: [][]u8 = &.{},
    /// Number of IAM users belonging to the group (via GetGroup, paginated).
    member_count: usize = 0,
    err: ?anyerror = null,
    done: std.atomic.Value(bool) = .init(false),
    thread: std.Thread = undefined,
};

fn fetchAttachedPolicies(ctx: *FetchCtx, client: *Iam.Client) void {
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
        const result = client.listAttachedGroupPolicies(.{
            .group_name = ctx.group_name,
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

    ctx.attached_names = names.toOwnedSlice(ctx.allocator) catch &.{};
    ctx.attached_arns = arns.toOwnedSlice(ctx.allocator) catch &.{};
}

fn fetchInlinePolicies(ctx: *FetchCtx, client: *Iam.Client) void {
    var names: std.ArrayList([]u8) = .empty;
    errdefer {
        for (names.items) |n| ctx.allocator.free(n);
        names.deinit(ctx.allocator);
    }

    var marker: ?[]u8 = null;
    defer if (marker) |m| ctx.allocator.free(m);

    while (true) {
        const result = client.listGroupPolicies(.{
            .group_name = ctx.group_name,
            .params = .{ .marker = marker },
        }) catch return;
        defer result.deinit();

        for (result.policy_names) |n| {
            const nm = ctx.allocator.dupe(u8, n) catch continue;
            names.append(ctx.allocator, nm) catch {
                ctx.allocator.free(nm);
                continue;
            };
        }

        if (marker) |m| ctx.allocator.free(m);
        marker = if (result.next_marker) |m| ctx.allocator.dupe(u8, m) catch null else null;
        if (result.next_marker == null) break;
    }

    ctx.inline_names = names.toOwnedSlice(ctx.allocator) catch &.{};
}

fn fetchMembers(ctx: *FetchCtx, client: *Iam.Client) void {
    var marker: ?[]u8 = null;
    defer if (marker) |m| ctx.allocator.free(m);
    var count: usize = 0;

    while (true) {
        const result = client.getGroup(.{
            .group_name = ctx.group_name,
            .params = .{ .marker = marker },
        }) catch return;
        defer result.deinit();

        count += result.users.len;

        if (marker) |m| ctx.allocator.free(m);
        marker = if (result.next_marker) |m| ctx.allocator.dupe(u8, m) catch null else null;
        if (result.next_marker == null) break;
    }

    ctx.member_count = count;
}

fn fetchThread(ctx: *FetchCtx) void {
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

    fetchAttachedPolicies(ctx, &client);
    fetchInlinePolicies(ctx, &client);
    fetchMembers(ctx, &client);
}

// ─── View fields ─────────────────────────────────────────────────────────────

fg_color: []const u8,
bg_color: []const u8,
scroll: usize = 0,
pending_g: bool = false,
group_name: []u8,
arn: []u8,
path: []u8,
create_date: []u8,
ctx: *FetchCtx,
alloc: std.mem.Allocator,
breadcrumb_buf: [320]u8 = undefined,
breadcrumb_len: usize = 0,

// ─── Init / deinit ───────────────────────────────────────────────────────────

pub fn init(
    allocator: std.mem.Allocator,
    io: std.Io,
    credentials: Credentials,
    group_name: []const u8,
    arn: []const u8,
    path: []const u8,
    create_date: []const u8,
    color_support: terminal.ColorSupport,
    parent_breadcrumb: []const u8,
) !IamGroupView {
    const colors = colors_mod.iam(color_support);

    const group_name_owned = try allocator.dupe(u8, group_name);
    errdefer allocator.free(group_name_owned);
    const arn_owned = try allocator.dupe(u8, arn);
    errdefer allocator.free(arn_owned);
    const path_owned = try allocator.dupe(u8, path);
    errdefer allocator.free(path_owned);
    const create_date_owned = try allocator.dupe(u8, create_date);
    errdefer allocator.free(create_date_owned);

    const ctx = try allocator.create(FetchCtx);
    errdefer allocator.destroy(ctx);
    const ctx_group_name = try allocator.dupe(u8, group_name);
    errdefer allocator.free(ctx_group_name);

    ctx.* = .{
        .allocator = allocator,
        .io = io,
        .credentials = credentials,
        .group_name = ctx_group_name,
    };
    ctx.thread = try std.Thread.spawn(.{}, fetchThread, .{ctx});

    var view = IamGroupView{
        .fg_color = colors.fg,
        .bg_color = colors.bg,
        .group_name = group_name_owned,
        .arn = arn_owned,
        .path = path_owned,
        .create_date = create_date_owned,
        .ctx = ctx,
        .alloc = allocator,
    };
    const bc = std.fmt.bufPrint(&view.breadcrumb_buf, "{s} {s} {s}", .{ parent_breadcrumb, constants.SEP_ARROW, group_name }) catch view.breadcrumb_buf[0..0];
    view.breadcrumb_len = bc.len;
    return view;
}

pub fn breadcrumb(self: *IamGroupView) []const u8 {
    return self.breadcrumb_buf[0..self.breadcrumb_len];
}

pub fn deinit(self: *IamGroupView) void {
    const alloc = self.ctx.allocator;
    if (!self.ctx.done.load(.acquire)) self.ctx.thread.join();
    for (self.ctx.attached_names) |n| alloc.free(n);
    alloc.free(self.ctx.attached_names);
    for (self.ctx.attached_arns) |a| alloc.free(a);
    alloc.free(self.ctx.attached_arns);
    for (self.ctx.inline_names) |n| alloc.free(n);
    alloc.free(self.ctx.inline_names);
    alloc.free(self.ctx.group_name);
    alloc.destroy(self.ctx);
    self.alloc.free(self.group_name);
    self.alloc.free(self.arn);
    self.alloc.free(self.path);
    self.alloc.free(self.create_date);
}

// ─── Event handling ──────────────────────────────────────────────────────────

pub fn handleEvent(self: *IamGroupView, event: Event, vctx: ViewContext) !Action {
    const total_props = 7;
    switch (event) {
        .key => |k| switch (k) {
            .ctrl_c => return .quit,
            .char => |c| switch (c) {
                'q' => return .{ .push = .{ .confirm = ConfirmView.init(self.fg_color, self.bg_color) } },
                'j' => self.scroll += 1,
                'k' => if (self.scroll > 0) { self.scroll -= 1; },
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
                'i' => return self.openInlinePolicies(vctx),
                else => self.pending_g = false,
            },
            .down => self.scroll += 1,
            .up => if (self.scroll > 0) { self.scroll -= 1; },
            .enter => return self.openAttachedPolicies(vctx),
            .escape => return .pop,
            else => {},
        },
        else => {},
    }
    return .none;
}

fn openAttachedPolicies(self: *IamGroupView, vctx: ViewContext) !Action {
    if (!self.ctx.done.load(.acquire) or self.ctx.attached_names.len == 0) return .none;
    const view = try IamRolePoliciesView.init(
        vctx.allocator,
        vctx.io,
        self.ctx.credentials,
        self.ctx.attached_names,
        self.ctx.attached_arns,
        self.fg_color,
        self.bg_color,
        self.breadcrumb(),
    );
    return .{ .push = .{ .iam_role_policies = view } };
}

fn openInlinePolicies(self: *IamGroupView, vctx: ViewContext) !Action {
    if (!self.ctx.done.load(.acquire) or self.ctx.inline_names.len == 0) return .none;
    const view = try IamGroupInlinePoliciesView.init(
        vctx.allocator,
        vctx.io,
        self.ctx.credentials,
        self.ctx.group_name,
        self.ctx.inline_names,
        self.fg_color,
        self.bg_color,
        self.breadcrumb(),
    );
    return .{ .push = .{ .iam_group_inline_policies = view } };
}

// ─── Rendering ───────────────────────────────────────────────────────────────

pub fn render(self: *IamGroupView, writer: *std.Io.Writer, size: Coord) !void {
    if (size.x < 10 or size.y < 2) return;
    const w: usize = @intCast(size.x);
    const h: usize = @intCast(size.y);

    const done = self.ctx.done.load(.acquire);
    const loading = !done;

    const ellipsis = "…";
    const dash = "-";

    var attached_buf: [64]u8 = undefined;
    const attached_str: []const u8 = if (loading)
        ellipsis
    else if (self.ctx.attached_names.len == 0)
        dash
    else
        std.fmt.bufPrint(&attached_buf, "{d} attached (Enter to view)", .{self.ctx.attached_names.len}) catch dash;

    var inline_buf: [64]u8 = undefined;
    const inline_str: []const u8 = if (loading)
        ellipsis
    else if (self.ctx.inline_names.len == 0)
        dash
    else
        std.fmt.bufPrint(&inline_buf, "{d} inline (i to view)", .{self.ctx.inline_names.len}) catch dash;

    var members_buf: [32]u8 = undefined;
    const members_str: []const u8 = if (loading)
        ellipsis
    else
        std.fmt.bufPrint(&members_buf, "{d}", .{self.ctx.member_count}) catch dash;

    var props_buf: [7]props_mod.Prop = undefined;
    var n: usize = 0;
    props_buf[n] = .{ .label = "Group Name", .value = self.group_name };
    n += 1;
    props_buf[n] = .{ .label = "ARN", .value = self.arn };
    n += 1;
    props_buf[n] = .{ .label = "Path", .value = self.path };
    n += 1;
    props_buf[n] = .{ .label = "Created", .value = self.create_date };
    n += 1;
    props_buf[n] = .{ .label = "Members", .value = members_str };
    n += 1;
    props_buf[n] = .{ .label = "Attached Policies", .value = attached_str };
    n += 1;
    props_buf[n] = .{ .label = "Inline Policies", .value = inline_str };
    n += 1;

    const total = n;
    const data_rows = if (h >= 1) h - 1 else 0;
    if (data_rows > 0 and self.scroll + data_rows > total) {
        self.scroll = if (total > data_rows) total - data_rows else 0;
    }

    try props_mod.render(writer, props_buf[0..n], self.scroll, w, h, self.fg_color);
}
