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
const IamPolicyDocumentView = @import("policy_document.zig");

const IamPolicyView = @This();
pub const name: []const u8 = "IAM Policy";

// ─── Background GetPolicy context ────────────────────────────────────────────

const GetPolicyCtx = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    credentials: Credentials,
    arn: []u8,
    result: ?Iam.GetPolicyResult = null,
    err: ?anyerror = null,
    done: std.atomic.Value(bool) = .init(false),
    thread: std.Thread = undefined,
};

fn getThread(ctx: *GetPolicyCtx) void {
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

    const result = client.getPolicy(.{ .arn = ctx.arn }) catch |e| {
        ctx.err = e;
        return;
    };
    ctx.result = result;
}

// ─── View fields ─────────────────────────────────────────────────────────────

fg_color: []const u8,
bg_color: []const u8,
scroll: usize = 0,
action_idx: usize = 0,
pending_g: bool = false,
policy_name: []u8,
arn: []u8,
ctx: *GetPolicyCtx,
alloc: std.mem.Allocator,
breadcrumb_buf: [320]u8 = undefined,
breadcrumb_len: usize = 0,

// ─── Init / deinit ───────────────────────────────────────────────────────────

pub fn init(
    allocator: std.mem.Allocator,
    io: std.Io,
    credentials: Credentials,
    policy_name: []const u8,
    arn: []const u8,
    fg_color: []const u8,
    bg_color: []const u8,
    parent_breadcrumb: []const u8,
) !IamPolicyView {
    const policy_name_owned = try allocator.dupe(u8, policy_name);
    errdefer allocator.free(policy_name_owned);

    const ctx = try allocator.create(GetPolicyCtx);
    errdefer allocator.destroy(ctx);
    const arn_owned = try allocator.dupe(u8, arn);
    errdefer allocator.free(arn_owned);

    ctx.* = .{
        .allocator = allocator,
        .io = io,
        .credentials = credentials,
        .arn = arn_owned,
    };
    ctx.thread = try std.Thread.spawn(.{}, getThread, .{ctx});

    var view = IamPolicyView{
        .fg_color = fg_color,
        .bg_color = bg_color,
        .policy_name = policy_name_owned,
        .arn = arn_owned,
        .ctx = ctx,
        .alloc = allocator,
    };
    const bc = std.fmt.bufPrint(&view.breadcrumb_buf, "{s} {s} {s}", .{ parent_breadcrumb, constants.SEP_ARROW, policy_name }) catch view.breadcrumb_buf[0..0];
    view.breadcrumb_len = bc.len;
    return view;
}

pub fn breadcrumb(self: *IamPolicyView) []const u8 {
    return self.breadcrumb_buf[0..self.breadcrumb_len];
}

pub fn deinit(self: *IamPolicyView) void {
    const alloc = self.ctx.allocator;
    if (!self.ctx.done.load(.acquire)) self.ctx.thread.join();
    if (self.ctx.result) |r| r.deinit();
    alloc.free(self.ctx.arn);
    alloc.destroy(self.ctx);
    self.alloc.free(self.policy_name);
}

// ─── Event handling ──────────────────────────────────────────────────────────

pub fn handleEvent(self: *IamPolicyView, event: Event, vctx: ViewContext) !Action {
    const total_props = 9;
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
                else => self.pending_g = false,
            },
            .down => self.scroll += 1,
            .up => if (self.scroll > 0) { self.scroll -= 1; },
            .enter => return self.openDocument(vctx),
            .escape => return .pop,
            else => {},
        },
        else => {},
    }
    return .none;
}

fn openDocument(self: *IamPolicyView, vctx: ViewContext) !Action {
    if (!self.ctx.done.load(.acquire)) return .none;
    const res = self.ctx.result orelse return .none;
    const view = try IamPolicyDocumentView.init(
        vctx.allocator,
        vctx.io,
        self.ctx.credentials,
        self.policy_name,
        self.arn,
        res.default_version_id,
        self.fg_color,
        self.bg_color,
        self.breadcrumb(),
    );
    return .{ .push = .{ .iam_policy_document = view } };
}

// ─── Rendering ───────────────────────────────────────────────────────────────

pub fn render(self: *IamPolicyView, writer: *std.Io.Writer, size: Coord) !void {
    if (size.x < 10 or size.y < 2) return;
    const w: usize = @intCast(size.x);
    const h: usize = @intCast(size.y);

    const done = self.ctx.done.load(.acquire);
    const loading = !done;
    const res: ?Iam.GetPolicyResult = if (done) self.ctx.result else null;

    const ellipsis = "…";
    const dash = "-";

    const path_str: []const u8 = if (res) |r| r.path else if (loading) ellipsis else dash;
    const version_str: []const u8 = if (res) |r| r.default_version_id else if (loading) ellipsis else dash;
    const create_str: []const u8 = if (res) |r| r.create_date else if (loading) ellipsis else dash;
    const update_str: []const u8 = if (res) |r| r.update_date else if (loading) ellipsis else dash;
    const desc_str: []const u8 = if (res) |r|
        if (r.description.len > 0) r.description else dash
    else if (loading) ellipsis else dash;

    var attach_buf: [32]u8 = undefined;
    const attach_str: []const u8 = if (res) |r|
        std.fmt.bufPrint(&attach_buf, "{d}", .{r.attachment_count}) catch dash
    else if (loading) ellipsis else dash;

    const attachable_str: []const u8 = if (res) |r|
        (if (r.is_attachable) "true" else "false")
    else if (loading) ellipsis else dash;

    var props_buf: [9]props_mod.Prop = undefined;
    var n: usize = 0;
    props_buf[n] = .{ .label = "Policy Name", .value = self.policy_name };
    n += 1;
    props_buf[n] = .{ .label = "ARN", .value = self.arn };
    n += 1;
    props_buf[n] = .{ .label = "Path", .value = path_str };
    n += 1;
    props_buf[n] = .{ .label = "Default Version", .value = version_str };
    n += 1;
    props_buf[n] = .{ .label = "Attachment Count", .value = attach_str };
    n += 1;
    props_buf[n] = .{ .label = "Attachable", .value = attachable_str };
    n += 1;
    props_buf[n] = .{ .label = "Description", .value = desc_str };
    n += 1;
    props_buf[n] = .{ .label = "Created", .value = create_str };
    n += 1;
    props_buf[n] = .{ .label = "Updated", .value = update_str };
    n += 1;

    const total = n;
    const data_rows = if (h >= 2) h - 2 else 0;
    if (data_rows > 0 and self.scroll + data_rows > total) {
        self.scroll = if (total > data_rows) total - data_rows else 0;
    }

    const props_h = if (h >= 2) h - 1 else h;
    try props_mod.render(writer, props_buf[0..n], self.scroll, w, props_h, self.fg_color);

    if (h >= 2) {
        try writer.writeAll("\r\n");
        try self.renderActionBar(writer, w, done);
    }
}

fn renderActionBar(self: *IamPolicyView, writer: *std.Io.Writer, w: usize, done: bool) !void {
    if (!done) {
        try writer.writeAll(terminal.DIM);
        try writer.writeAll(self.fg_color);
    } else {
        try writer.writeAll(self.bg_color);
        try writer.writeAll(terminal.FG_BLACK);
    }
    const view_btn = " [ View Document ] ";
    try writer.writeAll(view_btn);
    try writer.writeAll(terminal.RESET);

    if (w > view_btn.len) {
        for (0..w - view_btn.len) |_| try writer.writeByte(' ');
    }
}
