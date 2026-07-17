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
const SecretsManager = @import("../../../sdk/clients/secretsmanager/client.zig");
const constants = @import("../../../ui/constants.zig");
const ConfirmView = @import("../../../ui/confirm.zig");
const content_mod = @import("../s3/object_content.zig");
const computeLines = content_mod.computeLines;

const ResourcePolicyView = @This();
pub const name: []const u8 = "Resource Policy";

const NO_POLICY = "No resource policy attached to this secret.";

// ─── Background GetResourcePolicy context ────────────────────────────────────

const FetchCtx = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    credentials: Credentials,
    secret_id: []u8,
    region: []u8,
    /// Pretty-printed (indent_2) JSON policy document, falling back to the raw
    /// value verbatim if it doesn't parse as JSON. Null if no policy attached.
    document: ?[]u8 = null,
    err: ?anyerror = null,
    done: std.atomic.Value(bool) = .init(false),
    thread: std.Thread = undefined,
};

fn prettyPrintJson(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch
        return allocator.dupe(u8, raw);
    defer parsed.deinit();
    return std.json.Stringify.valueAlloc(allocator, parsed.value, .{ .whitespace = .indent_2 });
}

fn fetchThread(ctx: *FetchCtx) void {
    defer {
        ctx.done.store(true, .release);
        input.notify();
    }

    var client = SecretsManager.Client.init(ctx.allocator, .{
        .region = ctx.region,
        .io = ctx.io,
        .credentials = ctx.credentials,
    }) catch |e| {
        ctx.err = e;
        return;
    };
    defer client.deinit();

    const result = client.getResourcePolicy(.{ .secret_id = ctx.secret_id }) catch |e| {
        ctx.err = e;
        return;
    };
    defer result.deinit();

    if (result.resource_policy) |p| {
        ctx.document = prettyPrintJson(ctx.allocator, p) catch |e| {
            ctx.err = e;
            return;
        };
    }
}

// ─── View fields ─────────────────────────────────────────────────────────────

fg_color: []const u8,
bg_color: []const u8,
scroll: usize = 0,
pending_g: bool = false,
ctx: *FetchCtx,
alloc: std.mem.Allocator,
io: std.Io,
credentials: Credentials,
region: []u8,
secret_id: []u8,
lines: ?[][]const u8 = null,
last_lines_width: usize = 0,
breadcrumb_buf: [320]u8 = undefined,
breadcrumb_len: usize = 0,

// ─── Init / deinit ───────────────────────────────────────────────────────────

pub fn init(
    allocator: std.mem.Allocator,
    io: std.Io,
    credentials: Credentials,
    secret_id: []const u8,
    region: []const u8,
    color_support: terminal.ColorSupport,
    parent_breadcrumb: []const u8,
) !ResourcePolicyView {
    const colors = colors_mod.iam(color_support);

    const secret_id_owned = try allocator.dupe(u8, secret_id);
    errdefer allocator.free(secret_id_owned);
    const region_owned = try allocator.dupe(u8, region);
    errdefer allocator.free(region_owned);

    const ctx = try allocator.create(FetchCtx);
    errdefer allocator.destroy(ctx);
    const ctx_secret_id = try allocator.dupe(u8, secret_id);
    errdefer allocator.free(ctx_secret_id);
    const ctx_region = try allocator.dupe(u8, region);
    errdefer allocator.free(ctx_region);

    ctx.* = .{
        .allocator = allocator,
        .io = io,
        .credentials = credentials,
        .secret_id = ctx_secret_id,
        .region = ctx_region,
    };
    ctx.thread = try std.Thread.spawn(.{}, fetchThread, .{ctx});

    var view = ResourcePolicyView{
        .fg_color = colors.fg,
        .bg_color = colors.bg,
        .ctx = ctx,
        .alloc = allocator,
        .io = io,
        .credentials = credentials,
        .region = region_owned,
        .secret_id = secret_id_owned,
    };
    const bc = std.fmt.bufPrint(&view.breadcrumb_buf, "{s} {s} Policy", .{ parent_breadcrumb, constants.SEP_ARROW }) catch view.breadcrumb_buf[0..0];
    view.breadcrumb_len = bc.len;
    return view;
}

pub fn breadcrumb(self: *ResourcePolicyView) []const u8 {
    return self.breadcrumb_buf[0..self.breadcrumb_len];
}

pub fn deinit(self: *ResourcePolicyView) void {
    const alloc = self.ctx.allocator;
    if (!self.ctx.done.load(.acquire)) self.ctx.thread.join();
    if (self.ctx.document) |d| alloc.free(d);
    alloc.free(self.ctx.secret_id);
    alloc.free(self.ctx.region);
    alloc.destroy(self.ctx);
    if (self.lines) |l| self.alloc.free(l);
    self.alloc.free(self.region);
    self.alloc.free(self.secret_id);
}

fn refresh(self: *ResourcePolicyView) !void {
    if (!self.ctx.done.load(.acquire)) return;

    const alloc = self.ctx.allocator;

    self.ctx.thread.join();
    if (self.ctx.document) |d| alloc.free(d);
    alloc.free(self.ctx.secret_id);
    alloc.free(self.ctx.region);
    alloc.destroy(self.ctx);
    if (self.lines) |l| {
        self.alloc.free(l);
        self.lines = null;
    }

    const new_ctx = try alloc.create(FetchCtx);
    errdefer alloc.destroy(new_ctx);
    const secret_id_owned = try alloc.dupe(u8, self.secret_id);
    errdefer alloc.free(secret_id_owned);
    const region_owned = try alloc.dupe(u8, self.region);
    errdefer alloc.free(region_owned);

    new_ctx.* = .{
        .allocator = alloc,
        .io = self.io,
        .credentials = self.credentials,
        .secret_id = secret_id_owned,
        .region = region_owned,
    };
    new_ctx.thread = try std.Thread.spawn(.{}, fetchThread, .{new_ctx});
    self.ctx = new_ctx;
    self.scroll = 0;
}

// ─── Event handling ──────────────────────────────────────────────────────────

pub fn handleEvent(self: *ResourcePolicyView, event: Event, _: ViewContext) !Action {
    switch (event) {
        .key => |k| switch (k) {
            .ctrl_c => return .quit,
            .char => |c| switch (c) {
                'q' => return .{ .push = .{ .confirm = ConfirmView.init(self.fg_color, self.bg_color) } },
                'r' => self.refresh() catch {},
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
                    self.scroll = std.math.maxInt(usize) / 2;
                },
                else => {
                    self.pending_g = false;
                },
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

pub fn render(self: *ResourcePolicyView, writer: *std.Io.Writer, size: Coord) !void {
    if (size.x < 4 or size.y < 2) return;
    const w: usize = @intCast(size.x);
    const h: usize = @intCast(size.y);
    const inner_w = w - 2;
    const data_rows = h - 1;

    const done = self.ctx.done.load(.acquire);

    if (!done) {
        try self.writeStatus(writer, inner_w, data_rows, "Loading" ++ constants.ELLIPSES);
        return;
    }

    if (self.ctx.err) |e| {
        var buf: [128]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "Error: {s}", .{@errorName(e)}) catch "Error";
        try self.writeStatus(writer, inner_w, data_rows, msg);
        return;
    }

    const doc = self.ctx.document orelse {
        try self.writeStatus(writer, inner_w, data_rows, NO_POLICY);
        return;
    };

    const width_changed = self.last_lines_width != inner_w;
    if (self.lines == null or width_changed) {
        if (self.lines) |l| self.alloc.free(l);
        self.lines = try computeLines(self.alloc, doc, inner_w);
        self.last_lines_width = inner_w;
    }
    const lines = self.lines.?;

    if (data_rows > 0 and lines.len > 0 and self.scroll + data_rows > lines.len) {
        self.scroll = if (lines.len > data_rows) lines.len - data_rows else 0;
    }

    for (0..data_rows) |row| {
        try writer.writeAll(self.fg_color);
        try writer.writeAll(constants.VERTICAL);
        try writer.writeAll(terminal.RESET);
        const idx = self.scroll + row;
        if (idx < lines.len) {
            try writer.writeAll(lines[idx]);
            for (lines[idx].len..inner_w) |_| try writer.writeByte(' ');
        } else {
            for (0..inner_w) |_| try writer.writeByte(' ');
        }
        try writer.writeAll(self.fg_color);
        try writer.writeAll(constants.VERTICAL);
        try writer.writeAll(terminal.RESET);
        try writer.writeAll("\r\n");
    }

    try self.writeBottom(writer, inner_w);
}

fn writeStatus(self: *ResourcePolicyView, writer: *std.Io.Writer, inner_w: usize, data_rows: usize, msg: []const u8) !void {
    for (0..data_rows) |row| {
        try writer.writeAll(self.fg_color);
        try writer.writeAll(constants.VERTICAL);
        try writer.writeAll(terminal.RESET);
        if (row == 0) {
            const shown = msg[0..@min(msg.len, inner_w)];
            try writer.writeAll(shown);
            for (shown.len..inner_w) |_| try writer.writeByte(' ');
        } else {
            for (0..inner_w) |_| try writer.writeByte(' ');
        }
        try writer.writeAll(self.fg_color);
        try writer.writeAll(constants.VERTICAL);
        try writer.writeAll(terminal.RESET);
        try writer.writeAll("\r\n");
    }
    try self.writeBottom(writer, inner_w);
}

fn writeBottom(self: *ResourcePolicyView, writer: *std.Io.Writer, inner_w: usize) !void {
    try writer.writeAll(self.fg_color);
    try writer.writeAll(constants.BOTTOM_LEFT);
    for (0..inner_w) |_| try writer.writeAll(constants.HORIZONTAL);
    try writer.writeAll(constants.BOTTOM_RIGHT);
    try writer.writeAll(terminal.RESET);
}

// ============================================================================
// Tests
// ============================================================================

test "prettyPrintJson formats compact document" {
    const allocator = std.testing.allocator;
    const pretty = try prettyPrintJson(allocator, "{\"Version\":\"2012-10-17\"}");
    defer allocator.free(pretty);
    try std.testing.expect(std.mem.indexOf(u8, pretty, "\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, pretty, "\"Version\": \"2012-10-17\"") != null);
}
