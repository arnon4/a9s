const std = @import("std");
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
const constants = @import("../../../ui/constants.zig");
const ConfirmView = @import("../../../ui/confirm.zig");
const content_mod = @import("../s3/object_content.zig");
const computeLines = content_mod.computeLines;
const findNextMatch = content_mod.findNextMatch;
const writeLineHighlighted = content_mod.writeLineHighlighted;
const LineMatch = content_mod.LineMatch;

const IamUserInlinePolicyDocumentView = @This();
pub const name: []const u8 = "IAM User Inline Policy Document";

const Match = struct { line: usize, col: usize };

// ─── Background GetUserPolicy context ────────────────────────────────────────

const FetchCtx = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    credentials: Credentials,
    user_name: []u8,
    policy_name: []u8,
    /// Pretty-printed (indent_2) JSON document, falling back to the raw
    /// document verbatim if it doesn't parse as JSON.
    document: ?[]u8 = null,
    err: ?anyerror = null,
    done: std.atomic.Value(bool) = .init(false),
    thread: std.Thread = undefined,
};

/// Pretty-prints `raw` as indented JSON. Falls back to a plain dupe of `raw`
/// if it doesn't parse (policy documents are always JSON in practice, but be
/// defensive rather than dropping the content the user asked to view).
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

    var client = Iam.Client.init(ctx.allocator, .{
        .io = ctx.io,
        .credentials = ctx.credentials,
    }) catch |e| {
        ctx.err = e;
        return;
    };
    defer client.deinit();

    const result = client.getUserPolicy(.{ .user_name = ctx.user_name, .policy_name = ctx.policy_name }) catch |e| {
        ctx.err = e;
        return;
    };
    defer result.deinit();

    ctx.document = prettyPrintJson(ctx.allocator, result.policy_document) catch |e| {
        ctx.err = e;
        return;
    };
}

// ─── View fields ─────────────────────────────────────────────────────────────

fg_color: []const u8,
bg_color: []const u8,
scroll: usize = 0,
pending_g: bool = false,
policy_name: []u8,
ctx: *FetchCtx,
alloc: std.mem.Allocator,
lines: ?[][]const u8 = null,
last_lines_width: usize = 0,
io: std.Io,
credentials: Credentials,
refresh_user_name: []u8,
refresh_policy_name: []u8,
committed_filter: ?[]u8 = null,
live_filter: []const u8 = "",
matches: []Match = &.{},
current_match: usize = 0,
last_match_query: [256]u8 = undefined,
last_match_query_len: usize = 0,
breadcrumb_buf: [320]u8 = undefined,
breadcrumb_len: usize = 0,

// ─── Init / deinit ───────────────────────────────────────────────────────────

pub fn init(
    allocator: std.mem.Allocator,
    io: std.Io,
    credentials: Credentials,
    user_name: []const u8,
    policy_name: []const u8,
    fg_color: []const u8,
    bg_color: []const u8,
    parent_breadcrumb: []const u8,
) !IamUserInlinePolicyDocumentView {
    const policy_name_owned = try allocator.dupe(u8, policy_name);
    errdefer allocator.free(policy_name_owned);
    const ref_user_name = try allocator.dupe(u8, user_name);
    errdefer allocator.free(ref_user_name);
    const ref_policy_name = try allocator.dupe(u8, policy_name);
    errdefer allocator.free(ref_policy_name);

    const ctx = try allocator.create(FetchCtx);
    errdefer allocator.destroy(ctx);
    const user_name_owned = try allocator.dupe(u8, user_name);
    errdefer allocator.free(user_name_owned);
    const policy_name_ctx = try allocator.dupe(u8, policy_name);
    errdefer allocator.free(policy_name_ctx);

    ctx.* = .{
        .allocator = allocator,
        .io = io,
        .credentials = credentials,
        .user_name = user_name_owned,
        .policy_name = policy_name_ctx,
    };
    ctx.thread = try std.Thread.spawn(.{}, fetchThread, .{ctx});

    var view = IamUserInlinePolicyDocumentView{
        .fg_color = fg_color,
        .bg_color = bg_color,
        .policy_name = policy_name_owned,
        .ctx = ctx,
        .alloc = allocator,
        .io = io,
        .credentials = credentials,
        .refresh_user_name = ref_user_name,
        .refresh_policy_name = ref_policy_name,
    };
    const bc = std.fmt.bufPrint(&view.breadcrumb_buf, "{s} {s} {s}", .{ parent_breadcrumb, constants.SEP_ARROW, policy_name }) catch view.breadcrumb_buf[0..0];
    view.breadcrumb_len = bc.len;
    return view;
}

pub fn breadcrumb(self: *IamUserInlinePolicyDocumentView) []const u8 {
    return self.breadcrumb_buf[0..self.breadcrumb_len];
}

pub fn deinit(self: *IamUserInlinePolicyDocumentView) void {
    if (self.matches.len > 0) self.alloc.free(self.matches);
    if (self.committed_filter) |f| self.alloc.free(f);
    const alloc = self.ctx.allocator;
    if (!self.ctx.done.load(.acquire)) self.ctx.thread.join();
    if (self.ctx.document) |d| alloc.free(d);
    alloc.free(self.ctx.user_name);
    alloc.free(self.ctx.policy_name);
    alloc.destroy(self.ctx);
    if (self.lines) |l| self.alloc.free(l);
    self.alloc.free(self.policy_name);
    self.alloc.free(self.refresh_user_name);
    self.alloc.free(self.refresh_policy_name);
}

fn effectiveFilter(self: *const IamUserInlinePolicyDocumentView) []const u8 {
    if (self.live_filter.len > 0) return self.live_filter;
    return self.committed_filter orelse "";
}

pub fn setLiveFilter(self: *IamUserInlinePolicyDocumentView, text: []const u8) void {
    self.live_filter = text;
}

pub fn commitFilter(self: *IamUserInlinePolicyDocumentView, text: []const u8) void {
    if (self.committed_filter) |f| self.alloc.free(f);
    self.committed_filter = if (text.len > 0) self.alloc.dupe(u8, text) catch null else null;
    self.live_filter = "";
}

fn recomputeMatches(self: *IamUserInlinePolicyDocumentView, query: []const u8) void {
    if (self.matches.len > 0) {
        self.alloc.free(self.matches);
        self.matches = &.{};
    }
    self.current_match = 0;
    const lines = self.lines orelse return;
    if (query.len == 0) return;

    var list: std.ArrayList(Match) = .empty;
    for (lines, 0..) |line, li| {
        var pos: usize = 0;
        while (findNextMatch(line, query, pos)) |col| {
            list.append(self.alloc, .{ .line = li, .col = col }) catch break;
            pos = col + query.len;
        }
    }
    self.matches = list.toOwnedSlice(self.alloc) catch &.{};

    const qlen = @min(query.len, self.last_match_query.len);
    @memcpy(self.last_match_query[0..qlen], query[0..qlen]);
    self.last_match_query_len = qlen;

    if (self.matches.len > 0) {
        const line = self.matches[0].line;
        self.scroll = if (line >= 3) line - 3 else 0;
    }
}

fn refresh(self: *IamUserInlinePolicyDocumentView) !void {
    if (!self.ctx.done.load(.acquire)) return;

    if (self.matches.len > 0) {
        self.alloc.free(self.matches);
        self.matches = &.{};
    }
    if (self.committed_filter) |f| {
        self.alloc.free(f);
        self.committed_filter = null;
    }
    self.live_filter = "";
    self.last_match_query_len = 0;

    const alloc = self.ctx.allocator;

    self.ctx.thread.join();
    if (self.ctx.document) |d| alloc.free(d);
    alloc.free(self.ctx.user_name);
    alloc.free(self.ctx.policy_name);
    alloc.destroy(self.ctx);
    if (self.lines) |l| {
        self.alloc.free(l);
        self.lines = null;
    }

    const new_ctx = try alloc.create(FetchCtx);
    errdefer alloc.destroy(new_ctx);
    const user_name_owned = try alloc.dupe(u8, self.refresh_user_name);
    errdefer alloc.free(user_name_owned);
    const policy_name_owned = try alloc.dupe(u8, self.refresh_policy_name);
    errdefer alloc.free(policy_name_owned);

    new_ctx.* = .{
        .allocator = alloc,
        .io = self.io,
        .credentials = self.credentials,
        .user_name = user_name_owned,
        .policy_name = policy_name_owned,
    };
    new_ctx.thread = try std.Thread.spawn(.{}, fetchThread, .{new_ctx});
    self.ctx = new_ctx;
    self.scroll = 0;
}

// ─── Event handling ──────────────────────────────────────────────────────────

pub fn handleEvent(self: *IamUserInlinePolicyDocumentView, event: Event, _: ViewContext) !Action {
    switch (event) {
        .key => |k| switch (k) {
            .ctrl_c => return .quit,
            .char => |c| switch (c) {
                'q' => return .{ .push = .{ .confirm = ConfirmView.init(self.fg_color, self.bg_color) } },
                'r' => self.refresh() catch {},
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
                    self.scroll = std.math.maxInt(usize) / 2;
                },
                'n' => if (self.matches.len > 0) {
                    self.current_match = (self.current_match + 1) % self.matches.len;
                    const line = self.matches[self.current_match].line;
                    self.scroll = if (line >= 3) line - 3 else 0;
                },
                'N' => if (self.matches.len > 0) {
                    self.current_match = (self.current_match + self.matches.len - 1) % self.matches.len;
                    const line = self.matches[self.current_match].line;
                    self.scroll = if (line >= 3) line - 3 else 0;
                },
                else => self.pending_g = false,
            },
            .down => self.scroll += 1,
            .up => if (self.scroll > 0) { self.scroll -= 1; },
            .escape => {
                if (self.committed_filter != null) {
                    if (self.committed_filter) |f| {
                        self.alloc.free(f);
                        self.committed_filter = null;
                    }
                    self.last_match_query_len = 0;
                } else {
                    return .pop;
                }
            },
            else => {},
        },
        else => {},
    }
    return .none;
}

// ─── Rendering ───────────────────────────────────────────────────────────────

pub fn render(self: *IamUserInlinePolicyDocumentView, writer: *std.Io.Writer, size: Coord) !void {
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

    const doc = self.ctx.document orelse "";
    const width_changed = self.last_lines_width != inner_w;
    if (self.lines == null or width_changed) {
        if (self.lines) |l| self.alloc.free(l);
        self.lines = try computeLines(self.alloc, doc, inner_w);
        self.last_lines_width = inner_w;
    }
    const lines = self.lines.?;

    const query = self.effectiveFilter();
    const cached_query = self.last_match_query[0..self.last_match_query_len];
    if (width_changed or !std.mem.eql(u8, query, cached_query)) {
        self.recomputeMatches(query);
    }

    if (data_rows > 0 and lines.len > 0 and self.scroll + data_rows > lines.len) {
        self.scroll = if (lines.len > data_rows) lines.len - data_rows else 0;
    }

    for (0..data_rows) |row| {
        try writer.writeAll(self.fg_color);
        try writer.writeAll(constants.VERTICAL);
        try writer.writeAll(terminal.RESET);
        const idx = self.scroll + row;
        if (idx < lines.len) {
            const written = if (query.len > 0) blk: {
                var lm_buf: [64]LineMatch = undefined;
                var lm_n: usize = 0;
                for (self.matches, 0..) |m, mi| {
                    if (m.line == idx and lm_n < lm_buf.len) {
                        lm_buf[lm_n] = .{ .col = m.col, .is_current = mi == self.current_match };
                        lm_n += 1;
                    }
                }
                break :blk try writeLineHighlighted(writer, lines[idx], query.len, lm_buf[0..lm_n], self.bg_color);
            } else blk: {
                try writer.writeAll(lines[idx]);
                break :blk lines[idx].len;
            };
            for (written..inner_w) |_| try writer.writeByte(' ');
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

fn writeStatus(self: *IamUserInlinePolicyDocumentView, writer: *std.Io.Writer, inner_w: usize, data_rows: usize, msg: []const u8) !void {
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

fn writeBottom(self: *IamUserInlinePolicyDocumentView, writer: *std.Io.Writer, inner_w: usize) !void {
    try writer.writeAll(self.fg_color);
    try writer.writeAll(constants.BOTTOM_LEFT);
    for (0..inner_w) |_| try writer.writeAll(constants.HORIZONTAL);
    try writer.writeAll(constants.BOTTOM_RIGHT);
    try writer.writeAll(terminal.RESET);
}
