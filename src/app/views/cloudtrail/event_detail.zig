const std = @import("std");
const colors_mod = @import("../../../ui/colors.zig");
const terminal = @import("../../../terminal/terminal.zig");
const Event = @import("../../../event.zig").Event;
const view_mod = @import("../../../ui/view.zig");
const Action = view_mod.Action;
const ViewContext = view_mod.ViewContext;
const Coord = terminal.Coord;
const constants = @import("../../../ui/constants.zig");
const ConfirmView = @import("../../../ui/confirm.zig");
const content_mod = @import("../s3/object_content.zig");
const LineMatch = content_mod.LineMatch;

const EventDetailView = @This();
pub const name: []const u8 = "CloudTrail Event";

const Match = struct { line: usize, col: usize };

/// Pretty-prints `raw` as indented JSON. Falls back to a plain dupe of `raw`
/// if it doesn't parse (CloudTrail events are always JSON in practice, but be
/// defensive rather than dropping the content the user asked to view).
fn prettyPrintJson(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch
        return allocator.dupe(u8, raw);
    defer parsed.deinit();
    return std.json.Stringify.valueAlloc(allocator, parsed.value, .{ .whitespace = .indent_2 });
}

fg_color: []const u8,
bg_color: []const u8,
scroll: usize = 0,
pending_g: bool = false,
alloc: std.mem.Allocator,
/// Raw CloudTrailEvent JSON. Owned — freed in deinit.
body: []u8,
lines: ?[][]const u8 = null,
last_lines_width: usize = 0,
breadcrumb_buf: [640]u8 = undefined,
breadcrumb_len: usize = 0,
committed_filter: ?[]u8 = null,
live_filter: []const u8 = "",
matches: []Match = &.{},
current_match: usize = 0,
last_match_query: [256]u8 = undefined,
last_match_query_len: usize = 0,

fn effectiveFilter(self: *const EventDetailView) []const u8 {
    if (self.live_filter.len > 0) return self.live_filter;
    return self.committed_filter orelse "";
}

pub fn setLiveFilter(self: *EventDetailView, text: []const u8) void {
    self.live_filter = text;
}

pub fn commitFilter(self: *EventDetailView, text: []const u8) void {
    if (self.committed_filter) |f| self.alloc.free(f);
    self.committed_filter = if (text.len > 0) self.alloc.dupe(u8, text) catch null else null;
    self.live_filter = "";
}

fn recomputeMatches(self: *EventDetailView, query: []const u8) void {
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
        while (content_mod.findNextMatch(line, query, pos)) |col| {
            list.append(self.alloc, .{ .line = li, .col = col }) catch break;
            pos = col + query.len;
        }
    }
    self.matches = list.toOwnedSlice(self.alloc) catch &.{};

    const qlen = @min(query.len, self.last_match_query.len);
    @memcpy(self.last_match_query[0..qlen], query[0..qlen]);
    self.last_match_query_len = qlen;

    if (self.matches.len > 0) self.scroll = self.matches[0].line;
}

/// Takes ownership of `body`.
pub fn init(
    allocator: std.mem.Allocator,
    body: []u8,
    event_name: []const u8,
    color_support: terminal.ColorSupport,
    parent_breadcrumb: []const u8,
) !EventDetailView {
    const colors = colors_mod.red(color_support);

    const pretty = try prettyPrintJson(allocator, body);
    allocator.free(body);

    var view = EventDetailView{
        .fg_color = colors.fg,
        .bg_color = colors.bg,
        .alloc = allocator,
        .body = pretty,
    };

    const bc = std.fmt.bufPrint(&view.breadcrumb_buf, "{s} {s} {s}", .{ parent_breadcrumb, constants.SEP_ARROW, event_name }) catch view.breadcrumb_buf[0..0];
    view.breadcrumb_len = bc.len;

    return view;
}

pub fn breadcrumb(self: *EventDetailView) []const u8 {
    return self.breadcrumb_buf[0..self.breadcrumb_len];
}

pub fn deinit(self: *EventDetailView) void {
    if (self.matches.len > 0) self.alloc.free(self.matches);
    if (self.committed_filter) |f| self.alloc.free(f);
    if (self.lines) |l| self.alloc.free(l);
    self.alloc.free(self.body);
}

pub fn handleEvent(self: *EventDetailView, event: Event, _: ViewContext) !Action {
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
                    self.scroll = std.math.maxInt(usize) / 2;
                },
                'n' => if (self.matches.len > 0) {
                    self.current_match = (self.current_match + 1) % self.matches.len;
                    self.scroll = self.matches[self.current_match].line;
                },
                'N' => if (self.matches.len > 0) {
                    self.current_match = (self.current_match + self.matches.len - 1) % self.matches.len;
                    self.scroll = self.matches[self.current_match].line;
                },
                else => {
                    self.pending_g = false;
                },
            },
            .down => self.scroll += 1,
            .up => if (self.scroll > 0) {
                self.scroll -= 1;
            },
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

pub fn render(self: *EventDetailView, writer: *std.Io.Writer, size: Coord) !void {
    if (size.x < 4 or size.y < 2) return;
    const w: usize = @intCast(size.x);
    const h: usize = @intCast(size.y);
    const inner_w = w - 2;
    const data_rows = h - 1;

    const width_changed = self.last_lines_width != inner_w;
    if (self.lines == null or width_changed) {
        if (self.lines) |l| self.alloc.free(l);
        self.lines = try content_mod.computeLines(self.alloc, self.body, inner_w);
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
                    if (m.line != idx) continue;
                    if (lm_n < lm_buf.len) {
                        lm_buf[lm_n] = .{ .col = m.col, .is_current = mi == self.current_match };
                        lm_n += 1;
                    }
                }
                break :blk try content_mod.writeLineHighlighted(writer, lines[idx], query.len, lm_buf[0..lm_n], self.bg_color);
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

    try writer.writeAll(self.fg_color);
    try writer.writeAll(constants.BOTTOM_LEFT);
    for (0..inner_w) |_| try writer.writeAll(constants.HORIZONTAL);
    try writer.writeAll(constants.BOTTOM_RIGHT);
    try writer.writeAll(terminal.RESET);
}

// ============================================================================
// Tests
// ============================================================================

test "prettyPrintJson formats compact event" {
    const allocator = std.testing.allocator;
    const pretty = try prettyPrintJson(allocator, "{\"eventVersion\":\"1.08\",\"eventName\":\"ConsoleLogin\"}");
    defer allocator.free(pretty);
    try std.testing.expect(std.mem.indexOf(u8, pretty, "\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, pretty, "\"eventName\": \"ConsoleLogin\"") != null);
}

test "prettyPrintJson falls back on invalid json" {
    const allocator = std.testing.allocator;
    const pretty = try prettyPrintJson(allocator, "not json");
    defer allocator.free(pretty);
    try std.testing.expectEqualStrings("not json", pretty);
}
