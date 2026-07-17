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
const Lambda = @import("../../../sdk/clients/lambda/client.zig");
const constants = @import("../../../ui/constants.zig");
const ConfirmView = @import("../../../ui/confirm.zig");

pub const FetchCtx = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    io: std.Io,
    credentials: Credentials,
    region: []const u8,
    function_name: []const u8,
    thread: std.Thread,
    body: ?[]u8 = null,
    err: ?anyerror = null,
    done: std.atomic.Value(bool),
};

fn fetchThread(ctx: *FetchCtx) void {
    defer {
        ctx.done.store(true, .release);
        input.notify();
    }

    const arena_alloc = ctx.arena.allocator();

    var client = Lambda.Client.init(arena_alloc, .{
        .region = ctx.region,
        .io = ctx.io,
        .credentials = ctx.credentials,
    }) catch |e| {
        ctx.err = e;
        return;
    };
    defer client.deinit();

    var fn_result = client.getFunction(.{ .function_name = ctx.function_name }) catch |e| {
        ctx.err = e;
        return;
    };
    defer fn_result.deinit();

    if (fn_result.code.location.len == 0) {
        ctx.err = error.NoCodeLocation;
        return;
    }

    var http_client = std.http.Client{ .allocator = arena_alloc, .io = ctx.io };
    defer http_client.deinit();

    var resp_writer: std.Io.Writer.Allocating = .init(arena_alloc);

    const result = http_client.fetch(.{
        .method = .GET,
        .location = .{ .url = fn_result.code.location },
        .response_writer = &resp_writer.writer,
    }) catch |e| {
        ctx.err = e;
        return;
    };

    if (result.status != .ok) {
        ctx.err = error.HttpError;
        return;
    }

    const raw = resp_writer.writer.buffer[0..resp_writer.writer.end];
    ctx.body = if (isZip(raw)) zipToText(arena_alloc, ctx.io, raw) catch raw else raw;
}

fn isZip(data: []const u8) bool {
    return data.len >= 4 and data[0] == 0x50 and data[1] == 0x4b and data[2] == 0x03 and data[3] == 0x04;
}

const local_header_fixed: usize = 30;
const central_header_fixed: usize = 46;

fn zipToText(allocator: std.mem.Allocator, io: std.Io, zip_data: []const u8) ![]u8 {
    const flate = std.compress.flate;
    const cwd = std.Io.Dir.cwd();
    const tmp = ".at_lc_tmp.zip";

    {
        const f = try cwd.createFile(io, tmp, .{});
        defer f.close(io);
        var wbuf: [4096]u8 = undefined;
        var w = f.writer(io, &wbuf);
        try w.interface.writeAll(zip_data);
        try w.end();
    }
    defer cwd.deleteFile(io, tmp) catch {};

    const zf = try cwd.openFile(io, tmp, .{});
    defer zf.close(io);
    var rbuf: [4096]u8 = undefined;
    var zr = zf.reader(io, &rbuf);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    var flate_buf: [flate.max_window_len]u8 = undefined;
    var fname_buf: [4096]u8 = undefined;
    var iter = try std.zip.Iterator.init(&zr);

    while (try iter.next()) |entry| {
        if (entry.filename_len == 0 or entry.filename_len > fname_buf.len) continue;

        try zr.seekTo(entry.header_zip_offset + central_header_fixed);
        try zr.interface.readSliceAll(fname_buf[0..entry.filename_len]);
        const fname = fname_buf[0..entry.filename_len];

        if (fname[fname.len - 1] == '/') continue;

        try zr.seekTo(entry.file_offset);
        var lh: [local_header_fixed]u8 = undefined;
        try zr.interface.readSliceAll(&lh);
        const lh_fname_len = std.mem.readInt(u16, lh[26..28], .little);
        const lh_extra_len = std.mem.readInt(u16, lh[28..30], .little);
        const data_off = entry.file_offset + local_header_fixed + lh_fname_len + lh_extra_len;
        try zr.seekTo(data_off);

        var mem_out: std.Io.Writer.Allocating = .init(allocator);
        errdefer mem_out.deinit();

        switch (entry.compression_method) {
            .store => {
                try zr.interface.streamExact64(&mem_out.writer, entry.uncompressed_size);
            },
            .deflate => {
                var decomp: flate.Decompress = .init(&zr.interface, .raw, &flate_buf);
                try decomp.reader.streamExact64(&mem_out.writer, entry.uncompressed_size);
            },
            else => {
                mem_out.deinit();
                continue;
            },
        }

        const content = mem_out.writer.buffer[0..mem_out.writer.end];
        const hdr = try std.fmt.allocPrint(allocator, "\n=== {s} ===\n", .{fname});
        defer allocator.free(hdr);
        try out.appendSlice(allocator, hdr);
        try out.appendSlice(allocator, content);
        mem_out.deinit();
    }

    if (out.items.len == 0) try out.appendSlice(allocator, "(no files found)\n");
    return out.toOwnedSlice(allocator);
}

pub fn computeLines(allocator: std.mem.Allocator, body: []const u8, width: usize) ![][]const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    errdefer list.deinit(allocator);
    var it = std.mem.splitScalar(u8, body, '\n');
    while (it.next()) |raw| {
        const line = if (raw.len > 0 and raw[raw.len - 1] == '\r') raw[0 .. raw.len - 1] else raw;
        if (line.len == 0) {
            try list.append(allocator, "");
        } else {
            var i: usize = 0;
            while (i < line.len) {
                const end = @min(i + width, line.len);
                try list.append(allocator, line[i..end]);
                i = end;
            }
        }
    }
    return list.toOwnedSlice(allocator);
}

pub fn findNextMatch(haystack: []const u8, needle: []const u8, start: usize) ?usize {
    if (needle.len == 0 or start + needle.len > haystack.len) return null;
    var i = start;
    outer: while (i + needle.len <= haystack.len) : (i += 1) {
        for (needle, 0..) |nc, j| {
            if (std.ascii.toLower(haystack[i + j]) != std.ascii.toLower(nc)) continue :outer;
        }
        return i;
    }
    return null;
}

pub const LineMatch = struct { col: usize, is_current: bool };

pub fn writeLineHighlighted(
    writer: *std.Io.Writer,
    line: []const u8,
    query_len: usize,
    matches: []const LineMatch,
    hl_bg: []const u8,
) !usize {
    var pos: usize = 0;
    var written: usize = 0;
    for (matches) |m| {
        if (m.col < pos) continue;
        try writer.writeAll(line[pos..m.col]);
        written += m.col - pos;
        const bg = if (m.is_current) "\x1b[47m" else hl_bg;
        try writer.writeAll(bg);
        try writer.writeAll(terminal.FG_BLACK);
        try writer.writeAll(line[m.col .. m.col + query_len]);
        try writer.writeAll(terminal.RESET);
        written += query_len;
        pos = m.col + query_len;
    }
    try writer.writeAll(line[pos..]);
    written += line.len - pos;
    return written;
}

pub fn LambdaContentViewGeneric(comptime fetchFn: fn (*FetchCtx) void) type {
    return struct {
        const Self = @This();
        pub const name: []const u8 = "Function Code";

        const Match = struct { line: usize, col: usize };

        fg_color: []const u8,
        bg_color: []const u8,
        scroll: usize = 0,
        pending_g: bool = false,
        fetch_ctx: *FetchCtx,
        alloc: std.mem.Allocator,
        lines: ?[][]const u8 = null,
        last_lines_width: usize = 0,
        breadcrumb_buf: [256]u8 = undefined,
        breadcrumb_len: usize = 0,
        io: std.Io,
        credentials: Credentials,
        refresh_region: []u8,
        refresh_function_name: []u8,
        committed_filter: ?[]u8 = null,
        live_filter: []const u8 = "",
        matches: []Match = &.{},
        current_match: usize = 0,
        last_match_query: [256]u8 = undefined,
        last_match_query_len: usize = 0,

        fn effectiveFilter(self: *const Self) []const u8 {
            if (self.live_filter.len > 0) return self.live_filter;
            return self.committed_filter orelse "";
        }

        pub fn setLiveFilter(self: *Self, text: []const u8) void {
            self.live_filter = text;
        }

        pub fn commitFilter(self: *Self, text: []const u8) void {
            if (self.committed_filter) |f| self.alloc.free(f);
            self.committed_filter = if (text.len > 0) self.alloc.dupe(u8, text) catch null else null;
            self.live_filter = "";
        }

        fn recomputeMatches(self: *Self, query: []const u8) void {
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

            if (self.matches.len > 0) self.scroll = self.matches[0].line;
        }

        pub fn init(
            allocator: std.mem.Allocator,
            io: std.Io,
            credentials: Credentials,
            function_name: []const u8,
            region: []const u8,
            color_support: terminal.ColorSupport,
        ) !Self {
            const colors = colors_mod.orange(color_support);
            const fg_color = colors.fg;
            const bg_color = colors.bg;

            const ref_region = try allocator.dupe(u8, region);
            errdefer allocator.free(ref_region);
            const ref_name = try allocator.dupe(u8, function_name);
            errdefer allocator.free(ref_name);

            const ctx = try allocator.create(FetchCtx);
            errdefer allocator.destroy(ctx);

            ctx.* = .{
                .allocator = allocator,
                .arena = std.heap.ArenaAllocator.init(allocator),
                .io = io,
                .credentials = credentials,
                .region = undefined,
                .function_name = undefined,
                .thread = undefined,
                .done = std.atomic.Value(bool).init(false),
            };
            errdefer ctx.arena.deinit();

            const a = ctx.arena.allocator();
            ctx.region = try a.dupe(u8, region);
            ctx.function_name = try a.dupe(u8, function_name);

            ctx.thread = try std.Thread.spawn(.{}, fetchFn, .{ctx});
            errdefer ctx.thread.join();

            var bc_buf: [256]u8 = undefined;
            const bc = std.fmt.bufPrint(&bc_buf, "Functions {s} {s} {s} Code", .{ constants.SEP_ARROW, function_name, constants.SEP_ARROW }) catch bc_buf[0..0];

            return Self{
                .fg_color = fg_color,
                .bg_color = bg_color,
                .fetch_ctx = ctx,
                .alloc = allocator,
                .breadcrumb_buf = bc_buf,
                .breadcrumb_len = bc.len,
                .io = io,
                .credentials = credentials,
                .refresh_region = ref_region,
                .refresh_function_name = ref_name,
            };
        }

        pub fn breadcrumb(self: *Self) []const u8 {
            return self.breadcrumb_buf[0..self.breadcrumb_len];
        }

        pub fn deinit(self: *Self) void {
            if (self.matches.len > 0) self.alloc.free(self.matches);
            if (self.committed_filter) |f| self.alloc.free(f);
            self.fetch_ctx.thread.join();
            if (self.lines) |l| self.alloc.free(l);
            self.fetch_ctx.arena.deinit();
            self.alloc.destroy(self.fetch_ctx);
            self.alloc.free(self.refresh_region);
            self.alloc.free(self.refresh_function_name);
        }

        fn refresh(self: *Self) !void {
            if (!self.fetch_ctx.done.load(.acquire)) return;

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

            const alloc = self.fetch_ctx.allocator;

            self.fetch_ctx.thread.join();
            if (self.lines) |l| {
                self.alloc.free(l);
                self.lines = null;
            }
            self.fetch_ctx.arena.deinit();
            self.alloc.destroy(self.fetch_ctx);

            const new_ctx = try alloc.create(FetchCtx);
            errdefer alloc.destroy(new_ctx);
            new_ctx.* = .{
                .allocator = alloc,
                .arena = std.heap.ArenaAllocator.init(alloc),
                .io = self.io,
                .credentials = self.credentials,
                .region = undefined,
                .function_name = undefined,
                .thread = undefined,
                .done = std.atomic.Value(bool).init(false),
            };
            errdefer new_ctx.arena.deinit();

            const a = new_ctx.arena.allocator();
            new_ctx.region = try a.dupe(u8, self.refresh_region);
            new_ctx.function_name = try a.dupe(u8, self.refresh_function_name);

            new_ctx.thread = try std.Thread.spawn(.{}, fetchFn, .{new_ctx});
            self.fetch_ctx = new_ctx;
            self.scroll = 0;
        }

        pub fn handleEvent(self: *Self, event: Event, _: ViewContext) !Action {
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

        pub fn render(self: *Self, writer: *std.Io.Writer, size: Coord) !void {
            if (size.x < 4 or size.y < 2) return;
            const w: usize = @intCast(size.x);
            const h: usize = @intCast(size.y);
            const inner_w = w - 2;
            const data_rows = h - 1;

            const fetch_done = self.fetch_ctx.done.load(.acquire);

            const writeStatus = struct {
                fn call(sv: *Self, wr: *std.Io.Writer, iw: usize, dr: usize, msg: []const u8) !void {
                    for (0..dr) |row| {
                        try wr.writeAll(sv.fg_color);
                        try wr.writeAll(constants.VERTICAL);
                        try wr.writeAll(terminal.RESET);
                        if (row == 0) {
                            const shown = msg[0..@min(msg.len, iw)];
                            try wr.writeAll(shown);
                            for (shown.len..iw) |_| try wr.writeByte(' ');
                        } else {
                            for (0..iw) |_| try wr.writeByte(' ');
                        }
                        try wr.writeAll(sv.fg_color);
                        try wr.writeAll(constants.VERTICAL);
                        try wr.writeAll(terminal.RESET);
                        try wr.writeAll("\r\n");
                    }
                    try writeBottom(sv, wr, iw);
                }
            }.call;

            if (!fetch_done) {
                try writeStatus(self, writer, inner_w, data_rows, "Loading" ++ constants.ELLIPSES);
                return;
            }

            if (self.fetch_ctx.err) |e| {
                var buf: [128]u8 = undefined;
                const msg = std.fmt.bufPrint(&buf, "Error: {s}", .{@errorName(e)}) catch "Error";
                try writeStatus(self, writer, inner_w, data_rows, msg);
                return;
            }

            const body = self.fetch_ctx.body orelse "";
            const width_changed = self.last_lines_width != inner_w;
            if (self.lines == null or width_changed) {
                if (self.lines) |l| self.alloc.free(l);
                self.lines = try computeLines(self.alloc, body, inner_w);
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

            try writeBottom(self, writer, inner_w);
        }

        fn writeBottom(self: *Self, writer: *std.Io.Writer, inner_w: usize) !void {
            try writer.writeAll(self.fg_color);
            try writer.writeAll(constants.BOTTOM_LEFT);
            for (0..inner_w) |_| try writer.writeAll(constants.HORIZONTAL);
            try writer.writeAll(constants.BOTTOM_RIGHT);
            try writer.writeAll(terminal.RESET);
        }
    };
}

pub const LambdaContentView = LambdaContentViewGeneric(fetchThread);

// ============================================================================
// Tests
// ============================================================================

test "computeLines basic" {
    const allocator = std.testing.allocator;
    const lines = try computeLines(allocator, "hello\nworld\n", 80);
    defer allocator.free(lines);
    try std.testing.expectEqual(@as(usize, 3), lines.len);
    try std.testing.expectEqualStrings("hello", lines[0]);
    try std.testing.expectEqualStrings("world", lines[1]);
    try std.testing.expectEqualStrings("", lines[2]);
}

test "computeLines wrap" {
    const allocator = std.testing.allocator;
    const lines = try computeLines(allocator, "abcdef", 3);
    defer allocator.free(lines);
    try std.testing.expectEqual(@as(usize, 2), lines.len);
    try std.testing.expectEqualStrings("abc", lines[0]);
    try std.testing.expectEqualStrings("def", lines[1]);
}

test "computeLines crlf strip" {
    const allocator = std.testing.allocator;
    const lines = try computeLines(allocator, "hello\r\nworld", 80);
    defer allocator.free(lines);
    try std.testing.expectEqual(@as(usize, 2), lines.len);
    try std.testing.expectEqualStrings("hello", lines[0]);
}

test "findNextMatch basic" {
    try std.testing.expectEqual(@as(?usize, 6), findNextMatch("hello world", "world", 0));
}

test "findNextMatch case insensitive" {
    try std.testing.expectEqual(@as(?usize, 0), findNextMatch("Hello", "hello", 0));
}

test "findNextMatch not found" {
    try std.testing.expectEqual(@as(?usize, null), findNextMatch("hello", "xyz", 0));
}

test "findNextMatch start offset" {
    try std.testing.expectEqual(@as(?usize, 8), findNextMatch("aaa bbb aaa", "aaa", 3));
}
