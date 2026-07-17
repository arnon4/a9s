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
const Logs = @import("../../../sdk/clients/logs/client.zig");
const constants = @import("../../../ui/constants.zig");
const ConfirmView = @import("../../../ui/confirm.zig");
const content_mod = @import("../s3/object_content.zig");

pub const LogEventsView = @This();
pub const name: []const u8 = "Log Events";

const POLL_INTERVAL_MS: i64 = 5_000;
const TS_DISPLAY_W: usize = 19; // "YYYY-MM-DD HH:MM:SS"
const TS_COL_W: usize = 21; // " " + TS_DISPLAY_W + " "

// ─── Display line ─────────────────────────────────────────────────────────────

const DisplayLine = struct {
    ts: []const u8, // TS_DISPLAY_W chars or spaces (continuation rows)
    msg: []const u8, // sanitized message chunk
};

// ─── Event item ──────────────────────────────────────────────────────────────

const LogEventItem = struct {
    allocator: std.mem.Allocator,
    timestamp_ms: i64,
    message: []u8,

    pub fn deinit(self: LogEventItem) void {
        self.allocator.free(self.message);
    }
};

// ─── Fetch context ───────────────────────────────────────────────────────────

const FetchCtx = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    credentials: Credentials,
    region: []u8,
    log_group_name: []u8,
    log_stream_name: []u8,
    next_token: ?[]u8,
    thread: std.Thread = undefined,
    new_events: std.ArrayList(LogEventItem) = .empty,
    new_forward_token: ?[]u8 = null,
    done: std.atomic.Value(bool) = .init(false),
    err: ?anyerror = null,
};

fn fetchThread(ctx: *FetchCtx) void {
    defer {
        std.log.debug("log_events fetchThread: done group={s} stream={s} events={d} err={?}", .{ ctx.log_group_name, ctx.log_stream_name, ctx.new_events.items.len, ctx.err });
        ctx.done.store(true, .release);
        input.notify();
    }

    var client = Logs.Client.init(ctx.allocator, .{
        .region = ctx.region,
        .io = ctx.io,
        .credentials = ctx.credentials,
    }) catch |e| {
        ctx.err = e;
        return;
    };
    defer client.deinit();

    if (ctx.next_token == null) {
        // Initial load: two-phase.
        // Phase 1: anchor at tail (startFromHead=false, limit=1) — returns 0 events but gives
        //   nextForwardToken (absolute tail, for polling) and nextBackwardToken (last page of events).
        // Phase 2: fetch with nextBackwardToken to get the most recent events.
        std.log.debug("log_events fetchThread: start region={s} group={s} stream={s} (two-phase)", .{ ctx.region, ctx.log_group_name, ctx.log_stream_name });
        const anchor = client.getLogEvents(.{
            .log_group_name = ctx.log_group_name,
            .log_stream_name = ctx.log_stream_name,
            .start_from_head = false,
            .limit = 1,
        }) catch |e| {
            ctx.err = e;
            return;
        };

        // Dupe tokens before freeing anchor.
        const fwd_token: ?[]u8 = if (anchor.next_forward_token) |ft|
            ctx.allocator.dupe(u8, ft) catch null
        else
            null;
        const bwd_token: ?[]u8 = if (anchor.next_backward_token) |bt|
            ctx.allocator.dupe(u8, bt) catch null
        else
            null;
        anchor.deinit();

        ctx.new_forward_token = fwd_token;

        const bwd = bwd_token orelse {
            std.log.debug("log_events fetchThread: no backward token, stream empty", .{});
            return;
        };
        defer ctx.allocator.free(bwd);

        const result = client.getLogEvents(.{
            .log_group_name = ctx.log_group_name,
            .log_stream_name = ctx.log_stream_name,
            .next_token = bwd,
            .limit = 1000,
        }) catch |e| {
            ctx.err = e;
            return;
        };
        defer result.deinit();

        std.log.debug("log_events fetchThread: got {d} events from backward page fwd={?s}", .{ result.events.len, ctx.new_forward_token });

        for (result.events) |ev| {
            const msg = ctx.allocator.dupe(u8, ev.message) catch |e| {
                ctx.err = e;
                return;
            };
            ctx.new_events.append(ctx.allocator, .{
                .allocator = ctx.allocator,
                .timestamp_ms = ev.timestamp,
                .message = msg,
            }) catch |e| {
                ctx.allocator.free(msg);
                ctx.err = e;
                return;
            };
        }
        return;
    }

    // Polling: use next_token (forward token) directly.
    std.log.debug("log_events fetchThread: start region={s} group={s} stream={s} token={?s}", .{ ctx.region, ctx.log_group_name, ctx.log_stream_name, ctx.next_token });
    const result = client.getLogEvents(.{
        .log_group_name = ctx.log_group_name,
        .log_stream_name = ctx.log_stream_name,
        .next_token = ctx.next_token,
        .limit = 1000,
    }) catch |e| {
        ctx.err = e;
        return;
    };
    defer result.deinit();

    std.log.debug("log_events fetchThread: got {d} events fwd={?s}", .{ result.events.len, result.next_forward_token });

    for (result.events) |ev| {
        const msg = ctx.allocator.dupe(u8, ev.message) catch |e| {
            ctx.err = e;
            return;
        };
        ctx.new_events.append(ctx.allocator, .{
            .allocator = ctx.allocator,
            .timestamp_ms = ev.timestamp,
            .message = msg,
        }) catch |e| {
            ctx.allocator.free(msg);
            ctx.err = e;
            return;
        };
    }

    if (result.next_forward_token) |t| {
        ctx.new_forward_token = ctx.allocator.dupe(u8, t) catch null;
    }
}

fn destroyCtx(allocator: std.mem.Allocator, ctx: *FetchCtx) void {
    for (ctx.new_events.items) |item| item.deinit();
    ctx.new_events.deinit(allocator);
    if (ctx.new_forward_token) |t| allocator.free(t);
    allocator.free(ctx.region);
    allocator.free(ctx.log_group_name);
    allocator.free(ctx.log_stream_name);
    if (ctx.next_token) |t| allocator.free(t);
    allocator.destroy(ctx);
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn nowMs(io: std.Io) i64 {
    const ts = std.Io.Timestamp.now(io, .real);
    return @intCast(@divFloor(ts.nanoseconds, 1_000_000));
}

fn formatTs(buf: *[24]u8, ms: i64) []u8 {
    if (ms <= 0) return std.fmt.bufPrint(buf, "                   ", .{}) catch buf[0..0];
    const secs: u64 = @intCast(@divFloor(ms, 1000));
    const sec_in_min: u64 = secs % 60;
    const epoch_secs = std.time.epoch.EpochSeconds{ .secs = secs };
    const epoch_day = epoch_secs.getEpochDay();
    const day_secs = epoch_secs.getDaySeconds();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}", .{
        year_day.year,
        month_day.month.numeric(),
        month_day.day_index + 1,
        day_secs.getHoursIntoDay(),
        day_secs.getMinutesIntoHour(),
        sec_in_min,
    }) catch buf[0..0];
}

fn sanitizeMsg(a: std.mem.Allocator, raw: []const u8) ![]const u8 {
    const trimmed = std.mem.trimEnd(u8, raw, " \t\r\n");
    var buf: std.ArrayList(u8) = .empty;
    for (trimmed) |ch| {
        if (ch == '\t') {
            try buf.append(a, ' ');
        } else if (ch >= 0x20 or ch == 0) {
            try buf.append(a, ch);
        }
        // skip other control chars (\r, \n, etc.)
    }
    return buf.toOwnedSlice(a);
}

fn buildLines(a: std.mem.Allocator, events: []const LogEventItem, msg_content_w: usize) ![]const DisplayLine {
    const blank_ts = " " ** TS_DISPLAY_W;
    var list: std.ArrayList(DisplayLine) = .empty;

    for (events) |ev| {
        var ts_buf: [24]u8 = undefined;
        const ts_raw = formatTs(&ts_buf, ev.timestamp_ms);
        const ts = try a.dupe(u8, ts_raw);
        const msg = try sanitizeMsg(a, ev.message);

        const first_len = @min(msg.len, msg_content_w);
        try list.append(a, .{ .ts = ts, .msg = msg[0..first_len] });

        var pos: usize = first_len;
        while (pos < msg.len) {
            const end = @min(pos + msg_content_w, msg.len);
            try list.append(a, .{ .ts = blank_ts, .msg = msg[pos..end] });
            pos = end;
        }
    }

    return list.toOwnedSlice(a);
}

// ─── View fields ─────────────────────────────────────────────────────────────

allocator: std.mem.Allocator,
io: std.Io,
credentials: Credentials,
region: []u8,
log_group_name: []u8,
log_stream_name: []u8,
fg_color: []const u8,
bg_color: []const u8,
breadcrumb_buf: [512]u8 = undefined,
breadcrumb_len: usize = 0,

events: std.ArrayList(LogEventItem) = .empty,
next_forward_token: ?[]u8 = null,
fetch_ctx: ?*FetchCtx = null,
load_done: bool = false,
load_err: ?anyerror = null,
last_poll_ms: i64 = 0,

lines_arena: std.heap.ArenaAllocator,
lines: []const DisplayLine = &.{},
lines_event_count: usize = std.math.maxInt(usize),
lines_width: usize = 0,

scroll: usize = 0,
at_bottom: bool = true,
pending_g: bool = false,

committed_filter: ?[]u8 = null,
live_filter: []const u8 = "",
matches: []Match = &.{},
current_match: usize = 0,
last_match_query: [256]u8 = undefined,
last_match_query_len: usize = 0,

const Match = struct { line: usize, col: usize };

// ─── Init / deinit ───────────────────────────────────────────────────────────

pub fn init(
    allocator: std.mem.Allocator,
    io: std.Io,
    credentials: Credentials,
    region: []const u8,
    log_group_name: []const u8,
    log_stream_name: []const u8,
    color_support: terminal.ColorSupport,
    parent_breadcrumb: []const u8,
) !LogEventsView {
    const colors = colors_mod.red(color_support);

    const region_copy = try allocator.dupe(u8, region);
    errdefer allocator.free(region_copy);
    const group_copy = try allocator.dupe(u8, log_group_name);
    errdefer allocator.free(group_copy);
    const stream_copy = try allocator.dupe(u8, log_stream_name);
    errdefer allocator.free(stream_copy);

    // Spawn initial fetch
    const ctx = try allocator.create(FetchCtx);
    errdefer allocator.destroy(ctx);

    const ctx_region = try allocator.dupe(u8, region);
    errdefer allocator.free(ctx_region);
    const ctx_group = try allocator.dupe(u8, log_group_name);
    errdefer allocator.free(ctx_group);
    const ctx_stream = try allocator.dupe(u8, log_stream_name);
    errdefer allocator.free(ctx_stream);

    ctx.* = .{
        .allocator = allocator,
        .io = io,
        .credentials = credentials,
        .region = ctx_region,
        .log_group_name = ctx_group,
        .log_stream_name = ctx_stream,
        .next_token = null,
    };
    ctx.thread = try std.Thread.spawn(.{}, fetchThread, .{ctx});

    var bc_buf: [512]u8 = undefined;
    const bc = std.fmt.bufPrint(&bc_buf, "{s} {s} {s}", .{ parent_breadcrumb, constants.SEP_ARROW, log_stream_name }) catch bc_buf[0..0];

    return LogEventsView{
        .allocator = allocator,
        .io = io,
        .credentials = credentials,
        .region = region_copy,
        .log_group_name = group_copy,
        .log_stream_name = stream_copy,
        .fg_color = colors.fg,
        .bg_color = colors.bg,
        .breadcrumb_buf = bc_buf,
        .breadcrumb_len = bc.len,
        .fetch_ctx = ctx,
        .lines_arena = std.heap.ArenaAllocator.init(allocator),
        .last_poll_ms = nowMs(io),
    };
}

pub fn breadcrumb(self: *LogEventsView) []const u8 {
    return self.breadcrumb_buf[0..self.breadcrumb_len];
}

pub fn deinit(self: *LogEventsView) void {
    if (self.fetch_ctx) |ctx| {
        ctx.thread.join();
        destroyCtx(self.allocator, ctx);
    }
    for (self.events.items) |item| item.deinit();
    self.events.deinit(self.allocator);
    if (self.next_forward_token) |t| self.allocator.free(t);
    self.lines_arena.deinit();
    if (self.matches.len > 0) self.allocator.free(self.matches);
    if (self.committed_filter) |f| self.allocator.free(f);
    self.allocator.free(self.region);
    self.allocator.free(self.log_group_name);
    self.allocator.free(self.log_stream_name);
}

// ─── Filter helpers ──────────────────────────────────────────────────────────

fn effectiveFilter(self: *const LogEventsView) []const u8 {
    if (self.live_filter.len > 0) return self.live_filter;
    return self.committed_filter orelse "";
}

pub fn setLiveFilter(self: *LogEventsView, text: []const u8) void {
    self.live_filter = text;
}

pub fn commitFilter(self: *LogEventsView, text: []const u8) void {
    if (self.committed_filter) |f| self.allocator.free(f);
    self.committed_filter = if (text.len > 0) self.allocator.dupe(u8, text) catch null else null;
    self.live_filter = "";
}

// ─── Search helpers ──────────────────────────────────────────────────────────

fn recomputeMatches(self: *LogEventsView, query: []const u8) void {
    if (self.matches.len > 0) {
        self.allocator.free(self.matches);
        self.matches = &.{};
    }
    self.current_match = 0;
    if (query.len == 0) return;

    var list: std.ArrayList(Match) = .empty;
    for (self.lines, 0..) |dl, li| {
        var pos: usize = 0;
        while (content_mod.findNextMatch(dl.msg, query, pos)) |col| {
            list.append(self.allocator, .{ .line = li, .col = col }) catch break;
            pos = col + query.len;
        }
    }
    self.matches = list.toOwnedSlice(self.allocator) catch &.{};

    const qlen = @min(query.len, self.last_match_query.len);
    @memcpy(self.last_match_query[0..qlen], query[0..qlen]);
    self.last_match_query_len = qlen;

    if (self.matches.len > 0 and !self.at_bottom) {
        const line = self.matches[0].line;
        self.scroll = if (line >= 3) line - 3 else 0;
    }
}

// ─── Wake timer ──────────────────────────────────────────────────────────────

const WakeCtx = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
};

fn wakeThread(ctx: *WakeCtx) void {
    defer ctx.allocator.destroy(ctx);
    var futex = std.atomic.Value(u32).init(0);
    std.Io.futexWaitTimeout(ctx.io, u32, &futex.raw, 0, .{
        .duration = .{ .raw = .{ .nanoseconds = @as(u64, POLL_INTERVAL_MS) * std.time.ns_per_ms }, .clock = .real },
    }) catch {};
    input.notify();
}

fn scheduleWake(self: *LogEventsView) void {
    const ctx = self.allocator.create(WakeCtx) catch return;
    ctx.* = .{ .allocator = self.allocator, .io = self.io };
    const t = std.Thread.spawn(.{}, wakeThread, .{ctx}) catch {
        self.allocator.destroy(ctx);
        return;
    };
    t.detach();
}

// ─── Internal: merge completed fetch ─────────────────────────────────────────

fn mergeIfDone(self: *LogEventsView) void {
    const ctx = self.fetch_ctx orelse return;
    if (!ctx.done.load(.acquire)) return;

    if (ctx.err) |e| {
        if (!self.load_done) self.load_err = e;
    } else {
        for (ctx.new_events.items) |item| {
            self.events.append(self.allocator, item) catch {
                item.deinit();
            };
        }
        ctx.new_events.clearRetainingCapacity();

        if (self.next_forward_token) |t| self.allocator.free(t);
        self.next_forward_token = ctx.new_forward_token;
        ctx.new_forward_token = null;
    }

    self.load_done = true;
    self.last_poll_ms = nowMs(self.io);

    ctx.thread.join();
    destroyCtx(self.allocator, ctx);
    self.fetch_ctx = null;

    self.scheduleWake();
}

fn spawnPoll(self: *LogEventsView) void {
    if (self.fetch_ctx != null) return;
    const token = self.next_forward_token orelse return;

    const ctx = self.allocator.create(FetchCtx) catch return;

    const ctx_region = self.allocator.dupe(u8, self.region) catch {
        self.allocator.destroy(ctx);
        return;
    };
    const ctx_group = self.allocator.dupe(u8, self.log_group_name) catch {
        self.allocator.free(ctx_region);
        self.allocator.destroy(ctx);
        return;
    };
    const ctx_stream = self.allocator.dupe(u8, self.log_stream_name) catch {
        self.allocator.free(ctx_group);
        self.allocator.free(ctx_region);
        self.allocator.destroy(ctx);
        return;
    };
    const ctx_token = self.allocator.dupe(u8, token) catch {
        self.allocator.free(ctx_stream);
        self.allocator.free(ctx_group);
        self.allocator.free(ctx_region);
        self.allocator.destroy(ctx);
        return;
    };

    ctx.* = .{
        .allocator = self.allocator,
        .io = self.io,
        .credentials = self.credentials,
        .region = ctx_region,
        .log_group_name = ctx_group,
        .log_stream_name = ctx_stream,
        .next_token = ctx_token,
    };
    ctx.thread = std.Thread.spawn(.{}, fetchThread, .{ctx}) catch {
        destroyCtx(self.allocator, ctx);
        return;
    };
    self.fetch_ctx = ctx;
}

// ─── Lines rebuild ───────────────────────────────────────────────────────────

fn rebuildLines(self: *LogEventsView, inner_w: usize) void {
    if (self.matches.len > 0) {
        self.allocator.free(self.matches);
        self.matches = &.{};
    }
    self.last_match_query_len = 0;

    _ = self.lines_arena.reset(.retain_capacity);
    self.lines = &.{};

    // inner_w = TS_COL_W + 1(sep) + 1(space) + msg_content_w + 1(space)
    const msg_content_w: usize = if (inner_w > TS_COL_W + 3) inner_w - TS_COL_W - 3 else 1;
    const a = self.lines_arena.allocator();
    self.lines = buildLines(a, self.events.items, msg_content_w) catch &.{};
    self.lines_event_count = self.events.items.len;
    self.lines_width = inner_w;
}

// ─── Manual refresh ──────────────────────────────────────────────────────────

fn refresh(self: *LogEventsView) !void {
    if (self.fetch_ctx) |ctx| {
        ctx.thread.join();
        destroyCtx(self.allocator, ctx);
        self.fetch_ctx = null;
    }

    for (self.events.items) |item| item.deinit();
    self.events.clearRetainingCapacity();

    if (self.next_forward_token) |t| self.allocator.free(t);
    self.next_forward_token = null;

    if (self.matches.len > 0) {
        self.allocator.free(self.matches);
        self.matches = &.{};
    }
    self.last_match_query_len = 0;
    _ = self.lines_arena.reset(.retain_capacity);
    self.lines = &.{};
    self.lines_event_count = std.math.maxInt(usize);
    self.lines_width = 0;

    self.load_done = false;
    self.load_err = null;
    self.scroll = 0;
    self.at_bottom = true;
    self.pending_g = false;

    const ctx = try self.allocator.create(FetchCtx);
    errdefer self.allocator.destroy(ctx);
    const ctx_region = try self.allocator.dupe(u8, self.region);
    errdefer self.allocator.free(ctx_region);
    const ctx_group = try self.allocator.dupe(u8, self.log_group_name);
    errdefer self.allocator.free(ctx_group);
    const ctx_stream = try self.allocator.dupe(u8, self.log_stream_name);
    errdefer self.allocator.free(ctx_stream);

    ctx.* = .{
        .allocator = self.allocator,
        .io = self.io,
        .credentials = self.credentials,
        .region = ctx_region,
        .log_group_name = ctx_group,
        .log_stream_name = ctx_stream,
        .next_token = null,
    };
    ctx.thread = try std.Thread.spawn(.{}, fetchThread, .{ctx});
    self.fetch_ctx = ctx;
    self.last_poll_ms = nowMs(self.io);
}

// ─── Event handling ──────────────────────────────────────────────────────────

pub fn handleEvent(self: *LogEventsView, event: Event, _: ViewContext) !Action {
    switch (event) {
        .key => |k| switch (k) {
            .ctrl_c => return .quit,
            .char => |c| switch (c) {
                'q' => return .{ .push = .{ .confirm = ConfirmView.init(self.fg_color, self.bg_color) } },
                'r' => self.refresh() catch {},
                'j' => {
                    self.scroll += 1;
                    self.at_bottom = false;
                },
                'k' => if (self.scroll > 0) {
                    self.scroll -= 1;
                    self.at_bottom = false;
                },
                'n' => if (self.matches.len > 0) {
                    self.current_match = (self.current_match + 1) % self.matches.len;
                    const line = self.matches[self.current_match].line;
                    self.scroll = if (line >= 3) line - 3 else 0;
                    self.at_bottom = false;
                },
                'N' => if (self.matches.len > 0) {
                    self.current_match = (self.current_match + self.matches.len - 1) % self.matches.len;
                    const line = self.matches[self.current_match].line;
                    self.scroll = if (line >= 3) line - 3 else 0;
                    self.at_bottom = false;
                },
                'g' => {
                    if (self.pending_g) {
                        self.scroll = 0;
                        self.at_bottom = false;
                        self.pending_g = false;
                    } else {
                        self.pending_g = true;
                    }
                },
                'G' => {
                    self.pending_g = false;
                    self.scroll = std.math.maxInt(usize) / 2;
                    self.at_bottom = true;
                },
                else => {
                    self.pending_g = false;
                },
            },
            .down => {
                self.scroll += 1;
                self.at_bottom = false;
            },
            .up => if (self.scroll > 0) {
                self.scroll -= 1;
                self.at_bottom = false;
            },
            .escape => {
                if (self.committed_filter != null) {
                    if (self.committed_filter) |f| self.allocator.free(f);
                    self.committed_filter = null;
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

pub fn render(self: *LogEventsView, writer: *std.Io.Writer, size: Coord) !void {
    if (size.x < 10 or size.y < 4) return;
    const w: usize = @intCast(size.x);
    const h: usize = @intCast(size.y);
    const inner_w = w - 2;
    const show_header = h >= 5;
    const data_rows = if (show_header) h - 3 else h - 1;

    // msg column: inner_w = TS_COL_W + 1(sep) + 1(lpad) + msg_content_w + 1(rpad)
    const msg_col_w = if (inner_w > TS_COL_W + 1) inner_w - TS_COL_W - 1 else 2;
    const msg_content_w = if (msg_col_w >= 2) msg_col_w - 2 else 0;

    // Merge completed fetch
    self.mergeIfDone();

    // Trigger poll if enough time has passed
    if (self.load_done and self.fetch_ctx == null) {
        const now = nowMs(self.io);
        if (now - self.last_poll_ms >= POLL_INTERVAL_MS) {
            self.spawnPoll();
        }
    }

    // Show loading/error states before initial load completes
    if (!self.load_done) {
        const msg = if (self.load_err) |e| blk: {
            var buf: [64]u8 = undefined;
            break :blk std.fmt.bufPrint(&buf, "Error: {s}", .{@errorName(e)}) catch "Error";
        } else "Loading" ++ constants.ELLIPSES;
        try writeStatusFrame(self, writer, inner_w, h - 1, msg);
        return;
    }
    if (self.load_err != null and self.events.items.len == 0) {
        var buf: [64]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "Error: {s}", .{@errorName(self.load_err.?)}) catch "Error";
        try writeStatusFrame(self, writer, inner_w, h - 1, msg);
        return;
    }
    if (self.events.items.len == 0) {
        try writeStatusFrame(self, writer, inner_w, h - 1, "No events found");
        return;
    }

    // Rebuild lines if events changed or width changed
    const prev_count = self.lines.len;
    if (self.lines_event_count != self.events.items.len or self.lines_width != inner_w) {
        self.rebuildLines(inner_w);
    }
    const new_count = self.lines.len;

    // Recompute matches if query changed
    const query = self.effectiveFilter();
    const cached_query = self.last_match_query[0..self.last_match_query_len];
    if (!std.mem.eql(u8, query, cached_query)) {
        self.recomputeMatches(query);
    }

    // Auto-scroll to bottom if new lines arrived and we were at bottom
    if (self.at_bottom and new_count > prev_count) {
        self.scroll = if (new_count > data_rows) new_count - data_rows else 0;
    }

    // Clamp scroll
    if (new_count > 0 and data_rows > 0 and self.scroll + data_rows > new_count) {
        self.scroll = if (new_count > data_rows) new_count - data_rows else 0;
    }

    // Update at_bottom for next frame
    self.at_bottom = new_count == 0 or (data_rows >= new_count) or (self.scroll + data_rows >= new_count);

    // Header
    if (show_header) {
        try writeHeaderRow(self, writer, msg_col_w);
        try writer.writeAll("\r\n");
        try writeSepRow(self, writer, inner_w, false);
        try writer.writeAll("\r\n");
    }

    // Data rows
    for (0..data_rows) |row| {
        try writer.writeAll(self.fg_color);
        try writer.writeAll(constants.VERTICAL);
        try writer.writeAll(terminal.RESET);

        const idx = self.scroll + row;
        if (idx < self.lines.len) {
            const dl = self.lines[idx];

            // Timestamp column: " ts " (TS_COL_W chars)
            try writer.writeByte(' ');
            const ts_shown = dl.ts[0..@min(dl.ts.len, TS_DISPLAY_W)];
            try writer.writeAll(ts_shown);
            for (ts_shown.len..TS_DISPLAY_W) |_| try writer.writeByte(' ');
            try writer.writeByte(' ');

            // Separator
            try writer.writeAll(self.fg_color);
            try writer.writeAll(constants.VERTICAL);
            try writer.writeAll(terminal.RESET);

            // Message column: " msg... " (msg_col_w chars)
            try writer.writeByte(' ');
            const written = if (query.len > 0) blk: {
                var lm_buf: [64]content_mod.LineMatch = undefined;
                var lm_n: usize = 0;
                for (self.matches, 0..) |m, mi| {
                    if (m.line == idx and lm_n < lm_buf.len) {
                        lm_buf[lm_n] = .{ .col = m.col, .is_current = mi == self.current_match };
                        lm_n += 1;
                    }
                }
                break :blk try content_mod.writeLineHighlighted(writer, dl.msg, query.len, lm_buf[0..lm_n], self.bg_color);
            } else blk: {
                try writer.writeAll(dl.msg);
                break :blk dl.msg.len;
            };
            for (written..msg_content_w) |_| try writer.writeByte(' ');
            try writer.writeByte(' ');
        } else {
            for (0..TS_COL_W) |_| try writer.writeByte(' ');
            try writer.writeAll(self.fg_color);
            try writer.writeAll(constants.VERTICAL);
            try writer.writeAll(terminal.RESET);
            for (0..msg_col_w) |_| try writer.writeByte(' ');
        }

        try writer.writeAll(self.fg_color);
        try writer.writeAll(constants.VERTICAL);
        try writer.writeAll(terminal.RESET);
        try writer.writeAll("\r\n");
    }

    // Bottom border
    try writeSepRow(self, writer, inner_w, true);
}

fn writeHeaderRow(self: *LogEventsView, writer: *std.Io.Writer, msg_col_w: usize) !void {
    try writer.writeAll(self.fg_color);
    try writer.writeAll(constants.VERTICAL);
    try writer.writeAll(terminal.RESET);
    try writeHeaderCell(self, writer, "TIMESTAMP", TS_COL_W);
    try writer.writeAll(self.fg_color);
    try writer.writeAll(constants.VERTICAL);
    try writer.writeAll(terminal.RESET);
    try writeHeaderCell(self, writer, "MESSAGE", msg_col_w);
    try writer.writeAll(self.fg_color);
    try writer.writeAll(constants.VERTICAL);
    try writer.writeAll(terminal.RESET);
}

fn writeHeaderCell(self: *LogEventsView, writer: *std.Io.Writer, text: []const u8, cell_w: usize) !void {
    const content_w = if (cell_w >= 2) cell_w - 2 else 0;
    const text_len = @min(text.len, content_w);
    const pad = if (content_w > text_len) content_w - text_len else 0;
    const left_pad = pad / 2;
    const right_pad = pad - left_pad;
    try writer.writeByte(' ');
    try writer.writeAll(self.bg_color);
    try writer.writeAll(terminal.FG_BLACK);
    for (0..left_pad) |_| try writer.writeByte(' ');
    try writer.writeAll(text[0..text_len]);
    for (0..right_pad) |_| try writer.writeByte(' ');
    try writer.writeAll(terminal.RESET);
    try writer.writeByte(' ');
}

fn writeSepRow(self: *LogEventsView, writer: *std.Io.Writer, inner_w: usize, bottom: bool) !void {
    const left = if (bottom) constants.BOTTOM_LEFT else constants.LEFT_T;
    const mid = if (bottom) constants.BOTTOM_T else constants.CROSS;
    const right = if (bottom) constants.BOTTOM_RIGHT else constants.RIGHT_T;
    try writer.writeAll(self.fg_color);
    try writer.writeAll(left);
    for (0..TS_COL_W) |_| try writer.writeAll(constants.HORIZONTAL);
    try writer.writeAll(mid);
    const msg_col_w = if (inner_w > TS_COL_W + 1) inner_w - TS_COL_W - 1 else 0;
    for (0..msg_col_w) |_| try writer.writeAll(constants.HORIZONTAL);
    try writer.writeAll(right);
    try writer.writeAll(terminal.RESET);
}

fn writeStatusFrame(self: *LogEventsView, writer: *std.Io.Writer, inner_w: usize, data_rows: usize, msg: []const u8) !void {
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
    try writer.writeAll(self.fg_color);
    try writer.writeAll(constants.BOTTOM_LEFT);
    for (0..inner_w) |_| try writer.writeAll(constants.HORIZONTAL);
    try writer.writeAll(constants.BOTTOM_RIGHT);
    try writer.writeAll(terminal.RESET);
}
