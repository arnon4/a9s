const std = @import("std");
const colors_mod = @import("../../../ui/colors.zig");
const format_mod = @import("../../../ui/format.zig");
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
const filter_mod = @import("../../../commands/filter.zig");
const LogEventsView = @import("log_events.zig").LogEventsView;

const LogStreamsView = @This();
pub const name: []const u8 = "Log Streams";

const POLL_INTERVAL_MS: i64 = 5_000;
const LAST_EVENT_W: usize = 18;
const STORED_W: usize = 12;

const Mode = enum {
    wide, // >=90: Name | Last Event | Stored
    medium, // >=60: Name | Last Event
    compact, // <60:  Name
};

// ─── Local item ──────────────────────────────────────────────────────────────

const LogStreamItem = struct {
    allocator: std.mem.Allocator,
    name: []u8,
    last_event_ms: ?i64,
    stored_bytes: i64,

    pub fn deinit(self: LogStreamItem) void {
        self.allocator.free(self.name);
    }
};

fn streamToItem(allocator: std.mem.Allocator, s: Logs.LogStream) !LogStreamItem {
    const item_name = try allocator.dupe(u8, s.log_stream_name);
    return .{
        .allocator = allocator,
        .name = item_name,
        .last_event_ms = s.last_event_timestamp,
        .stored_bytes = s.stored_bytes,
    };
}

fn nowMs(io: std.Io) i64 {
    const ts = std.Io.Timestamp.now(io, .real);
    return @intCast(@divFloor(ts.nanoseconds, 1_000_000));
}

fn formatTimestampMs(buf: []u8, ms: i64) []u8 {
    if (ms <= 0) return std.fmt.bufPrint(buf, "-", .{}) catch buf[0..0];
    const secs: u64 = @intCast(@divFloor(ms, 1000));
    const epoch_secs = std.time.epoch.EpochSeconds{ .secs = secs };
    const epoch_day = epoch_secs.getEpochDay();
    const day_secs = epoch_secs.getDaySeconds();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}", .{
        year_day.year,
        month_day.month.numeric(),
        month_day.day_index + 1,
        day_secs.getHoursIntoDay(),
        day_secs.getMinutesIntoHour(),
    }) catch buf[0..0];
}

// ─── Concurrency ─────────────────────────────────────────────────────────────

const LoadCtx = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    credentials: Credentials,
    log_group_name: []u8,
    region: []u8,
    mutex: std.atomic.Mutex = .unlocked,
    items: std.ArrayList(LogStreamItem) = .empty,
    done: std.atomic.Value(bool) = .init(false),
    thread: std.Thread = undefined,
    err: ?anyerror = null,
};

const State = union(enum) {
    active: *LoadCtx,
    failed: anyerror,
};

fn fetchThread(ctx: *LoadCtx) void {
    std.log.debug("log_streams fetchThread: start group={s}", .{ctx.log_group_name});
    defer {
        std.log.debug("log_streams fetchThread: done group={s} items={d} err={?}", .{ ctx.log_group_name, ctx.items.items.len, ctx.err });
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

    var next_token: ?[]u8 = null;
    defer if (next_token) |t| ctx.allocator.free(t);

    while (true) {
        const result = client.describeLogStreams(.{
            .log_group_name = ctx.log_group_name,
            .order_by = .last_event_time,
            .descending = true,
            .next_token = next_token,
        }) catch |e| {
            ctx.err = e;
            return;
        };
        defer result.deinit();

        if (next_token) |t| ctx.allocator.free(t);
        next_token = if (result.next_token) |t|
            ctx.allocator.dupe(u8, t) catch |e| {
                ctx.err = e;
                return;
            }
        else
            null;

        const is_last = result.next_token == null;

        lockMutex(&ctx.mutex);
        for (result.log_streams) |s| {
            const item = streamToItem(ctx.allocator, s) catch |e| {
                ctx.mutex.unlock();
                ctx.err = e;
                return;
            };
            ctx.items.append(ctx.allocator, item) catch |e| {
                item.deinit();
                ctx.mutex.unlock();
                ctx.err = e;
                return;
            };
        }
        ctx.mutex.unlock();

        if (is_last) break;
        input.notify();
    }
}

fn lockMutex(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

fn deinitLoadCtx(alloc: std.mem.Allocator, ctx: *LoadCtx) void {
    ctx.thread.join();
    for (ctx.items.items) |item| item.deinit();
    ctx.items.deinit(alloc);
    alloc.free(ctx.log_group_name);
    alloc.free(ctx.region);
    alloc.destroy(ctx);
}

// ─── Wake timer ──────────────────────────────────────────────────────────────

const WakeCtx = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    alive: *std.atomic.Value(bool),
};

fn wakeThread(ctx: *WakeCtx) void {
    const allocator = ctx.allocator;
    const io = ctx.io;
    const alive = ctx.alive;
    allocator.destroy(ctx);

    var futex = std.atomic.Value(u32).init(0);
    std.log.debug("log_streams wakeThread: sleeping {}ms", .{POLL_INTERVAL_MS});
    std.Io.futexWaitTimeout(io, u32, &futex.raw, 0, .{
        .duration = .{ .raw = .{ .nanoseconds = @as(u64, POLL_INTERVAL_MS) * std.time.ns_per_ms }, .clock = .real },
    }) catch {};

    std.log.debug("log_streams wakeThread: alive={}", .{alive.load(.acquire)});
    if (!alive.load(.acquire)) {
        allocator.destroy(alive);
        return;
    }

    // Reschedule before notifying — chain lives regardless of which view is active.
    const next = allocator.create(WakeCtx) catch {
        allocator.destroy(alive);
        input.notify();
        return;
    };
    next.* = .{ .allocator = allocator, .io = io, .alive = alive };
    const t = std.Thread.spawn(.{}, wakeThread, .{next}) catch {
        allocator.destroy(next);
        allocator.destroy(alive);
        input.notify();
        return;
    };
    t.detach();

    std.log.debug("log_streams wakeThread: firing notify", .{});
    input.notify();
}

// ─── Sort ────────────────────────────────────────────────────────────────────

pub const SortKey = enum { name, last_event, stored };

const SortCtx = struct {
    items: []const LogStreamItem,
    keys: []const SortKey,
    dir: constants.SortDir,

    fn lessThan(ctx: @This(), a: usize, b: usize) bool {
        for (ctx.keys) |key| {
            const ord = compareField(ctx.items[a], ctx.items[b], key);
            if (ord != .eq) return if (ctx.dir == .asc) ord == .lt else ord == .gt;
        }
        return false;
    }
};

fn compareField(a: LogStreamItem, b: LogStreamItem, key: SortKey) std.math.Order {
    return switch (key) {
        .name => std.mem.order(u8, a.name, b.name),
        .last_event => std.math.order(a.last_event_ms orelse -1, b.last_event_ms orelse -1),
        .stored => std.math.order(a.stored_bytes, b.stored_bytes),
    };
}

// ─── Filter ──────────────────────────────────────────────────────────────────

const ItemResolver = struct {
    item: LogStreamItem,

    pub fn resolve(self: ItemResolver, field: []const u8) filter_mod.FieldValue {
        if (std.mem.eql(u8, field, "name")) return .{ .string = self.item.name };
        return .unknown;
    }
};

// ─── View fields ─────────────────────────────────────────────────────────────

fg_color: []const u8,
bg_color: []const u8,
state: State,
selected: usize = 0,
scroll_offset: usize = 0,
pending_g: bool = false,
alloc: std.mem.Allocator,
io: std.Io,
credentials: Credentials,
region: []u8,
log_group_name_buf: [512]u8 = undefined,
log_group_name_len: usize = 0,
committed_filter: ?[]u8 = null,
live_filter: []const u8 = "",
filter_expr: ?filter_mod.ParseResult = null,
sort_keys: [3]SortKey = .{ .last_event, undefined, undefined },
sort_keys_len: usize = 1,
sort_dir: constants.SortDir = .desc,
sorted_indices: []usize = &.{},
last_sorted_len: usize = 0,
sort_dirty: bool = false,
sort_applied: bool = false,
last_poll_ms: i64 = 0,
refresh_ctx: ?*LoadCtx = null,
wake_alive: *std.atomic.Value(bool) = undefined,
breadcrumb_buf: [576]u8 = undefined,
breadcrumb_len: usize = 0,

// ─── Init / deinit ───────────────────────────────────────────────────────────

pub fn init(
    allocator: std.mem.Allocator,
    io: std.Io,
    credentials: Credentials,
    region: []const u8,
    log_group_name: []const u8,
    color_support: terminal.ColorSupport,
    parent_breadcrumb: []const u8,
) !LogStreamsView {
    const colors = colors_mod.red(color_support);

    const ctx = try allocator.create(LoadCtx);
    errdefer allocator.destroy(ctx);

    const view_region = try allocator.dupe(u8, region);
    errdefer allocator.free(view_region);

    const ctx_region = try allocator.dupe(u8, region);
    errdefer allocator.free(ctx_region);

    const name_copy = try allocator.dupe(u8, log_group_name);
    errdefer allocator.free(name_copy);

    ctx.* = .{
        .allocator = allocator,
        .io = io,
        .credentials = credentials,
        .log_group_name = name_copy,
        .region = ctx_region,
    };

    ctx.thread = try std.Thread.spawn(.{}, fetchThread, .{ctx});

    const alive = try allocator.create(std.atomic.Value(bool));
    alive.* = .init(true);

    var view = LogStreamsView{
        .fg_color = colors.fg,
        .bg_color = colors.bg,
        .state = .{ .active = ctx },
        .alloc = allocator,
        .io = io,
        .credentials = credentials,
        .region = view_region,
        .last_poll_ms = nowMs(io),
        .wake_alive = alive,
    };

    const len = @min(log_group_name.len, view.log_group_name_buf.len);
    @memcpy(view.log_group_name_buf[0..len], log_group_name[0..len]);
    view.log_group_name_len = len;

    const bc = std.fmt.bufPrint(&view.breadcrumb_buf, "{s} {s} {s}", .{ parent_breadcrumb, constants.SEP_ARROW, log_group_name }) catch view.breadcrumb_buf[0..0];
    view.breadcrumb_len = bc.len;

    view.scheduleWake();
    return view;
}

pub fn breadcrumb(self: *LogStreamsView) []const u8 {
    return self.breadcrumb_buf[0..self.breadcrumb_len];
}

pub fn deinit(self: *LogStreamsView) void {
    self.wake_alive.store(false, .release);
    self.alloc.free(self.region);
    if (self.refresh_ctx) |rctx| deinitLoadCtx(self.alloc, rctx);
    if (self.committed_filter) |f| self.alloc.free(f);
    if (self.filter_expr) |*fe| fe.deinit();
    if (self.sorted_indices.len > 0) self.alloc.free(self.sorted_indices);
    switch (self.state) {
        .active => |ctx| deinitLoadCtx(self.alloc, ctx),
        .failed => {},
    }
}

// ─── Filter helpers ──────────────────────────────────────────────────────────

fn effectiveFilter(self: *const LogStreamsView) []const u8 {
    return if (self.live_filter.len > 0) self.live_filter else self.committed_filter orelse "";
}

fn matchesItem(self: *const LogStreamsView, item: LogStreamItem, text_f: []const u8) bool {
    if (!filter_mod.matchesText(item.name, text_f)) return false;
    if (self.filter_expr) |*fe| {
        const resolver = ItemResolver{ .item = item };
        if (!filter_mod.evalExpr(fe.expr, resolver)) return false;
    }
    return true;
}

fn visibleCount(self: *const LogStreamsView, items: []const LogStreamItem, text_f: []const u8) usize {
    var n: usize = 0;
    for (items) |item| {
        if (self.matchesItem(item, text_f)) n += 1;
    }
    return n;
}

pub fn setLiveFilter(self: *LogStreamsView, text: []const u8) void {
    if (!std.mem.eql(u8, self.live_filter, text)) {
        self.selected = 0;
        self.scroll_offset = 0;
    }
    self.live_filter = text;
}

pub fn commitFilter(self: *LogStreamsView, text: []const u8) void {
    if (self.committed_filter) |f| self.alloc.free(f);
    self.committed_filter = if (text.len == 0) null else self.alloc.dupe(u8, text) catch null;
    self.live_filter = "";
    self.selected = 0;
    self.scroll_offset = 0;
}

pub fn setFilterExpr(self: *LogStreamsView, result: filter_mod.ParseResult) void {
    if (self.filter_expr) |*fe| fe.deinit();
    self.filter_expr = result;
    self.selected = 0;
    self.scroll_offset = 0;
}

pub fn clearFilterExpr(self: *LogStreamsView) void {
    if (self.filter_expr) |*fe| fe.deinit();
    self.filter_expr = null;
    self.selected = 0;
    self.scroll_offset = 0;
}

// ─── Sort helpers ─────────────────────────────────────────────────────────────

fn recomputeSort(self: *LogStreamsView, items: []const LogStreamItem) void {
    if (self.sorted_indices.len > 0) {
        self.alloc.free(self.sorted_indices);
        self.sorted_indices = &.{};
    }
    const indices = self.alloc.alloc(usize, items.len) catch return;
    for (indices, 0..) |*idx, i| idx.* = i;
    std.mem.sortUnstable(usize, indices, SortCtx{
        .items = items,
        .keys = self.sort_keys[0..self.sort_keys_len],
        .dir = self.sort_dir,
    }, SortCtx.lessThan);
    self.sorted_indices = indices;
    self.last_sorted_len = items.len;
}

fn ensureSorted(self: *LogStreamsView, items: []const LogStreamItem) void {
    if (!self.sort_dirty and self.sorted_indices.len == items.len) return;
    self.recomputeSort(items);
    self.sort_dirty = false;
}

pub fn setSort(self: *LogStreamsView, keys: []const SortKey, dir: constants.SortDir) void {
    const n = @min(keys.len, self.sort_keys.len);
    @memcpy(self.sort_keys[0..n], keys[0..n]);
    self.sort_keys_len = if (n > 0) n else 1;
    self.sort_dir = dir;
    self.sort_dirty = true;
    self.sort_applied = true;
    self.selected = 0;
    self.scroll_offset = 0;
}

pub fn clearSort(self: *LogStreamsView) void {
    self.sort_keys[0] = .last_event;
    self.sort_keys_len = 1;
    self.sort_dir = .desc;
    self.sort_dirty = true;
    self.sort_applied = false;
    self.selected = 0;
    self.scroll_offset = 0;
}

// ─── Refresh ─────────────────────────────────────────────────────────────────

fn scheduleWake(self: *LogStreamsView) void {
    std.log.debug("log_streams scheduleWake: scheduling {}ms wake", .{POLL_INTERVAL_MS});
    const ctx = self.alloc.create(WakeCtx) catch |e| {
        std.log.debug("log_streams scheduleWake: alloc failed err={}", .{e});
        return;
    };
    ctx.* = .{ .allocator = self.alloc, .io = self.io, .alive = self.wake_alive };
    const t = std.Thread.spawn(.{}, wakeThread, .{ctx}) catch |e| {
        std.log.debug("log_streams scheduleWake: spawn failed err={}", .{e});
        self.alloc.destroy(ctx);
        return;
    };
    t.detach();
}

fn spawnRefresh(self: *LogStreamsView) void {
    std.log.debug("log_streams spawnRefresh: called refresh_ctx={} state={s}", .{ self.refresh_ctx != null, @tagName(self.state) });
    if (self.refresh_ctx != null) {
        std.log.debug("log_streams spawnRefresh: already running, skip", .{});
        return;
    }
    // Skip if initial fetch is still in progress.
    switch (self.state) {
        .active => |lctx| if (!lctx.done.load(.acquire)) {
            std.log.debug("log_streams spawnRefresh: initial fetch not done, skip", .{});
            return;
        },
        .failed => {}, // allow periodic refresh to retry after failure
    }

    const ctx = self.alloc.create(LoadCtx) catch return;
    const region_copy = self.alloc.dupe(u8, self.region) catch {
        self.alloc.destroy(ctx);
        return;
    };
    const name_copy = self.alloc.dupe(u8, self.log_group_name_buf[0..self.log_group_name_len]) catch {
        self.alloc.free(region_copy);
        self.alloc.destroy(ctx);
        return;
    };
    ctx.* = .{
        .allocator = self.alloc,
        .io = self.io,
        .credentials = self.credentials,
        .log_group_name = name_copy,
        .region = region_copy,
    };
    ctx.thread = std.Thread.spawn(.{}, fetchThread, .{ctx}) catch |e| {
        std.log.debug("log_streams spawnRefresh: thread spawn failed err={}", .{e});
        self.alloc.free(name_copy);
        self.alloc.free(region_copy);
        self.alloc.destroy(ctx);
        return;
    };
    std.log.debug("log_streams spawnRefresh: refresh thread spawned", .{});
    self.refresh_ctx = ctx;
}

// Merge refreshed stream list into existing list in-place.
// Updated streams get new timestamps; new streams are appended; deleted streams are removed.
// Scroll position is preserved since we don't replace the whole list.
fn mergeStreamItems(alloc: std.mem.Allocator, old: *std.ArrayList(LogStreamItem), new: *std.ArrayList(LogStreamItem)) void {
    const new_matched = alloc.alloc(bool, new.items.len) catch {
        // OOM fallback: full replace
        for (old.items) |item| item.deinit();
        old.deinit(alloc);
        old.* = new.*;
        new.* = .empty;
        return;
    };
    defer alloc.free(new_matched);
    @memset(new_matched, false);

    // Update existing streams; remove deleted ones.
    var i: usize = 0;
    while (i < old.items.len) {
        const old_item = &old.items[i];
        var found = false;
        for (new.items, 0..) |new_item, ni| {
            if (std.mem.eql(u8, old_item.name, new_item.name)) {
                old_item.last_event_ms = new_item.last_event_ms;
                old_item.stored_bytes = new_item.stored_bytes;
                new_matched[ni] = true;
                found = true;
                break;
            }
        }
        if (!found) {
            old_item.deinit();
            _ = old.swapRemove(i);
        } else {
            i += 1;
        }
    }

    // Append genuinely new streams; free matched new items (old already updated).
    for (new.items, 0..) |new_item, ni| {
        if (!new_matched[ni]) {
            old.append(alloc, new_item) catch new_item.deinit();
        } else {
            new_item.deinit();
        }
    }
    new.deinit(alloc);
    new.* = .empty;
}

fn mergeRefreshIfDone(self: *LogStreamsView) void {
    const rctx = self.refresh_ctx orelse return;
    if (!rctx.done.load(.acquire)) return;

    std.log.debug("log_streams mergeRefreshIfDone: refresh done items={d} err={?}", .{ rctx.items.items.len, rctx.err });

    rctx.thread.join();

    defer {
        for (rctx.items.items) |item| item.deinit();
        rctx.items.deinit(self.alloc);
        self.alloc.free(rctx.log_group_name);
        self.alloc.free(rctx.region);
        self.alloc.destroy(rctx);
        self.refresh_ctx = null;
        self.last_poll_ms = nowMs(self.io);
    }

    if (rctx.err) |e| {
        std.log.debug("log_streams mergeRefreshIfDone: refresh error {}, discarding", .{e});
        return;
    }

    const lctx: *LoadCtx = switch (self.state) {
        .active => |c| c,
        .failed => {
            std.log.debug("log_streams mergeRefreshIfDone: state=failed, discarding", .{});
            return;
        },
    };

    lockMutex(&lctx.mutex);
    const old_count = lctx.items.items.len;
    mergeStreamItems(self.alloc, &lctx.items, &rctx.items);
    self.sort_dirty = true;
    lctx.mutex.unlock();
    std.log.debug("log_streams mergeRefreshIfDone: merged old={d} -> new={d}", .{ old_count, lctx.items.items.len });
}

// ─── Manual refresh ──────────────────────────────────────────────────────────

fn refresh(self: *LogStreamsView) !void {
    // Cancel any in-flight periodic refresh.
    if (self.refresh_ctx) |rctx| {
        deinitLoadCtx(self.alloc, rctx);
        self.refresh_ctx = null;
    }

    if (self.sorted_indices.len > 0) {
        self.alloc.free(self.sorted_indices);
        self.sorted_indices = &.{};
    }
    self.last_sorted_len = 0;
    self.sort_dirty = true;

    // Allocate and spawn the new ctx BEFORE destroying old state so that a
    // spawn failure leaves self.state valid (no dangling .active pointer).
    const ctx = try self.alloc.create(LoadCtx);
    errdefer self.alloc.destroy(ctx);
    const ctx_region = try self.alloc.dupe(u8, self.region);
    errdefer self.alloc.free(ctx_region);
    const name_copy = try self.alloc.dupe(u8, self.log_group_name_buf[0..self.log_group_name_len]);
    errdefer self.alloc.free(name_copy);

    ctx.* = .{
        .allocator = self.alloc,
        .io = self.io,
        .credentials = self.credentials,
        .log_group_name = name_copy,
        .region = ctx_region,
    };
    ctx.thread = try std.Thread.spawn(.{}, fetchThread, .{ctx});

    // Spawn succeeded — safe to destroy old state now.
    switch (self.state) {
        .active => |old| deinitLoadCtx(self.alloc, old),
        .failed => {},
    }

    self.state = .{ .active = ctx };
    self.selected = 0;
    self.scroll_offset = 0;
    self.last_poll_ms = nowMs(self.io);
}

// ─── Event handling ──────────────────────────────────────────────────────────

fn selectedStreamName(self: *LogStreamsView, items: []const LogStreamItem) ?[]const u8 {
    const filter = self.effectiveFilter();
    var vis_idx: usize = 0;
    for (self.sorted_indices) |orig_idx| {
        const item = items[orig_idx];
        if (!self.matchesItem(item, filter)) continue;
        if (vis_idx == self.selected) return item.name;
        vis_idx += 1;
    }
    return null;
}

pub fn handleEvent(self: *LogStreamsView, event: Event, ctx: ViewContext) !Action {
    const count: usize = switch (self.state) {
        .active => |lctx| blk: {
            lockMutex(&lctx.mutex);
            defer lctx.mutex.unlock();
            break :blk self.visibleCount(lctx.items.items, self.effectiveFilter());
        },
        .failed => 0,
    };

    switch (event) {
        .key => |k| switch (k) {
            .ctrl_c => return .quit,
            .char => |c| switch (c) {
                'q' => return .{ .push = .{ .confirm = ConfirmView.init(self.fg_color, self.bg_color) } },
                'r' => self.refresh() catch {},
                'j' => if (count > 0 and self.selected < count - 1) {
                    self.selected += 1;
                },
                'k' => if (self.selected > 0) {
                    self.selected -= 1;
                },
                'g' => {
                    if (self.pending_g) {
                        self.selected = 0;
                        self.scroll_offset = 0;
                        self.pending_g = false;
                    } else {
                        self.pending_g = true;
                    }
                },
                'G' => {
                    self.pending_g = false;
                    if (count > 0) self.selected = count - 1;
                },
                else => {
                    self.pending_g = false;
                },
            },
            .down => if (count > 0 and self.selected < count - 1) {
                self.selected += 1;
            },
            .up => if (self.selected > 0) {
                self.selected -= 1;
            },
            .enter => switch (self.state) {
                .active => |lctx| {
                    lockMutex(&lctx.mutex);
                    self.ensureSorted(lctx.items.items);
                    const stream_name = self.selectedStreamName(lctx.items.items);
                    lctx.mutex.unlock();
                    if (stream_name) |sn| {
                        const v = try LogEventsView.init(
                            ctx.allocator,
                            ctx.io,
                            lctx.credentials,
                            lctx.region,
                            self.log_group_name_buf[0..self.log_group_name_len],
                            sn,
                            ctx.color_support,
                            self.breadcrumb(),
                        );
                        return .{ .push = .{ .logs_log_events = v } };
                    }
                },
                .failed => {},
            },
            .escape => {
                if (self.committed_filter) |f| {
                    self.alloc.free(f);
                    self.committed_filter = null;
                    self.selected = 0;
                    self.scroll_offset = 0;
                } else if (self.filter_expr != null) {
                    self.clearFilterExpr();
                } else if (self.sort_applied) {
                    self.clearSort();
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

fn modeFor(width: i16) Mode {
    if (width >= 90) return .wide;
    if (width >= 60) return .medium;
    return .compact;
}

fn nameWidth(inner: usize, mode: Mode) usize {
    const fixed: usize = switch (mode) {
        .wide => LAST_EVENT_W + STORED_W + 2,
        .medium => LAST_EVENT_W + 1,
        .compact => 0,
    };
    return if (inner > fixed + 2) inner - fixed else 2;
}

fn writePaddedCell(writer: *std.Io.Writer, text: []const u8, cell_w: usize) !void {
    const content_w = if (cell_w >= 2) cell_w - 2 else 0;
    try writer.writeByte(' ');
    const shown = if (text.len > content_w) text[0..content_w] else text;
    try writer.writeAll(shown);
    for (shown.len..content_w) |_| try writer.writeByte(' ');
    try writer.writeByte(' ');
}

fn writeVert(self: *LogStreamsView, writer: *std.Io.Writer, selected: bool, reset: bool) !void {
    if (selected) {
        try writer.writeAll(self.bg_color);
        try writer.writeAll(terminal.FG_BLACK);
    } else {
        try writer.writeAll(self.fg_color);
    }
    try writer.writeAll(constants.VERTICAL);
    if (reset) try writer.writeAll(terminal.RESET);
}

fn writeSepRow(self: *LogStreamsView, writer: *std.Io.Writer, name_w: usize, mode: Mode, bottom: bool) !void {
    const left = if (bottom) constants.BOTTOM_LEFT else constants.LEFT_T;
    const mid = if (bottom) constants.BOTTOM_T else constants.CROSS;
    const right = if (bottom) constants.BOTTOM_RIGHT else constants.RIGHT_T;

    try writer.writeAll(self.fg_color);
    try writer.writeAll(left);
    for (0..name_w) |_| try writer.writeAll(constants.HORIZONTAL);
    switch (mode) {
        .wide => {
            try writer.writeAll(mid);
            for (0..LAST_EVENT_W) |_| try writer.writeAll(constants.HORIZONTAL);
            try writer.writeAll(mid);
            for (0..STORED_W) |_| try writer.writeAll(constants.HORIZONTAL);
        },
        .medium => {
            try writer.writeAll(mid);
            for (0..LAST_EVENT_W) |_| try writer.writeAll(constants.HORIZONTAL);
        },
        .compact => {},
    }
    try writer.writeAll(right);
    try writer.writeAll(terminal.RESET);
}

fn writeHeaderCell(self: *LogStreamsView, writer: *std.Io.Writer, text: []const u8, cell_w: usize) !void {
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

fn writeHeaderRow(self: *LogStreamsView, writer: *std.Io.Writer, name_w: usize, mode: Mode) !void {
    try writer.writeAll(self.fg_color);
    try writer.writeAll(constants.VERTICAL);
    try writer.writeAll(terminal.RESET);
    try self.writeHeaderCell(writer, "NAME", name_w);
    switch (mode) {
        .wide => {
            try writer.writeAll(self.fg_color);
            try writer.writeAll(constants.VERTICAL);
            try writer.writeAll(terminal.RESET);
            try self.writeHeaderCell(writer, "LAST EVENT", LAST_EVENT_W);
            try writer.writeAll(self.fg_color);
            try writer.writeAll(constants.VERTICAL);
            try writer.writeAll(terminal.RESET);
            try self.writeHeaderCell(writer, "STORED", STORED_W);
        },
        .medium => {
            try writer.writeAll(self.fg_color);
            try writer.writeAll(constants.VERTICAL);
            try writer.writeAll(terminal.RESET);
            try self.writeHeaderCell(writer, "LAST EVENT", LAST_EVENT_W);
        },
        .compact => {},
    }
    try writer.writeAll(self.fg_color);
    try writer.writeAll(constants.VERTICAL);
    try writer.writeAll(terminal.RESET);
}

fn writeItemRow(self: *LogStreamsView, writer: *std.Io.Writer, item: LogStreamItem, sel: bool, name_w: usize, mode: Mode) !void {
    try self.writeVert(writer, sel, !sel);

    const content_w = if (name_w >= 2) name_w - 2 else 0;
    const max_name = if (content_w >= 2) content_w - 2 else 0;
    try writer.writeByte(' ');
    try writer.writeAll(if (sel) "▸ " else "  ");
    const shown_name = if (item.name.len > max_name) item.name[0..max_name] else item.name;
    try writer.writeAll(shown_name);
    for (shown_name.len..max_name) |_| try writer.writeByte(' ');
    try writer.writeByte(' ');

    switch (mode) {
        .wide => {
            var ts_buf: [20]u8 = undefined;
            const ts_str = formatTimestampMs(&ts_buf, item.last_event_ms orelse 0);
            try self.writeVert(writer, sel, !sel);
            try writePaddedCell(writer, ts_str, LAST_EVENT_W);
            try self.writeVert(writer, sel, !sel);
            var size_buf: [24]u8 = undefined;
            const size_str = format_mod.size(&size_buf, @intCast(@max(0, item.stored_bytes)));
            try writePaddedCell(writer, size_str, STORED_W);
        },
        .medium => {
            var ts_buf: [20]u8 = undefined;
            const ts_str = formatTimestampMs(&ts_buf, item.last_event_ms orelse 0);
            try self.writeVert(writer, sel, !sel);
            try writePaddedCell(writer, ts_str, LAST_EVENT_W);
        },
        .compact => {},
    }

    try self.writeVert(writer, sel, true);
}

fn writeEmptyRow(self: *LogStreamsView, writer: *std.Io.Writer, name_w: usize, mode: Mode) !void {
    try self.writeVert(writer, false, true);
    for (0..name_w) |_| try writer.writeByte(' ');
    switch (mode) {
        .wide => {
            try self.writeVert(writer, false, true);
            for (0..LAST_EVENT_W) |_| try writer.writeByte(' ');
            try self.writeVert(writer, false, true);
            for (0..STORED_W) |_| try writer.writeByte(' ');
        },
        .medium => {
            try self.writeVert(writer, false, true);
            for (0..LAST_EVENT_W) |_| try writer.writeByte(' ');
        },
        .compact => {},
    }
    try self.writeVert(writer, false, true);
}

pub fn render(self: *LogStreamsView, writer: *std.Io.Writer, size: Coord) !void {
    if (size.x < 10 or size.y < 4) return;
    const w: usize = @intCast(size.x);
    const h: usize = @intCast(size.y);
    const inner = w - 2;
    const mode = modeFor(size.x);
    const name_w = nameWidth(inner, mode);
    const show_header = h >= 6;
    const data_rows = if (show_header) h - 3 else h - 1;

    // Merge completed refresh and check timer.
    self.mergeRefreshIfDone();
    if (self.refresh_ctx == null) {
        const now = nowMs(self.io);
        if (now - self.last_poll_ms >= POLL_INTERVAL_MS) {
            self.spawnRefresh();
        }
    }

    // Transition active → failed once done with no items and an error.
    switch (self.state) {
        .active => |ctx| {
            if (ctx.done.load(.acquire)) {
                lockMutex(&ctx.mutex);
                const n = ctx.items.items.len;
                const err = ctx.err;
                ctx.mutex.unlock();
                if (n == 0) {
                    if (err) |e| {
                        ctx.thread.join();
                        self.alloc.free(ctx.log_group_name);
                        self.alloc.free(ctx.region);
                        for (ctx.items.items) |item| item.deinit();
                        ctx.items.deinit(self.alloc);
                        self.alloc.destroy(ctx);
                        self.state = .{ .failed = e };
                    }
                }
            }
        },
        .failed => {},
    }

    if (show_header) {
        try self.writeHeaderRow(writer, name_w, mode);
        try writer.writeAll("\r\n");
        try self.writeSepRow(writer, name_w, mode, false);
        try writer.writeAll("\r\n");
    }

    switch (self.state) {
        .active => |ctx| {
            lockMutex(&ctx.mutex);
            defer ctx.mutex.unlock();
            const items = ctx.items.items;
            const filter = self.effectiveFilter();
            const vis_total = self.visibleCount(items, filter);

            if (vis_total > 0) {
                if (self.selected >= vis_total) self.selected = vis_total - 1;
                if (self.selected < self.scroll_offset) self.scroll_offset = self.selected;
                if (data_rows > 0 and self.selected >= self.scroll_offset + data_rows)
                    self.scroll_offset = self.selected - data_rows + 1;
            } else {
                self.selected = 0;
                self.scroll_offset = 0;
            }
            self.ensureSorted(items);
            var vis_idx: usize = 0;
            var rendered: usize = 0;
            for (self.sorted_indices) |orig_idx| {
                const item = items[orig_idx];
                if (!self.matchesItem(item, filter)) continue;
                if (vis_idx >= self.scroll_offset and rendered < data_rows) {
                    try self.writeItemRow(writer, item, vis_idx == self.selected, name_w, mode);
                    try writer.writeAll("\r\n");
                    rendered += 1;
                }
                vis_idx += 1;
            }
            for (rendered..data_rows) |_| {
                try self.writeEmptyRow(writer, name_w, mode);
                try writer.writeAll("\r\n");
            }
        },
        .failed => |e| {
            for (0..data_rows) |row| {
                try self.writeVert(writer, false, true);
                if (row == 0) {
                    var buf: [128]u8 = undefined;
                    const msg = std.fmt.bufPrint(&buf, " Error: {s}", .{@errorName(e)}) catch " Error loading log streams";
                    const shown = if (msg.len > inner) msg[0..inner] else msg;
                    try writer.writeAll(shown);
                    for (shown.len..inner) |_| try writer.writeByte(' ');
                } else {
                    for (0..inner) |_| try writer.writeByte(' ');
                }
                try self.writeVert(writer, false, true);
                try writer.writeAll("\r\n");
            }
        },
    }

    try self.writeSepRow(writer, name_w, mode, true);
}
