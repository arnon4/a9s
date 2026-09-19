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
const CloudTrail = @import("../../../sdk/clients/cloudtrail/client.zig");
const constants = @import("../../../ui/constants.zig");
const ConfirmView = @import("../../../ui/confirm.zig");
const filter_mod = @import("../../../commands/filter.zig");
const EventDetailView = @import("event_detail.zig");

const EventsView = @This();
pub const name: []const u8 = "CloudTrail Events";

const TIME_W: usize = 21;
const USER_W: usize = 16;
const SOURCE_W: usize = 22;
const ACCOUNT_W: usize = 14;

const Mode = enum {
    wide, // >=120: Name | Time | User | Source | Account
    medium, //  >=70: Name | Time
    compact, //  <70: Name
};

// ─── Local item ──────────────────────────────────────────────────────────────

const EventItem = struct {
    allocator: std.mem.Allocator,
    event_name: []u8,
    event_time: ?f64,
    username: []u8,
    event_source: []u8,
    account_id: []u8,
    raw_event: []u8,

    pub fn deinit(self: EventItem) void {
        self.allocator.free(self.event_name);
        self.allocator.free(self.username);
        self.allocator.free(self.event_source);
        self.allocator.free(self.account_id);
        self.allocator.free(self.raw_event);
    }
};

fn eventToItem(allocator: std.mem.Allocator, e: CloudTrail.CloudTrailEvent) !EventItem {
    const event_name = try allocator.dupe(u8, e.event_name);
    errdefer allocator.free(event_name);

    const username = try allocator.dupe(u8, if (e.username.len > 0) e.username else "-");
    errdefer allocator.free(username);

    const event_source = try allocator.dupe(u8, e.event_source);
    errdefer allocator.free(event_source);

    const account_id = try allocator.dupe(u8, if (e.account_id.len > 0) e.account_id else "-");
    errdefer allocator.free(account_id);

    const raw_event = try allocator.dupe(u8, e.cloud_trail_event);
    errdefer allocator.free(raw_event);

    return .{
        .allocator = allocator,
        .event_name = event_name,
        .event_time = e.event_time,
        .username = username,
        .event_source = event_source,
        .account_id = account_id,
        .raw_event = raw_event,
    };
}

fn formatEpochSeconds(buf: []u8, secs_f: ?f64) []u8 {
    const secs_val = secs_f orelse return std.fmt.bufPrint(buf, "-", .{}) catch buf[0..0];
    if (secs_val <= 0) return std.fmt.bufPrint(buf, "-", .{}) catch buf[0..0];
    const secs: u64 = @intFromFloat(secs_val);
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
        day_secs.getSecondsIntoMinute(),
    }) catch buf[0..0];
}

// ─── Concurrency ─────────────────────────────────────────────────────────────

const LoadCtx = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    credentials: Credentials,
    region: []u8,
    mutex: std.atomic.Mutex = .unlocked,
    items: std.ArrayList(EventItem) = .empty,
    done: std.atomic.Value(bool) = .init(false),
    /// Set by the view when it's torn down mid-fetch, so the background thread
    /// stops paginating instead of walking the account's entire event history
    /// (LookupEvents defaults to a 90-day lookback) — otherwise `deinit`'s
    /// `thread.join()` blocks the whole UI, including Ctrl+C, until it finishes.
    cancel: std.atomic.Value(bool) = .init(false),
    thread: std.Thread = undefined,
    err: ?anyerror = null,
};

/// How far back to look up events. Bounds pagination for busy accounts —
/// LookupEvents defaults to the full 90-day history otherwise.
const LOOKBACK_SECONDS: i64 = 24 * 3600;

const State = union(enum) {
    active: *LoadCtx,
    failed: anyerror,
};

fn fetchThread(ctx: *LoadCtx) void {
    defer {
        ctx.done.store(true, .release);
        input.notify();
    }

    var client = CloudTrail.Client.init(ctx.allocator, .{
        .region = ctx.region,
        .io = ctx.io,
        .credentials = ctx.credentials,
    }) catch |e| {
        ctx.err = e;
        return;
    };
    defer client.deinit();

    const now: i64 = @intCast(@divFloor(std.Io.Timestamp.now(ctx.io, .real).nanoseconds, std.time.ns_per_s));
    const start_time = now - LOOKBACK_SECONDS;

    var next_token: ?[]u8 = null;
    defer if (next_token) |t| ctx.allocator.free(t);

    while (true) {
        if (ctx.cancel.load(.acquire)) return;

        const result = client.lookupEvents(.{
            .next_token = next_token,
            .max_results = 50,
            .start_time = start_time,
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
        for (result.events) |e| {
            const item = eventToItem(ctx.allocator, e) catch |err| {
                ctx.mutex.unlock();
                ctx.err = err;
                return;
            };
            ctx.items.append(ctx.allocator, item) catch |err| {
                item.deinit();
                ctx.mutex.unlock();
                ctx.err = err;
                return;
            };
        }
        ctx.mutex.unlock();
        input.notify();

        if (is_last) break;
    }
}

fn lockMutex(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

fn deinitLoadCtx(alloc: std.mem.Allocator, ctx: *LoadCtx) void {
    ctx.cancel.store(true, .release);
    ctx.thread.join();
    for (ctx.items.items) |item| item.deinit();
    ctx.items.deinit(alloc);
    alloc.free(ctx.region);
    alloc.destroy(ctx);
}

// ─── Sort ────────────────────────────────────────────────────────────────────

pub const SortKey = enum { time, name, user, source, account };

const SortCtx = struct {
    items: []const EventItem,
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

fn compareField(a: EventItem, b: EventItem, key: SortKey) std.math.Order {
    return switch (key) {
        .time => std.math.order(a.event_time orelse -1, b.event_time orelse -1),
        .name => std.mem.order(u8, a.event_name, b.event_name),
        .user => std.mem.order(u8, a.username, b.username),
        .source => std.mem.order(u8, a.event_source, b.event_source),
        .account => std.mem.order(u8, a.account_id, b.account_id),
    };
}

// ─── Filter ──────────────────────────────────────────────────────────────────

const ItemResolver = struct {
    item: EventItem,

    pub fn resolve(self: ItemResolver, field: []const u8) filter_mod.FieldValue {
        if (std.mem.eql(u8, field, "name")) return .{ .string = self.item.event_name };
        if (std.mem.eql(u8, field, "user") or std.mem.eql(u8, field, "username")) return .{ .string = self.item.username };
        if (std.mem.eql(u8, field, "source")) return .{ .string = self.item.event_source };
        if (std.mem.eql(u8, field, "account") or std.mem.eql(u8, field, "account_id")) return .{ .string = self.item.account_id };
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
committed_filter: ?[]u8 = null,
live_filter: []const u8 = "",
filter_expr: ?filter_mod.ParseResult = null,
sort_keys: [4]SortKey = .{ .time, undefined, undefined, undefined },
sort_keys_len: usize = 1,
sort_dir: constants.SortDir = .desc,
sorted_indices: []usize = &.{},
last_sorted_len: usize = 0,
sort_dirty: bool = false,
sort_applied: bool = false,
breadcrumb_buf: [576]u8 = undefined,
breadcrumb_len: usize = 0,

// ─── Init / deinit ───────────────────────────────────────────────────────────

pub fn init(
    allocator: std.mem.Allocator,
    io: std.Io,
    credentials: Credentials,
    region: []const u8,
    trail_name: []const u8,
    color_support: terminal.ColorSupport,
    parent_breadcrumb: []const u8,
) !EventsView {
    const colors = colors_mod.red(color_support);

    const ctx = try allocator.create(LoadCtx);
    errdefer allocator.destroy(ctx);

    const view_region = try allocator.dupe(u8, region);
    errdefer allocator.free(view_region);

    const ctx_region = try allocator.dupe(u8, region);
    errdefer allocator.free(ctx_region);

    ctx.* = .{
        .allocator = allocator,
        .io = io,
        .credentials = credentials,
        .region = ctx_region,
    };

    ctx.thread = try std.Thread.spawn(.{}, fetchThread, .{ctx});

    var view = EventsView{
        .fg_color = colors.fg,
        .bg_color = colors.bg,
        .state = .{ .active = ctx },
        .alloc = allocator,
        .io = io,
        .credentials = credentials,
        .region = view_region,
    };

    const bc = std.fmt.bufPrint(&view.breadcrumb_buf, "{s} {s} {s}", .{ parent_breadcrumb, constants.SEP_ARROW, trail_name }) catch view.breadcrumb_buf[0..0];
    view.breadcrumb_len = bc.len;

    return view;
}

pub fn breadcrumb(self: *EventsView) []const u8 {
    return self.breadcrumb_buf[0..self.breadcrumb_len];
}

pub fn deinit(self: *EventsView) void {
    self.alloc.free(self.region);
    if (self.committed_filter) |f| self.alloc.free(f);
    if (self.filter_expr) |*fe| fe.deinit();
    if (self.sorted_indices.len > 0) self.alloc.free(self.sorted_indices);
    switch (self.state) {
        .active => |ctx| deinitLoadCtx(self.alloc, ctx),
        .failed => {},
    }
}

// ─── Filter helpers ──────────────────────────────────────────────────────────

fn effectiveFilter(self: *const EventsView) []const u8 {
    return if (self.live_filter.len > 0) self.live_filter else self.committed_filter orelse "";
}

fn matchesItem(self: *const EventsView, item: EventItem, text_f: []const u8) bool {
    if (!filter_mod.matchesText(item.event_name, text_f)) return false;
    if (self.filter_expr) |*fe| {
        const resolver = ItemResolver{ .item = item };
        if (!filter_mod.evalExpr(fe.expr, resolver)) return false;
    }
    return true;
}

fn visibleCount(self: *const EventsView, items: []const EventItem, text_f: []const u8) usize {
    var n: usize = 0;
    for (items) |item| {
        if (self.matchesItem(item, text_f)) n += 1;
    }
    return n;
}

pub fn setLiveFilter(self: *EventsView, text: []const u8) void {
    if (!std.mem.eql(u8, self.live_filter, text)) {
        self.selected = 0;
        self.scroll_offset = 0;
    }
    self.live_filter = text;
}

pub fn commitFilter(self: *EventsView, text: []const u8) void {
    if (self.committed_filter) |f| self.alloc.free(f);
    self.committed_filter = if (text.len == 0) null else self.alloc.dupe(u8, text) catch null;
    self.live_filter = "";
    self.selected = 0;
    self.scroll_offset = 0;
}

pub fn setFilterExpr(self: *EventsView, result: filter_mod.ParseResult) void {
    if (self.filter_expr) |*fe| fe.deinit();
    self.filter_expr = result;
    self.selected = 0;
    self.scroll_offset = 0;
}

pub fn clearFilterExpr(self: *EventsView) void {
    if (self.filter_expr) |*fe| fe.deinit();
    self.filter_expr = null;
    self.selected = 0;
    self.scroll_offset = 0;
}

// ─── Sort helpers ────────────────────────────────────────────────────────────

fn recomputeSort(self: *EventsView, items: []const EventItem) void {
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

fn ensureSorted(self: *EventsView, items: []const EventItem) void {
    if (!self.sort_dirty and self.sorted_indices.len == items.len) return;
    self.recomputeSort(items);
    self.sort_dirty = false;
}

pub fn setSort(self: *EventsView, keys: []const SortKey, dir: constants.SortDir) void {
    const n = @min(keys.len, self.sort_keys.len);
    @memcpy(self.sort_keys[0..n], keys[0..n]);
    self.sort_keys_len = if (n > 0) n else 1;
    self.sort_dir = dir;
    self.sort_dirty = true;
    self.sort_applied = true;
    self.selected = 0;
    self.scroll_offset = 0;
}

pub fn clearSort(self: *EventsView) void {
    self.sort_keys[0] = .time;
    self.sort_keys_len = 1;
    self.sort_dir = .desc;
    self.sort_dirty = true;
    self.sort_applied = false;
    self.selected = 0;
    self.scroll_offset = 0;
}

// ─── Manual refresh ──────────────────────────────────────────────────────────

fn refresh(self: *EventsView) !void {
    if (self.sorted_indices.len > 0) {
        self.alloc.free(self.sorted_indices);
        self.sorted_indices = &.{};
    }
    self.last_sorted_len = 0;
    self.sort_dirty = true;

    const ctx = try self.alloc.create(LoadCtx);
    errdefer self.alloc.destroy(ctx);
    const ctx_region = try self.alloc.dupe(u8, self.region);
    errdefer self.alloc.free(ctx_region);

    ctx.* = .{
        .allocator = self.alloc,
        .io = self.io,
        .credentials = self.credentials,
        .region = ctx_region,
    };
    ctx.thread = try std.Thread.spawn(.{}, fetchThread, .{ctx});

    switch (self.state) {
        .active => |old| deinitLoadCtx(self.alloc, old),
        .failed => {},
    }

    self.state = .{ .active = ctx };
    self.selected = 0;
    self.scroll_offset = 0;
}

// ─── Event handling ──────────────────────────────────────────────────────────

pub fn handleEvent(self: *EventsView, event: Event, ctx: ViewContext) !Action {
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
                    const items = lctx.items.items;
                    const filter = self.effectiveFilter();
                    self.ensureSorted(items);

                    var vis: usize = 0;
                    var raw: ?[]u8 = null;
                    var ev_name: ?[]u8 = null;
                    for (self.sorted_indices) |orig_idx| {
                        const item = items[orig_idx];
                        if (!self.matchesItem(item, filter)) continue;
                        if (vis == self.selected) {
                            raw = ctx.allocator.dupe(u8, item.raw_event) catch null;
                            ev_name = ctx.allocator.dupe(u8, item.event_name) catch null;
                            break;
                        }
                        vis += 1;
                    }
                    lctx.mutex.unlock();

                    const raw_str = raw orelse return .none;
                    const name_str = ev_name orelse {
                        ctx.allocator.free(raw_str);
                        return .none;
                    };
                    defer ctx.allocator.free(name_str);

                    const v = EventDetailView.init(ctx.allocator, raw_str, name_str, ctx.color_support, self.breadcrumb()) catch {
                        ctx.allocator.free(raw_str);
                        return .none;
                    };
                    return .{ .push = .{ .cloudtrail_event_detail = v } };
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
    if (width >= 120) return .wide;
    if (width >= 70) return .medium;
    return .compact;
}

fn nameWidth(inner: usize, mode: Mode) usize {
    const fixed: usize = switch (mode) {
        .wide => TIME_W + USER_W + SOURCE_W + ACCOUNT_W + 4,
        .medium => TIME_W + 1,
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

fn writeVert(self: *EventsView, writer: *std.Io.Writer, selected: bool, reset: bool) !void {
    if (selected) {
        try writer.writeAll(self.bg_color);
        try writer.writeAll(terminal.FG_BLACK);
    } else {
        try writer.writeAll(self.fg_color);
    }
    try writer.writeAll(constants.VERTICAL);
    if (reset) try writer.writeAll(terminal.RESET);
}

fn writeSepRow(self: *EventsView, writer: *std.Io.Writer, name_w: usize, mode: Mode, bottom: bool) !void {
    const left = if (bottom) constants.BOTTOM_LEFT else constants.LEFT_T;
    const mid = if (bottom) constants.BOTTOM_T else constants.CROSS;
    const right = if (bottom) constants.BOTTOM_RIGHT else constants.RIGHT_T;

    try writer.writeAll(self.fg_color);
    try writer.writeAll(left);
    for (0..name_w) |_| try writer.writeAll(constants.HORIZONTAL);
    switch (mode) {
        .wide => {
            try writer.writeAll(mid);
            for (0..TIME_W) |_| try writer.writeAll(constants.HORIZONTAL);
            try writer.writeAll(mid);
            for (0..USER_W) |_| try writer.writeAll(constants.HORIZONTAL);
            try writer.writeAll(mid);
            for (0..SOURCE_W) |_| try writer.writeAll(constants.HORIZONTAL);
            try writer.writeAll(mid);
            for (0..ACCOUNT_W) |_| try writer.writeAll(constants.HORIZONTAL);
        },
        .medium => {
            try writer.writeAll(mid);
            for (0..TIME_W) |_| try writer.writeAll(constants.HORIZONTAL);
        },
        .compact => {},
    }
    try writer.writeAll(right);
    try writer.writeAll(terminal.RESET);
}

fn writeHeaderCell(self: *EventsView, writer: *std.Io.Writer, text: []const u8, cell_w: usize) !void {
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

fn writeHeaderRow(self: *EventsView, writer: *std.Io.Writer, name_w: usize, mode: Mode) !void {
    try writer.writeAll(self.fg_color);
    try writer.writeAll(constants.VERTICAL);
    try writer.writeAll(terminal.RESET);
    try self.writeHeaderCell(writer, "EVENT NAME", name_w);
    switch (mode) {
        .wide => {
            try writer.writeAll(self.fg_color);
            try writer.writeAll(constants.VERTICAL);
            try writer.writeAll(terminal.RESET);
            try self.writeHeaderCell(writer, "TIME", TIME_W);
            try writer.writeAll(self.fg_color);
            try writer.writeAll(constants.VERTICAL);
            try writer.writeAll(terminal.RESET);
            try self.writeHeaderCell(writer, "USER", USER_W);
            try writer.writeAll(self.fg_color);
            try writer.writeAll(constants.VERTICAL);
            try writer.writeAll(terminal.RESET);
            try self.writeHeaderCell(writer, "SOURCE", SOURCE_W);
            try writer.writeAll(self.fg_color);
            try writer.writeAll(constants.VERTICAL);
            try writer.writeAll(terminal.RESET);
            try self.writeHeaderCell(writer, "ACCOUNT", ACCOUNT_W);
        },
        .medium => {
            try writer.writeAll(self.fg_color);
            try writer.writeAll(constants.VERTICAL);
            try writer.writeAll(terminal.RESET);
            try self.writeHeaderCell(writer, "TIME", TIME_W);
        },
        .compact => {},
    }
    try writer.writeAll(self.fg_color);
    try writer.writeAll(constants.VERTICAL);
    try writer.writeAll(terminal.RESET);
}

fn writeItemRow(self: *EventsView, writer: *std.Io.Writer, item: EventItem, sel: bool, name_w: usize, mode: Mode) !void {
    try self.writeVert(writer, sel, !sel);

    const content_w = if (name_w >= 2) name_w - 2 else 0;
    const max_name = if (content_w >= 2) content_w - 2 else 0;
    try writer.writeByte(' ');
    try writer.writeAll(if (sel) "▸ " else "  ");
    const shown_name = if (item.event_name.len > max_name) item.event_name[0..max_name] else item.event_name;
    try writer.writeAll(shown_name);
    for (shown_name.len..max_name) |_| try writer.writeByte(' ');
    try writer.writeByte(' ');

    switch (mode) {
        .wide => {
            var ts_buf: [24]u8 = undefined;
            const ts_str = formatEpochSeconds(&ts_buf, item.event_time);
            try self.writeVert(writer, sel, !sel);
            try writePaddedCell(writer, ts_str, TIME_W);
            try self.writeVert(writer, sel, !sel);
            try writePaddedCell(writer, item.username, USER_W);
            try self.writeVert(writer, sel, !sel);
            try writePaddedCell(writer, item.event_source, SOURCE_W);
            try self.writeVert(writer, sel, !sel);
            try writePaddedCell(writer, item.account_id, ACCOUNT_W);
        },
        .medium => {
            var ts_buf: [24]u8 = undefined;
            const ts_str = formatEpochSeconds(&ts_buf, item.event_time);
            try self.writeVert(writer, sel, !sel);
            try writePaddedCell(writer, ts_str, TIME_W);
        },
        .compact => {},
    }

    try self.writeVert(writer, sel, true);
}

fn writeEmptyRow(self: *EventsView, writer: *std.Io.Writer, name_w: usize, mode: Mode) !void {
    try self.writeVert(writer, false, true);
    for (0..name_w) |_| try writer.writeByte(' ');
    switch (mode) {
        .wide => {
            try self.writeVert(writer, false, true);
            for (0..TIME_W) |_| try writer.writeByte(' ');
            try self.writeVert(writer, false, true);
            for (0..USER_W) |_| try writer.writeByte(' ');
            try self.writeVert(writer, false, true);
            for (0..SOURCE_W) |_| try writer.writeByte(' ');
            try self.writeVert(writer, false, true);
            for (0..ACCOUNT_W) |_| try writer.writeByte(' ');
        },
        .medium => {
            try self.writeVert(writer, false, true);
            for (0..TIME_W) |_| try writer.writeByte(' ');
        },
        .compact => {},
    }
    try self.writeVert(writer, false, true);
}

pub fn render(self: *EventsView, writer: *std.Io.Writer, size: Coord) !void {
    if (size.x < 10 or size.y < 4) return;
    const w: usize = @intCast(size.x);
    const h: usize = @intCast(size.y);
    const inner = w - 2;
    const mode = modeFor(size.x);
    const name_w = nameWidth(inner, mode);
    const show_header = h >= 6;
    const data_rows = if (show_header) h - 3 else h - 1;

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
                    const msg = std.fmt.bufPrint(&buf, " Error: {s}", .{@errorName(e)}) catch " Error loading events";
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
