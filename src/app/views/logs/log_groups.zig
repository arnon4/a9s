const std = @import("std");
const colors_mod = @import("../../../ui/colors.zig");
const format_mod = @import("../../../ui/format.zig");
const fetcher = @import("../../../sdk/credentials/fetcher.zig");
const Credentials = fetcher.Credentials;
const ProfileSet = @import("../../profile_set.zig").ProfileSet;
const terminal = @import("../../../terminal/terminal.zig");
const input = @import("../../../terminal/input.zig");
const Event = @import("../../../event.zig").Event;
const view_mod = @import("../../../ui/view.zig");
const Action = view_mod.Action;
const ViewContext = view_mod.ViewContext;
const Coord = terminal.Coord;
const Logs = @import("../../../sdk/clients/logs/client.zig");
const CloudWatch = @import("../../../sdk/clients/cloudwatch/client.zig");
const constants = @import("../../../ui/constants.zig");
const ConfirmView = @import("../../../ui/confirm.zig");
const filter_mod = @import("../../../commands/filter.zig");
const LogStreamsView = @import("log_streams.zig");

const LogGroupsView = @This();
pub const name: []const u8 = "Log Groups";

const CLASS_W: usize = 12;
const REGION_W: usize = 16;
const RETENTION_W: usize = 12;
const STORED_W: usize = 12;

const Mode = enum {
    wide, // >=100: Name | Class | Region | Retention | Stored
    medium, //  >=70: Name | Region | Retention
    compact, //   <70: Name | Retention
};

// ─── Local item ──────────────────────────────────────────────────────────────

const LogGroupItem = struct {
    allocator: std.mem.Allocator,
    name: []u8,
    region: []u8,
    class: []u8,
    retention_days: ?i32,
    stored_bytes: ?i64,
    arn: []u8,
    credentials: Credentials,

    pub fn deinit(self: LogGroupItem) void {
        self.allocator.free(self.name);
        self.allocator.free(self.region);
        self.allocator.free(self.class);
        self.allocator.free(self.arn);
    }
};

/// Parse region from log group ARN: arn:aws:logs:{region}:{account}:log-group:{name}
fn regionFromArn(arn: []const u8) []const u8 {
    var it = std.mem.splitScalar(u8, arn, ':');
    _ = it.next(); // arn
    _ = it.next(); // aws
    _ = it.next(); // logs
    return it.next() orelse "";
}

fn classLabel(g: Logs.LogGroup) []const u8 {
    return switch (g.log_group_class) {
        .standard => "Standard",
        .infrequent_access => "Infreq",
        .delivery => "Delivery",
        .unknown => "",
    };
}

fn groupToItem(allocator: std.mem.Allocator, g: Logs.LogGroup, credentials: Credentials) !LogGroupItem {
    const item_name = try allocator.dupe(u8, g.log_group_name);
    errdefer allocator.free(item_name);

    const region_raw = regionFromArn(g.log_group_arn);
    const region = try allocator.dupe(u8, if (region_raw.len > 0) region_raw else "—");
    errdefer allocator.free(region);

    const class = try allocator.dupe(u8, classLabel(g));
    errdefer allocator.free(class);

    const arn = try allocator.dupe(u8, g.arn);
    errdefer allocator.free(arn);

    return .{
        .allocator = allocator,
        .name = item_name,
        .region = region,
        .class = class,
        .retention_days = g.retention_in_days,
        .stored_bytes = if (g.stored_bytes > 0) g.stored_bytes else null,
        .arn = arn,
        .credentials = credentials,
    };
}

// ─── Concurrency ─────────────────────────────────────────────────────────────

const SharedCtx = struct {
    allocator: std.mem.Allocator,
    mutex: std.atomic.Mutex = .unlocked,
    items: std.ArrayList(LogGroupItem) = .empty,
    region_ctxs: []*RegionCtx,
    pending: std.atomic.Value(usize),
    done: std.atomic.Value(bool) = .init(false),
};

const RegionCtx = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    credentials: Credentials,
    region: []u8,
    shared: *SharedCtx,
    thread: std.Thread = undefined,
    err: ?anyerror = null,
    done: std.atomic.Value(bool) = .init(false),
};

const State = union(enum) {
    active: *SharedCtx,
    failed: anyerror,
};

fn fetchRegionThread(ctx: *RegionCtx) void {
    defer {
        ctx.done.store(true, .release);
        const prev = ctx.shared.pending.fetchSub(1, .release);
        if (prev == 1) ctx.shared.done.store(true, .release);
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
        const result = client.describeLogGroups(.{
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

        lockMutex(&ctx.shared.mutex);
        for (result.log_groups) |g| {
            const item = groupToItem(ctx.allocator, g, ctx.credentials) catch |e| {
                ctx.shared.mutex.unlock();
                ctx.err = e;
                return;
            };
            ctx.shared.items.append(ctx.allocator, item) catch |e| {
                item.deinit();
                ctx.shared.mutex.unlock();
                ctx.err = e;
                return;
            };
        }
        ctx.shared.mutex.unlock();

        if (is_last) break;
        input.notify();
    }

    fetchStoredBytesForRegion(ctx);
}

fn lockMutex(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

fn fetchStoredBytesForRegion(ctx: *RegionCtx) void {
    // Collect indices + names of items belonging to this region.
    lockMutex(&ctx.shared.mutex);
    var indices: std.ArrayList(usize) = .empty;
    var names: std.ArrayList([]const u8) = .empty;
    for (ctx.shared.items.items, 0..) |item, i| {
        if (!std.mem.eql(u8, item.region, ctx.region)) continue;
        indices.append(ctx.allocator, i) catch {
            ctx.shared.mutex.unlock();
            indices.deinit(ctx.allocator);
            names.deinit(ctx.allocator);
            return;
        };
        names.append(ctx.allocator, item.name) catch {
            ctx.shared.mutex.unlock();
            indices.deinit(ctx.allocator);
            names.deinit(ctx.allocator);
            return;
        };
    }
    ctx.shared.mutex.unlock();
    defer indices.deinit(ctx.allocator);
    defer names.deinit(ctx.allocator);

    if (indices.items.len == 0) return;

    var cw_client = CloudWatch.Client.init(ctx.allocator, .{
        .region = ctx.region,
        .io = ctx.io,
        .credentials = ctx.credentials,
    }) catch return;
    defer cw_client.deinit();

    const now: i64 = @intCast(@divFloor(std.Io.Timestamp.now(ctx.io, .real).nanoseconds, std.time.ns_per_s));
    const two_weeks_ago = now - 14 * 24 * 3600;

    // Process in batches of 500 (GetMetricData limit).
    var batch_start: usize = 0;
    while (batch_start < indices.items.len) {
        const batch_end = @min(batch_start + 500, indices.items.len);
        const batch_len = batch_end - batch_start;
        const batch_names = names.items[batch_start..batch_end];
        const batch_indices = indices.items[batch_start..batch_end];

        const queries = ctx.allocator.alloc(CloudWatch.MetricDataQuery, batch_len) catch {
            batch_start = batch_end;
            continue;
        };
        defer ctx.allocator.free(queries);

        const dims = ctx.allocator.alloc(CloudWatch.Dimension, batch_len) catch {
            batch_start = batch_end;
            continue;
        };
        defer ctx.allocator.free(dims);

        // ID buffers: "m" + up to 3 digits = 4 bytes max, use 8 to be safe.
        const id_bufs = ctx.allocator.alloc([8]u8, batch_len) catch {
            batch_start = batch_end;
            continue;
        };
        defer ctx.allocator.free(id_bufs);

        for (batch_names, 0..) |lg_name, qi| {
            dims[qi] = .{ .name = "LogGroupName", .value = lg_name };
            const id_slice = std.fmt.bufPrint(&id_bufs[qi], "m{d}", .{qi}) catch "m0";
            queries[qi] = .{
                .id = id_slice,
                .metric_stat = .{
                    .metric = .{
                        .namespace = "AWS/Logs",
                        .metric_name = "StoredBytes",
                        .dimensions = dims[qi .. qi + 1],
                    },
                    .period = 86400,
                    .stat = "Maximum",
                },
            };
        }

        const result = cw_client.getMetricData(.{
            .start_time = two_weeks_ago,
            .end_time = now,
            .queries = queries,
        }) catch {
            batch_start = batch_end;
            continue;
        };
        defer result.deinit();

        for (result.metric_data_results) |mdr| {
            if (mdr.id.len < 2 or mdr.id[0] != 'm') continue;
            const qi = std.fmt.parseInt(usize, mdr.id[1..], 10) catch continue;
            if (qi >= batch_len) continue;
            if (mdr.values.len == 0) continue;

            var max_val: f64 = 0;
            for (mdr.values) |v| if (v > max_val) {
                max_val = v;
            };

            lockMutex(&ctx.shared.mutex);
            ctx.shared.items.items[batch_indices[qi]].stored_bytes = @intFromFloat(max_val);
            ctx.shared.mutex.unlock();
        }

        batch_start = batch_end;
        input.notify();
    }
}

// ─── Sort ────────────────────────────────────────────────────────────────────

pub const SortKey = enum { name, region, retention, stored, class };

const SortCtx = struct {
    items: []const LogGroupItem,
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

fn compareField(a: LogGroupItem, b: LogGroupItem, key: SortKey) std.math.Order {
    return switch (key) {
        .name => std.mem.order(u8, a.name, b.name),
        .region => std.mem.order(u8, a.region, b.region),
        .class => std.mem.order(u8, a.class, b.class),
        .stored => std.math.order(a.stored_bytes orelse -1, b.stored_bytes orelse -1),
        .retention => blk: {
            // null (never expire) sorts last on asc, first on desc
            const av: i64 = if (a.retention_days) |d| d else std.math.maxInt(i64);
            const bv: i64 = if (b.retention_days) |d| d else std.math.maxInt(i64);
            break :blk std.math.order(av, bv);
        },
    };
}

// ─── Filter ──────────────────────────────────────────────────────────────────

const ItemResolver = struct {
    item: LogGroupItem,

    pub fn resolve(self: ItemResolver, field: []const u8) filter_mod.FieldValue {
        if (std.mem.eql(u8, field, "name")) return .{ .string = self.item.name };
        if (std.mem.eql(u8, field, "region")) return .{ .string = self.item.region };
        if (std.mem.eql(u8, field, "class")) return .{ .string = self.item.class };
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
profile_set: *const ProfileSet,
regions: []const []const u8,
live_filter: []const u8 = "",
committed_filter: ?[]u8 = null,
filter_expr: ?filter_mod.ParseResult = null,
sort_keys: [4]SortKey = .{ .name, undefined, undefined, undefined },
sort_keys_len: usize = 1,
sort_dir: constants.SortDir = .asc,
sorted_indices: []usize = &.{},
last_sorted_len: usize = 0,
sort_dirty: bool = false,
sort_applied: bool = false,

// ─── Init / deinit ───────────────────────────────────────────────────────────

pub fn init(
    allocator: std.mem.Allocator,
    io: std.Io,
    profile_set: *const ProfileSet,
    regions: []const []const u8,
    color_support: terminal.ColorSupport,
) !LogGroupsView {
    const colors = colors_mod.red(color_support);

    const effective_regions: []const []const u8 = if (regions.len > 0) regions else &.{"us-east-1"};

    var creds_list: std.ArrayList(Credentials) = .empty;
    defer creds_list.deinit(allocator);
    for (profile_set.entries.items) |*entry| {
        const creds = entry.store.getCredentials() catch continue;
        try creds_list.append(allocator, creds);
    }
    if (creds_list.items.len == 0) return error.NoCredentials;

    const n = creds_list.items.len * effective_regions.len;

    const shared = try allocator.create(SharedCtx);
    errdefer allocator.destroy(shared);

    const region_ctxs = try allocator.alloc(*RegionCtx, n);
    errdefer allocator.free(region_ctxs);

    shared.* = .{
        .allocator = allocator,
        .region_ctxs = region_ctxs,
        .pending = std.atomic.Value(usize).init(n),
    };

    var spawned: usize = 0;
    errdefer for (region_ctxs[0..spawned]) |rctx| {
        rctx.thread.join();
        rctx.allocator.free(rctx.region);
        rctx.allocator.destroy(rctx);
    };

    for (creds_list.items) |creds| {
        for (effective_regions) |region| {
            const rctx = try allocator.create(RegionCtx);
            errdefer allocator.destroy(rctx);
            const region_copy = try allocator.dupe(u8, region);
            errdefer allocator.free(region_copy);
            rctx.* = .{
                .allocator = allocator,
                .io = io,
                .credentials = creds,
                .region = region_copy,
                .shared = shared,
            };
            rctx.thread = try std.Thread.spawn(.{}, fetchRegionThread, .{rctx});
            region_ctxs[spawned] = rctx;
            spawned += 1;
        }
    }

    return .{
        .fg_color = colors.fg,
        .bg_color = colors.bg,
        .state = .{ .active = shared },
        .alloc = allocator,
        .io = io,
        .profile_set = profile_set,
        .regions = regions,
    };
}

pub fn breadcrumb(_: *LogGroupsView) []const u8 {
    return "Log Groups";
}

pub fn deinit(self: *LogGroupsView) void {
    if (self.committed_filter) |f| self.alloc.free(f);
    if (self.filter_expr) |*fe| fe.deinit();
    if (self.sorted_indices.len > 0) self.alloc.free(self.sorted_indices);
    switch (self.state) {
        .active => |shared| {
            for (shared.region_ctxs) |rctx| {
                if (!rctx.done.load(.acquire)) rctx.thread.join();
                rctx.allocator.free(rctx.region);
                rctx.allocator.destroy(rctx);
            }
            shared.allocator.free(shared.region_ctxs);
            for (shared.items.items) |item| item.deinit();
            shared.items.deinit(shared.allocator);
            shared.allocator.destroy(shared);
        },
        .failed => {},
    }
}

// ─── Filter helpers ──────────────────────────────────────────────────────────

fn effectiveFilter(self: *const LogGroupsView) []const u8 {
    return if (self.live_filter.len > 0) self.live_filter else self.committed_filter orelse "";
}

fn matchesItem(self: *const LogGroupsView, item: LogGroupItem, text_f: []const u8) bool {
    if (!filter_mod.matchesText(item.name, text_f)) return false;
    if (self.filter_expr) |*fe| {
        const resolver = ItemResolver{ .item = item };
        if (!filter_mod.evalExpr(fe.expr, resolver)) return false;
    }
    return true;
}

fn visibleCount(self: *const LogGroupsView, items: []const LogGroupItem, text_f: []const u8) usize {
    var n: usize = 0;
    for (items) |item| {
        if (self.matchesItem(item, text_f)) n += 1;
    }
    return n;
}

pub fn setLiveFilter(self: *LogGroupsView, text: []const u8) void {
    if (!std.mem.eql(u8, self.live_filter, text)) {
        self.selected = 0;
        self.scroll_offset = 0;
    }
    self.live_filter = text;
}

pub fn commitFilter(self: *LogGroupsView, text: []const u8) void {
    if (self.committed_filter) |f| self.alloc.free(f);
    self.committed_filter = if (text.len == 0) null else self.alloc.dupe(u8, text) catch null;
    self.live_filter = "";
    self.selected = 0;
    self.scroll_offset = 0;
}

pub fn setFilterExpr(self: *LogGroupsView, result: filter_mod.ParseResult) void {
    if (self.filter_expr) |*fe| fe.deinit();
    self.filter_expr = result;
    self.selected = 0;
    self.scroll_offset = 0;
}

pub fn clearFilterExpr(self: *LogGroupsView) void {
    if (self.filter_expr) |*fe| fe.deinit();
    self.filter_expr = null;
    self.selected = 0;
    self.scroll_offset = 0;
}

// ─── Sort helpers ────────────────────────────────────────────────────────────

fn recomputeSort(self: *LogGroupsView, items: []const LogGroupItem) void {
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

fn ensureSorted(self: *LogGroupsView, items: []const LogGroupItem) void {
    if (!self.sort_dirty and self.sorted_indices.len == items.len) return;
    self.recomputeSort(items);
    self.sort_dirty = false;
}

pub fn setSort(self: *LogGroupsView, keys: []const SortKey, dir: constants.SortDir) void {
    const n = @min(keys.len, self.sort_keys.len);
    @memcpy(self.sort_keys[0..n], keys[0..n]);
    self.sort_keys_len = if (n > 0) n else 1;
    self.sort_dir = dir;
    self.sort_dirty = true;
    self.sort_applied = true;
    self.selected = 0;
    self.scroll_offset = 0;
}

pub fn clearSort(self: *LogGroupsView) void {
    self.sort_keys[0] = .name;
    self.sort_keys_len = 1;
    self.sort_dir = .asc;
    self.sort_dirty = true;
    self.sort_applied = false;
    self.selected = 0;
    self.scroll_offset = 0;
}

// ─── Manual refresh ──────────────────────────────────────────────────────────

fn refresh(self: *LogGroupsView) !void {
    switch (self.state) {
        .active => |shared| {
            for (shared.region_ctxs) |rctx| {
                if (!rctx.done.load(.acquire)) rctx.thread.join();
                rctx.allocator.free(rctx.region);
                rctx.allocator.destroy(rctx);
            }
            shared.allocator.free(shared.region_ctxs);
            for (shared.items.items) |item| item.deinit();
            shared.items.deinit(shared.allocator);
            shared.allocator.destroy(shared);
        },
        .failed => {},
    }

    if (self.sorted_indices.len > 0) {
        self.alloc.free(self.sorted_indices);
        self.sorted_indices = &.{};
    }
    self.last_sorted_len = 0;
    self.sort_dirty = true;

    const effective_regions: []const []const u8 = if (self.regions.len > 0) self.regions else &.{"us-east-1"};

    var creds_list: std.ArrayList(Credentials) = .empty;
    defer creds_list.deinit(self.alloc);
    for (self.profile_set.entries.items) |*entry| {
        const creds = entry.store.getCredentials() catch continue;
        try creds_list.append(self.alloc, creds);
    }
    if (creds_list.items.len == 0) return error.NoCredentials;

    const n = creds_list.items.len * effective_regions.len;

    const shared = try self.alloc.create(SharedCtx);
    errdefer self.alloc.destroy(shared);

    const region_ctxs = try self.alloc.alloc(*RegionCtx, n);
    errdefer self.alloc.free(region_ctxs);

    shared.* = .{
        .allocator = self.alloc,
        .region_ctxs = region_ctxs,
        .pending = std.atomic.Value(usize).init(n),
    };

    var spawned: usize = 0;
    errdefer for (region_ctxs[0..spawned]) |rctx| {
        rctx.thread.join();
        rctx.allocator.free(rctx.region);
        rctx.allocator.destroy(rctx);
    };

    for (creds_list.items) |creds| {
        for (effective_regions) |region| {
            const rctx = try self.alloc.create(RegionCtx);
            errdefer self.alloc.destroy(rctx);
            const region_copy = try self.alloc.dupe(u8, region);
            errdefer self.alloc.free(region_copy);
            rctx.* = .{
                .allocator = self.alloc,
                .io = self.io,
                .credentials = creds,
                .region = region_copy,
                .shared = shared,
            };
            rctx.thread = try std.Thread.spawn(.{}, fetchRegionThread, .{rctx});
            region_ctxs[spawned] = rctx;
            spawned += 1;
        }
    }

    self.state = .{ .active = shared };
    self.selected = 0;
    self.scroll_offset = 0;
}

// ─── Event handling ──────────────────────────────────────────────────────────

pub fn handleEvent(self: *LogGroupsView, event: Event, ctx: ViewContext) !Action {
    const count: usize = switch (self.state) {
        .active => |shared| blk: {
            lockMutex(&shared.mutex);
            defer shared.mutex.unlock();
            break :blk self.visibleCount(shared.items.items, self.effectiveFilter());
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
            .enter => {
                switch (self.state) {
                    .active => |shared| {
                        lockMutex(&shared.mutex);
                        const items = shared.items.items;
                        const filter = self.effectiveFilter();
                        self.ensureSorted(items);

                        var vis: usize = 0;
                        var lg_name: ?[]u8 = null;
                        var lg_region: ?[]u8 = null;
                        var lg_creds: Credentials = undefined;

                        for (self.sorted_indices) |orig_idx| {
                            const item = items[orig_idx];
                            if (!self.matchesItem(item, filter)) continue;
                            if (vis == self.selected) {
                                lg_name = ctx.allocator.dupe(u8, item.name) catch null;
                                lg_region = ctx.allocator.dupe(u8, item.region) catch null;
                                lg_creds = item.credentials;
                                break;
                            }
                            vis += 1;
                        }
                        shared.mutex.unlock();

                        const name_str = lg_name orelse return .none;
                        const region_str = lg_region orelse {
                            ctx.allocator.free(name_str);
                            return .none;
                        };

                        const v = LogStreamsView.init(ctx.allocator, ctx.io, lg_creds, region_str, name_str, ctx.color_support, self.breadcrumb()) catch {
                            ctx.allocator.free(name_str);
                            ctx.allocator.free(region_str);
                            return .none;
                        };
                        ctx.allocator.free(name_str);
                        ctx.allocator.free(region_str);
                        return .{ .push = .{ .logs_log_streams = v } };
                    },
                    .failed => {},
                }
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
    if (width >= 100) return .wide;
    if (width >= 70) return .medium;
    return .compact;
}

fn nameWidth(inner: usize, mode: Mode) usize {
    const fixed: usize = switch (mode) {
        .wide => CLASS_W + REGION_W + RETENTION_W + STORED_W + 4,
        .medium => REGION_W + RETENTION_W + 2,
        .compact => RETENTION_W + 1,
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

fn writeVert(self: *LogGroupsView, writer: *std.Io.Writer, selected: bool, reset: bool) !void {
    if (selected) {
        try writer.writeAll(self.bg_color);
        try writer.writeAll(terminal.FG_BLACK);
    } else {
        try writer.writeAll(self.fg_color);
    }
    try writer.writeAll(constants.VERTICAL);
    if (reset) try writer.writeAll(terminal.RESET);
}

fn writeSepRow(self: *LogGroupsView, writer: *std.Io.Writer, name_w: usize, mode: Mode, bottom: bool) !void {
    const left = if (bottom) constants.BOTTOM_LEFT else constants.LEFT_T;
    const mid = if (bottom) constants.BOTTOM_T else constants.CROSS;
    const right = if (bottom) constants.BOTTOM_RIGHT else constants.RIGHT_T;

    try writer.writeAll(self.fg_color);
    try writer.writeAll(left);
    for (0..name_w) |_| try writer.writeAll(constants.HORIZONTAL);
    try writer.writeAll(mid);
    for (0..RETENTION_W) |_| try writer.writeAll(constants.HORIZONTAL);
    switch (mode) {
        .wide => {
            try writer.writeAll(mid);
            for (0..CLASS_W) |_| try writer.writeAll(constants.HORIZONTAL);
            try writer.writeAll(mid);
            for (0..REGION_W) |_| try writer.writeAll(constants.HORIZONTAL);
            try writer.writeAll(mid);
            for (0..STORED_W) |_| try writer.writeAll(constants.HORIZONTAL);
        },
        .medium => {
            try writer.writeAll(mid);
            for (0..REGION_W) |_| try writer.writeAll(constants.HORIZONTAL);
        },
        .compact => {},
    }
    try writer.writeAll(right);
    try writer.writeAll(terminal.RESET);
}

fn writeHeaderCell(self: *LogGroupsView, writer: *std.Io.Writer, text: []const u8, cell_w: usize) !void {
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

fn writeHeaderRow(self: *LogGroupsView, writer: *std.Io.Writer, name_w: usize, mode: Mode) !void {
    try writer.writeAll(self.fg_color);
    try writer.writeAll(constants.VERTICAL);
    try writer.writeAll(terminal.RESET);
    try self.writeHeaderCell(writer, "NAME", name_w);
    try writer.writeAll(self.fg_color);
    try writer.writeAll(constants.VERTICAL);
    try writer.writeAll(terminal.RESET);
    try self.writeHeaderCell(writer, "RETENTION", RETENTION_W);
    switch (mode) {
        .wide => {
            try writer.writeAll(self.fg_color);
            try writer.writeAll(constants.VERTICAL);
            try writer.writeAll(terminal.RESET);
            try self.writeHeaderCell(writer, "CLASS", CLASS_W);
            try writer.writeAll(self.fg_color);
            try writer.writeAll(constants.VERTICAL);
            try writer.writeAll(terminal.RESET);
            try self.writeHeaderCell(writer, "REGION", REGION_W);
            try writer.writeAll(self.fg_color);
            try writer.writeAll(constants.VERTICAL);
            try writer.writeAll(terminal.RESET);
            try self.writeHeaderCell(writer, "STORED", STORED_W);
        },
        .medium => {
            try writer.writeAll(self.fg_color);
            try writer.writeAll(constants.VERTICAL);
            try writer.writeAll(terminal.RESET);
            try self.writeHeaderCell(writer, "REGION", REGION_W);
        },
        .compact => {},
    }
    try writer.writeAll(self.fg_color);
    try writer.writeAll(constants.VERTICAL);
    try writer.writeAll(terminal.RESET);
}

fn retentionLabel(buf: []u8, days: ?i32) []u8 {
    if (days) |d| {
        return std.fmt.bufPrint(buf, "{d}d", .{d}) catch buf[0..0];
    }
    return std.fmt.bufPrint(buf, "Never", .{}) catch buf[0..0];
}

fn writeItemRow(self: *LogGroupsView, writer: *std.Io.Writer, item: LogGroupItem, sel: bool, name_w: usize, mode: Mode) !void {
    try self.writeVert(writer, sel, !sel);

    const content_w = if (name_w >= 2) name_w - 2 else 0;
    const max_name = if (content_w >= 2) content_w - 2 else 0;
    try writer.writeByte(' ');
    try writer.writeAll(if (sel) "▸ " else "  ");
    const shown_name = if (item.name.len > max_name) item.name[0..max_name] else item.name;
    try writer.writeAll(shown_name);
    for (shown_name.len..max_name) |_| try writer.writeByte(' ');
    try writer.writeByte(' ');

    var ret_buf: [16]u8 = undefined;
    const ret_str = retentionLabel(&ret_buf, item.retention_days);

    try self.writeVert(writer, sel, !sel);
    try writePaddedCell(writer, ret_str, RETENTION_W);

    switch (mode) {
        .wide => {
            try self.writeVert(writer, sel, !sel);
            try writePaddedCell(writer, item.class, CLASS_W);
            try self.writeVert(writer, sel, !sel);
            try writePaddedCell(writer, item.region, REGION_W);
            try self.writeVert(writer, sel, !sel);
            var size_buf: [24]u8 = undefined;
            const size_str: []const u8 = if (item.stored_bytes) |sb|
                format_mod.size(&size_buf, @intCast(sb))
            else
                "-";
            try writePaddedCell(writer, size_str, STORED_W);
        },
        .medium => {
            try self.writeVert(writer, sel, !sel);
            try writePaddedCell(writer, item.region, REGION_W);
        },
        .compact => {},
    }

    try self.writeVert(writer, sel, true);
}

fn writeEmptyRow(self: *LogGroupsView, writer: *std.Io.Writer, name_w: usize, mode: Mode) !void {
    try self.writeVert(writer, false, true);
    for (0..name_w) |_| try writer.writeByte(' ');
    try self.writeVert(writer, false, true);
    for (0..RETENTION_W) |_| try writer.writeByte(' ');
    switch (mode) {
        .wide => {
            try self.writeVert(writer, false, true);
            for (0..CLASS_W) |_| try writer.writeByte(' ');
            try self.writeVert(writer, false, true);
            for (0..REGION_W) |_| try writer.writeByte(' ');
            try self.writeVert(writer, false, true);
            for (0..STORED_W) |_| try writer.writeByte(' ');
        },
        .medium => {
            try self.writeVert(writer, false, true);
            for (0..REGION_W) |_| try writer.writeByte(' ');
        },
        .compact => {},
    }
    try self.writeVert(writer, false, true);
}

pub fn render(self: *LogGroupsView, writer: *std.Io.Writer, size: Coord) !void {
    if (size.x < 10 or size.y < 4) return;
    const w: usize = @intCast(size.x);
    const h: usize = @intCast(size.y);
    const inner = w - 2;
    const mode = modeFor(size.x);
    const name_w = nameWidth(inner, mode);
    const show_header = h >= 6;
    const data_rows = if (show_header) h - 3 else h - 1;

    // Transition active → failed once all regions done with no results and errors.
    switch (self.state) {
        .active => |shared| {
            if (shared.done.load(.acquire)) {
                lockMutex(&shared.mutex);
                const n = shared.items.items.len;
                shared.mutex.unlock();
                if (n == 0) {
                    var first_err: ?anyerror = null;
                    for (shared.region_ctxs) |rctx| {
                        if (rctx.err) |e| {
                            first_err = e;
                            break;
                        }
                    }
                    if (first_err) |e| {
                        for (shared.region_ctxs) |rctx| {
                            rctx.allocator.free(rctx.region);
                            rctx.allocator.destroy(rctx);
                        }
                        shared.allocator.free(shared.region_ctxs);
                        for (shared.items.items) |item| item.deinit();
                        shared.items.deinit(shared.allocator);
                        shared.allocator.destroy(shared);
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
        .active => |shared| {
            lockMutex(&shared.mutex);
            defer shared.mutex.unlock();
            const items = shared.items.items;
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
                    const msg = std.fmt.bufPrint(&buf, " Error: {s}", .{@errorName(e)}) catch " Error loading log groups";
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
