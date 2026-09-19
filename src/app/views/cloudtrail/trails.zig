const std = @import("std");
const colors_mod = @import("../../../ui/colors.zig");
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
const CloudTrail = @import("../../../sdk/clients/cloudtrail/client.zig");
const constants = @import("../../../ui/constants.zig");
const ConfirmView = @import("../../../ui/confirm.zig");
const filter_mod = @import("../../../commands/filter.zig");
const EventsView = @import("events.zig");

const TrailsView = @This();
pub const name: []const u8 = "CloudTrail Trails";

const ACCOUNT_W: usize = 14;
const REGION_W: usize = 16;
const STATUS_W: usize = 12;

const Mode = enum {
    wide, //   >=110: Name | Account | Region | Status
    medium, //   >=60: Name | Status
    compact, //   <60: Name
};

// ─── Local item ──────────────────────────────────────────────────────────────

const TrailItem = struct {
    allocator: std.mem.Allocator,
    name: []u8,
    home_region: []u8,
    account_id: []u8,
    arn: []u8,
    is_logging: ?bool,
    is_org: ?bool,
    credentials: Credentials,

    pub fn deinit(self: TrailItem) void {
        self.allocator.free(self.name);
        self.allocator.free(self.home_region);
        self.allocator.free(self.account_id);
        self.allocator.free(self.arn);
    }
};

/// Parse the account id out of a trail ARN: arn:aws:cloudtrail:{region}:{account}:trail/{name}
fn accountIdFromArn(arn: []const u8) []const u8 {
    var it = std.mem.splitScalar(u8, arn, ':');
    _ = it.next(); // arn
    _ = it.next(); // aws
    _ = it.next(); // cloudtrail
    _ = it.next(); // region
    return it.next() orelse "";
}

fn trailToItem(allocator: std.mem.Allocator, t: CloudTrail.TrailInfo, fallback_region: []const u8, credentials: Credentials) !TrailItem {
    const item_name = try allocator.dupe(u8, t.name);
    errdefer allocator.free(item_name);

    const region_src = if (t.home_region.len > 0) t.home_region else fallback_region;
    const home_region = try allocator.dupe(u8, region_src);
    errdefer allocator.free(home_region);

    const account_id_src = accountIdFromArn(t.trail_arn);
    const account_id = try allocator.dupe(u8, if (account_id_src.len > 0) account_id_src else "-");
    errdefer allocator.free(account_id);

    const arn = try allocator.dupe(u8, t.trail_arn);
    errdefer allocator.free(arn);

    return .{
        .allocator = allocator,
        .name = item_name,
        .home_region = home_region,
        .account_id = account_id,
        .arn = arn,
        .is_logging = null,
        .is_org = null,
        .credentials = credentials,
    };
}

// ─── Concurrency ─────────────────────────────────────────────────────────────

const SharedCtx = struct {
    allocator: std.mem.Allocator,
    mutex: std.atomic.Mutex = .unlocked,
    items: std.ArrayList(TrailItem) = .empty,
    region_ctxs: []*RegionCtx,
    pending: std.atomic.Value(usize),
    done: std.atomic.Value(bool) = .init(false),
    /// Set by the view when it's torn down mid-fetch, so background threads
    /// stop paginating/fetching statuses instead of running to completion —
    /// otherwise `deinit`'s `thread.join()` blocks the whole UI, including
    /// Ctrl+C, until every region and trail finishes.
    cancel: std.atomic.Value(bool) = .init(false),
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

    var client = CloudTrail.Client.init(ctx.allocator, .{
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
        if (ctx.shared.cancel.load(.acquire)) return;

        const result = client.listTrails(.{
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
        for (result.trails) |t| {
            // Organization trails are visible from every member account/profile —
            // skip if a profile that ran earlier already listed this exact trail.
            var is_dup = false;
            for (ctx.shared.items.items) |existing| {
                if (std.mem.eql(u8, existing.arn, t.trail_arn)) {
                    is_dup = true;
                    break;
                }
            }
            if (is_dup) continue;

            const item = trailToItem(ctx.allocator, t, ctx.region, ctx.credentials) catch |e| {
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

    fetchStatusForRegion(ctx, &client);
}

fn lockMutex(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

fn fetchStatusForRegion(ctx: *RegionCtx, client: *CloudTrail.Client) void {
    lockMutex(&ctx.shared.mutex);
    var indices: std.ArrayList(usize) = .empty;
    var arns: std.ArrayList([]const u8) = .empty;
    for (ctx.shared.items.items, 0..) |item, i| {
        if (!std.mem.eql(u8, item.home_region, ctx.region)) continue;
        indices.append(ctx.allocator, i) catch {
            ctx.shared.mutex.unlock();
            indices.deinit(ctx.allocator);
            arns.deinit(ctx.allocator);
            return;
        };
        arns.append(ctx.allocator, item.arn) catch {
            ctx.shared.mutex.unlock();
            indices.deinit(ctx.allocator);
            arns.deinit(ctx.allocator);
            return;
        };
    }
    ctx.shared.mutex.unlock();
    defer indices.deinit(ctx.allocator);
    defer arns.deinit(ctx.allocator);

    if (arns.items.len > 0 and !ctx.shared.cancel.load(.acquire)) fetch_org: {
        const desc = client.describeTrails(.{ .trail_name_list = arns.items }) catch break :fetch_org;
        defer desc.deinit();

        lockMutex(&ctx.shared.mutex);
        for (desc.trails) |td| {
            for (arns.items, 0..) |arn, i| {
                if (std.mem.eql(u8, td.trail_arn, arn)) {
                    ctx.shared.items.items[indices.items[i]].is_org = td.is_organization_trail;
                    break;
                }
            }
        }
        ctx.shared.mutex.unlock();
        input.notify();
    }

    for (arns.items, 0..) |arn, i| {
        if (ctx.shared.cancel.load(.acquire)) return;

        const status = client.getTrailStatus(.{ .name = arn }) catch continue;
        defer status.deinit();

        lockMutex(&ctx.shared.mutex);
        ctx.shared.items.items[indices.items[i]].is_logging = status.is_logging;
        ctx.shared.mutex.unlock();
        input.notify();
    }
}

// ─── Sort ────────────────────────────────────────────────────────────────────

pub const SortKey = enum { name, region, status, account };

const SortCtx = struct {
    items: []const TrailItem,
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

fn compareField(a: TrailItem, b: TrailItem, key: SortKey) std.math.Order {
    return switch (key) {
        .name => std.mem.order(u8, a.name, b.name),
        .region => std.mem.order(u8, a.home_region, b.home_region),
        .status => blk: {
            const av: i8 = if (a.is_logging) |l| (if (l) 1 else 0) else -1;
            const bv: i8 = if (b.is_logging) |l| (if (l) 1 else 0) else -1;
            break :blk std.math.order(av, bv);
        },
        .account => std.mem.order(u8, a.account_id, b.account_id),
    };
}

// ─── Filter ──────────────────────────────────────────────────────────────────

const ItemResolver = struct {
    item: TrailItem,

    pub fn resolve(self: ItemResolver, field: []const u8) filter_mod.FieldValue {
        if (std.mem.eql(u8, field, "name")) return .{ .string = self.item.name };
        if (std.mem.eql(u8, field, "region")) return .{ .string = self.item.home_region };
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
profile_set: *const ProfileSet,
regions: []const []const u8,
live_filter: []const u8 = "",
committed_filter: ?[]u8 = null,
filter_expr: ?filter_mod.ParseResult = null,
sort_keys: [3]SortKey = .{ .name, undefined, undefined },
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
) !TrailsView {
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

pub fn breadcrumb(_: *TrailsView) []const u8 {
    return "Trails";
}

pub fn deinit(self: *TrailsView) void {
    if (self.committed_filter) |f| self.alloc.free(f);
    if (self.filter_expr) |*fe| fe.deinit();
    if (self.sorted_indices.len > 0) self.alloc.free(self.sorted_indices);
    switch (self.state) {
        .active => |shared| {
            shared.cancel.store(true, .release);
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

fn effectiveFilter(self: *const TrailsView) []const u8 {
    return if (self.live_filter.len > 0) self.live_filter else self.committed_filter orelse "";
}

fn matchesItem(self: *const TrailsView, item: TrailItem, text_f: []const u8) bool {
    if (!filter_mod.matchesText(item.name, text_f)) return false;
    if (self.filter_expr) |*fe| {
        const resolver = ItemResolver{ .item = item };
        if (!filter_mod.evalExpr(fe.expr, resolver)) return false;
    }
    return true;
}

fn visibleCount(self: *const TrailsView, items: []const TrailItem, text_f: []const u8) usize {
    var n: usize = 0;
    for (items) |item| {
        if (self.matchesItem(item, text_f)) n += 1;
    }
    return n;
}

pub fn setLiveFilter(self: *TrailsView, text: []const u8) void {
    if (!std.mem.eql(u8, self.live_filter, text)) {
        self.selected = 0;
        self.scroll_offset = 0;
    }
    self.live_filter = text;
}

pub fn commitFilter(self: *TrailsView, text: []const u8) void {
    if (self.committed_filter) |f| self.alloc.free(f);
    self.committed_filter = if (text.len == 0) null else self.alloc.dupe(u8, text) catch null;
    self.live_filter = "";
    self.selected = 0;
    self.scroll_offset = 0;
}

pub fn setFilterExpr(self: *TrailsView, result: filter_mod.ParseResult) void {
    if (self.filter_expr) |*fe| fe.deinit();
    self.filter_expr = result;
    self.selected = 0;
    self.scroll_offset = 0;
}

pub fn clearFilterExpr(self: *TrailsView) void {
    if (self.filter_expr) |*fe| fe.deinit();
    self.filter_expr = null;
    self.selected = 0;
    self.scroll_offset = 0;
}

// ─── Sort helpers ────────────────────────────────────────────────────────────

fn recomputeSort(self: *TrailsView, items: []const TrailItem) void {
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

fn ensureSorted(self: *TrailsView, items: []const TrailItem) void {
    if (!self.sort_dirty and self.sorted_indices.len == items.len) return;
    self.recomputeSort(items);
    self.sort_dirty = false;
}

pub fn setSort(self: *TrailsView, keys: []const SortKey, dir: constants.SortDir) void {
    const n = @min(keys.len, self.sort_keys.len);
    @memcpy(self.sort_keys[0..n], keys[0..n]);
    self.sort_keys_len = if (n > 0) n else 1;
    self.sort_dir = dir;
    self.sort_dirty = true;
    self.sort_applied = true;
    self.selected = 0;
    self.scroll_offset = 0;
}

pub fn clearSort(self: *TrailsView) void {
    self.sort_keys[0] = .name;
    self.sort_keys_len = 1;
    self.sort_dir = .asc;
    self.sort_dirty = true;
    self.sort_applied = false;
    self.selected = 0;
    self.scroll_offset = 0;
}

// ─── Manual refresh ──────────────────────────────────────────────────────────

fn refresh(self: *TrailsView) !void {
    switch (self.state) {
        .active => |shared| {
            shared.cancel.store(true, .release);
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

pub fn handleEvent(self: *TrailsView, event: Event, ctx: ViewContext) !Action {
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
                        var trail_name: ?[]u8 = null;
                        var trail_region: ?[]u8 = null;
                        var trail_creds: Credentials = undefined;

                        for (self.sorted_indices) |orig_idx| {
                            const item = items[orig_idx];
                            if (!self.matchesItem(item, filter)) continue;
                            if (vis == self.selected) {
                                trail_name = ctx.allocator.dupe(u8, item.name) catch null;
                                trail_region = ctx.allocator.dupe(u8, item.home_region) catch null;
                                trail_creds = item.credentials;
                                break;
                            }
                            vis += 1;
                        }
                        shared.mutex.unlock();

                        const name_str = trail_name orelse return .none;
                        const region_str = trail_region orelse {
                            ctx.allocator.free(name_str);
                            return .none;
                        };

                        const v = EventsView.init(ctx.allocator, ctx.io, trail_creds, region_str, name_str, ctx.color_support, self.breadcrumb()) catch {
                            ctx.allocator.free(name_str);
                            ctx.allocator.free(region_str);
                            return .none;
                        };
                        ctx.allocator.free(name_str);
                        ctx.allocator.free(region_str);
                        return .{ .push = .{ .cloudtrail_events = v } };
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
    if (width >= 110) return .wide;
    if (width >= 60) return .medium;
    return .compact;
}

fn nameWidth(inner: usize, mode: Mode) usize {
    const fixed: usize = switch (mode) {
        .wide => ACCOUNT_W + REGION_W + STATUS_W + 3,
        .medium => STATUS_W + 1,
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

fn writeVert(self: *TrailsView, writer: *std.Io.Writer, selected: bool, reset: bool) !void {
    if (selected) {
        try writer.writeAll(self.bg_color);
        try writer.writeAll(terminal.FG_BLACK);
    } else {
        try writer.writeAll(self.fg_color);
    }
    try writer.writeAll(constants.VERTICAL);
    if (reset) try writer.writeAll(terminal.RESET);
}

fn writeSepRow(self: *TrailsView, writer: *std.Io.Writer, name_w: usize, mode: Mode, bottom: bool) !void {
    const left = if (bottom) constants.BOTTOM_LEFT else constants.LEFT_T;
    const mid = if (bottom) constants.BOTTOM_T else constants.CROSS;
    const right = if (bottom) constants.BOTTOM_RIGHT else constants.RIGHT_T;

    try writer.writeAll(self.fg_color);
    try writer.writeAll(left);
    for (0..name_w) |_| try writer.writeAll(constants.HORIZONTAL);
    switch (mode) {
        .wide => {
            try writer.writeAll(mid);
            for (0..ACCOUNT_W) |_| try writer.writeAll(constants.HORIZONTAL);
            try writer.writeAll(mid);
            for (0..REGION_W) |_| try writer.writeAll(constants.HORIZONTAL);
            try writer.writeAll(mid);
            for (0..STATUS_W) |_| try writer.writeAll(constants.HORIZONTAL);
        },
        .medium => {
            try writer.writeAll(mid);
            for (0..STATUS_W) |_| try writer.writeAll(constants.HORIZONTAL);
        },
        .compact => {},
    }
    try writer.writeAll(right);
    try writer.writeAll(terminal.RESET);
}

fn writeHeaderCell(self: *TrailsView, writer: *std.Io.Writer, text: []const u8, cell_w: usize) !void {
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

fn writeHeaderRow(self: *TrailsView, writer: *std.Io.Writer, name_w: usize, mode: Mode) !void {
    try writer.writeAll(self.fg_color);
    try writer.writeAll(constants.VERTICAL);
    try writer.writeAll(terminal.RESET);
    try self.writeHeaderCell(writer, "NAME", name_w);
    switch (mode) {
        .wide => {
            try writer.writeAll(self.fg_color);
            try writer.writeAll(constants.VERTICAL);
            try writer.writeAll(terminal.RESET);
            try self.writeHeaderCell(writer, "ACCOUNT", ACCOUNT_W);
            try writer.writeAll(self.fg_color);
            try writer.writeAll(constants.VERTICAL);
            try writer.writeAll(terminal.RESET);
            try self.writeHeaderCell(writer, "REGION", REGION_W);
            try writer.writeAll(self.fg_color);
            try writer.writeAll(constants.VERTICAL);
            try writer.writeAll(terminal.RESET);
            try self.writeHeaderCell(writer, "STATUS", STATUS_W);
        },
        .medium => {
            try writer.writeAll(self.fg_color);
            try writer.writeAll(constants.VERTICAL);
            try writer.writeAll(terminal.RESET);
            try self.writeHeaderCell(writer, "STATUS", STATUS_W);
        },
        .compact => {},
    }
    try writer.writeAll(self.fg_color);
    try writer.writeAll(constants.VERTICAL);
    try writer.writeAll(terminal.RESET);
}

fn statusLabel(is_logging: ?bool) []const u8 {
    if (is_logging) |l| return if (l) "Logging" else "Stopped";
    return "…";
}

fn writeItemRow(self: *TrailsView, writer: *std.Io.Writer, item: TrailItem, sel: bool, name_w: usize, mode: Mode) !void {
    try self.writeVert(writer, sel, !sel);

    const content_w = if (name_w >= 2) name_w - 2 else 0;
    const max_name = if (content_w >= 2) content_w - 2 else 0;
    try writer.writeByte(' ');
    try writer.writeAll(if (sel) "▸ " else "  ");
    const shown_name = if (item.name.len > max_name) item.name[0..max_name] else item.name;
    try writer.writeAll(shown_name);
    const name_remaining = max_name - shown_name.len;
    if (item.is_org == true and name_remaining > "[org]".len + 1) {
        if (!sel) try writer.writeAll(terminal.DIM);
        try writer.writeAll(" [org]");
        if (!sel) try writer.writeAll(terminal.RESET);
        for ("[org]".len + 1..name_remaining) |_| try writer.writeByte(' ');
    } else {
        for (shown_name.len..max_name) |_| try writer.writeByte(' ');
    }
    try writer.writeByte(' ');

    switch (mode) {
        .wide => {
            try self.writeVert(writer, sel, !sel);
            try writePaddedCell(writer, item.account_id, ACCOUNT_W);
            try self.writeVert(writer, sel, !sel);
            try writePaddedCell(writer, item.home_region, REGION_W);
            try self.writeVert(writer, sel, !sel);
            try writePaddedCell(writer, statusLabel(item.is_logging), STATUS_W);
        },
        .medium => {
            try self.writeVert(writer, sel, !sel);
            try writePaddedCell(writer, statusLabel(item.is_logging), STATUS_W);
        },
        .compact => {},
    }

    try self.writeVert(writer, sel, true);
}

fn writeEmptyRow(self: *TrailsView, writer: *std.Io.Writer, name_w: usize, mode: Mode) !void {
    try self.writeVert(writer, false, true);
    for (0..name_w) |_| try writer.writeByte(' ');
    switch (mode) {
        .wide => {
            try self.writeVert(writer, false, true);
            for (0..ACCOUNT_W) |_| try writer.writeByte(' ');
            try self.writeVert(writer, false, true);
            for (0..REGION_W) |_| try writer.writeByte(' ');
            try self.writeVert(writer, false, true);
            for (0..STATUS_W) |_| try writer.writeByte(' ');
        },
        .medium => {
            try self.writeVert(writer, false, true);
            for (0..STATUS_W) |_| try writer.writeByte(' ');
        },
        .compact => {},
    }
    try self.writeVert(writer, false, true);
}

pub fn render(self: *TrailsView, writer: *std.Io.Writer, size: Coord) !void {
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
                    const msg = std.fmt.bufPrint(&buf, " Error: {s}", .{@errorName(e)}) catch " Error loading trails";
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
