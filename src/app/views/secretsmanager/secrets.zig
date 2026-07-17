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
const SecretsManager = @import("../../../sdk/clients/secretsmanager/client.zig");
const constants = @import("../../../ui/constants.zig");
const ConfirmView = @import("../../../ui/confirm.zig");
const filter_mod = @import("../../../commands/filter.zig");
const SecretView = @import("secret.zig");

const SecretsView = @This();
pub const name: []const u8 = "Secrets";

const ACCOUNT_W: usize = 14;
const REGION_W: usize = 16;
const CREATED_W: usize = 12;
const ACCESSED_W: usize = 15;

const Mode = enum {
    wide, //   >=120: Name | Account | Region | Created | Last Accessed
    medium, //  >=90: Name | Region | Created
    compact, //  <90: Name
};

pub const SortKey = enum { name, account, region, created, last_accessed };

const SortCtx = struct {
    items: []const SecretItem,
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

fn compareField(a: SecretItem, b: SecretItem, key: SortKey) std.math.Order {
    return switch (key) {
        .name => std.mem.order(u8, a.name, b.name),
        .account => std.mem.order(u8, a.account_id, b.account_id),
        .region => std.mem.order(u8, a.region, b.region),
        .created => std.math.order(a.created_date orelse -1, b.created_date orelse -1),
        .last_accessed => std.math.order(a.last_accessed_date orelse -1, b.last_accessed_date orelse -1),
    };
}

const SecretResolver = struct {
    item: SecretItem,

    pub fn resolve(self: SecretResolver, field: []const u8) filter_mod.FieldValue {
        if (std.mem.eql(u8, field, "name")) return .{ .string = self.item.name };
        if (std.mem.eql(u8, field, "account") or std.mem.eql(u8, field, "account_id")) return .{ .string = self.item.account_id };
        if (std.mem.eql(u8, field, "region")) return .{ .string = self.item.region };
        if (std.mem.eql(u8, field, "description")) return .{ .string = self.item.description };
        return .unknown;
    }
};

// ─── Item stored in the view ─────────────────────────────────────────────────

const SecretItem = struct {
    allocator: std.mem.Allocator,
    name: []u8,
    account_id: []u8,
    region: []u8,
    description: []u8,
    arn: []u8,
    created_date: ?f64,
    last_accessed_date: ?f64,
    credentials: Credentials,

    pub fn deinit(self: SecretItem) void {
        self.allocator.free(self.name);
        self.allocator.free(self.account_id);
        self.allocator.free(self.region);
        self.allocator.free(self.description);
        self.allocator.free(self.arn);
    }
};

/// Parse region and account_id from secret ARN:
/// arn:aws:secretsmanager:{region}:{account}:secret:{name}
fn parseArn(arn: []const u8) struct { region: []const u8, account_id: []const u8 } {
    var it = std.mem.splitScalar(u8, arn, ':');
    _ = it.next(); // arn
    _ = it.next(); // aws
    _ = it.next(); // secretsmanager
    const region = it.next() orelse "";
    const account_id = it.next() orelse "";
    return .{ .region = region, .account_id = account_id };
}

fn secretToItem(allocator: std.mem.Allocator, s: SecretsManager.SecretEntry, credentials: Credentials) !SecretItem {
    const parsed = parseArn(s.arn);

    const item_name = try allocator.dupe(u8, s.name);
    errdefer allocator.free(item_name);

    const account_id = try allocator.dupe(u8, parsed.account_id);
    errdefer allocator.free(account_id);

    const region = try allocator.dupe(u8, if (parsed.region.len > 0) parsed.region else "—");
    errdefer allocator.free(region);

    const description = try allocator.dupe(u8, s.description);
    errdefer allocator.free(description);

    const arn = try allocator.dupe(u8, s.arn);
    errdefer allocator.free(arn);

    return .{
        .allocator = allocator,
        .name = item_name,
        .account_id = account_id,
        .region = region,
        .description = description,
        .arn = arn,
        .created_date = s.created_date,
        .last_accessed_date = s.last_accessed_date,
        .credentials = credentials,
    };
}

// ─── Concurrency ─────────────────────────────────────────────────────────────

const SharedCtx = struct {
    allocator: std.mem.Allocator,
    mutex: std.atomic.Mutex = .unlocked,
    items: std.ArrayList(SecretItem) = .empty,
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

    var client = SecretsManager.Client.init(ctx.allocator, .{
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
        const result = client.listSecrets(.{
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
        for (result.secrets) |s| {
            const item = secretToItem(ctx.allocator, s, ctx.credentials) catch |e| {
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
}

fn lockMutex(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

// ─── Sort ────────────────────────────────────────────────────────────────────

fn recomputeSort(self: *SecretsView, items: []const SecretItem) void {
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

fn ensureSorted(self: *SecretsView, items: []const SecretItem) void {
    if (!self.sort_dirty and self.sorted_indices.len == items.len) return;
    self.recomputeSort(items);
    self.sort_dirty = false;
}

pub fn setSort(self: *SecretsView, keys: []const SortKey, dir: constants.SortDir) void {
    const n = @min(keys.len, self.sort_keys.len);
    @memcpy(self.sort_keys[0..n], keys[0..n]);
    self.sort_keys_len = if (n > 0) n else 1;
    self.sort_dir = dir;
    self.sort_dirty = true;
    self.sort_applied = true;
    self.selected = 0;
    self.scroll_offset = 0;
}

pub fn clearSort(self: *SecretsView) void {
    self.sort_keys[0] = .name;
    self.sort_keys_len = 1;
    self.sort_dir = .asc;
    self.sort_dirty = true;
    self.sort_applied = false;
    self.selected = 0;
    self.scroll_offset = 0;
}

// ─── Filter ──────────────────────────────────────────────────────────────────

fn effectiveFilter(self: *const SecretsView) []const u8 {
    return if (self.live_filter.len > 0) self.live_filter else self.committed_filter orelse "";
}

fn matchesItem(self: *const SecretsView, item: SecretItem, text_f: []const u8) bool {
    if (!filter_mod.matchesText(item.name, text_f)) return false;
    if (self.filter_expr) |*fe| {
        const resolver = SecretResolver{ .item = item };
        if (!filter_mod.evalExpr(fe.expr, resolver)) return false;
    }
    return true;
}

fn visibleCount(self: *const SecretsView, items: []const SecretItem, text_f: []const u8) usize {
    var n: usize = 0;
    for (items) |item| {
        if (self.matchesItem(item, text_f)) n += 1;
    }
    return n;
}

pub fn setLiveFilter(self: *SecretsView, text: []const u8) void {
    if (!std.mem.eql(u8, self.live_filter, text)) {
        self.selected = 0;
        self.scroll_offset = 0;
    }
    self.live_filter = text;
}

pub fn commitFilter(self: *SecretsView, text: []const u8) void {
    if (self.committed_filter) |f| self.alloc.free(f);
    self.committed_filter = if (text.len == 0) null else self.alloc.dupe(u8, text) catch null;
    self.live_filter = "";
    self.selected = 0;
    self.scroll_offset = 0;
}

pub fn setFilterExpr(self: *SecretsView, result: filter_mod.ParseResult) void {
    if (self.filter_expr) |*fe| fe.deinit();
    self.filter_expr = result;
    self.selected = 0;
    self.scroll_offset = 0;
}

pub fn clearFilterExpr(self: *SecretsView) void {
    if (self.filter_expr) |*fe| fe.deinit();
    self.filter_expr = null;
    self.selected = 0;
    self.scroll_offset = 0;
}

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
) !SecretsView {
    const colors = colors_mod.iam(color_support);

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

pub fn breadcrumb(_: *SecretsView) []const u8 {
    return "Secrets";
}

pub fn deinit(self: *SecretsView) void {
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

// ─── Manual refresh ──────────────────────────────────────────────────────────

fn refresh(self: *SecretsView) !void {
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

pub fn handleEvent(self: *SecretsView, event: Event, ctx: ViewContext) !Action {
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
                if (self.state == .active) {
                    const shared = self.state.active;
                    lockMutex(&shared.mutex);
                    defer shared.mutex.unlock();
                    const items = shared.items.items;
                    const filter = self.effectiveFilter();
                    var vis_idx: usize = 0;
                    var selected_item: ?SecretItem = null;
                    self.ensureSorted(items);
                    for (self.sorted_indices) |orig_idx| {
                        const item = items[orig_idx];
                        if (!self.matchesItem(item, filter)) continue;
                        if (vis_idx == self.selected) {
                            selected_item = item;
                            break;
                        }
                        vis_idx += 1;
                    }
                    if (selected_item) |item| {
                        const v = try SecretView.init(
                            ctx.allocator,
                            ctx.io,
                            item.credentials,
                            item.name,
                            item.arn,
                            item.account_id,
                            item.region,
                            item.description,
                            item.created_date,
                            item.last_accessed_date,
                            ctx.color_support,
                        );
                        return .{ .push = .{ .secretsmanager_secret = v } };
                    }
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
    if (width >= 120) return .wide;
    if (width >= 90) return .medium;
    return .compact;
}

fn nameWidth(inner: usize, mode: Mode) usize {
    const fixed: usize = switch (mode) {
        .wide => ACCOUNT_W + REGION_W + CREATED_W + ACCESSED_W + 4,
        .medium => REGION_W + CREATED_W + 2,
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

fn writeVert(self: *SecretsView, writer: *std.Io.Writer, selected: bool, reset: bool) !void {
    if (selected) {
        try writer.writeAll(self.bg_color);
        try writer.writeAll(terminal.FG_BLACK);
    } else {
        try writer.writeAll(self.fg_color);
    }
    try writer.writeAll(constants.VERTICAL);
    if (reset) try writer.writeAll(terminal.RESET);
}

fn writeSepRow(self: *SecretsView, writer: *std.Io.Writer, name_w: usize, mode: Mode, bottom: bool) !void {
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
            for (0..CREATED_W) |_| try writer.writeAll(constants.HORIZONTAL);
            try writer.writeAll(mid);
            for (0..ACCESSED_W) |_| try writer.writeAll(constants.HORIZONTAL);
        },
        .medium => {
            try writer.writeAll(mid);
            for (0..REGION_W) |_| try writer.writeAll(constants.HORIZONTAL);
            try writer.writeAll(mid);
            for (0..CREATED_W) |_| try writer.writeAll(constants.HORIZONTAL);
        },
        .compact => {},
    }
    try writer.writeAll(right);
    try writer.writeAll(terminal.RESET);
}

fn writeHeaderCell(self: *SecretsView, writer: *std.Io.Writer, text: []const u8, cell_w: usize) !void {
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

fn writeHeaderRow(self: *SecretsView, writer: *std.Io.Writer, name_w: usize, mode: Mode) !void {
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
            try self.writeHeaderCell(writer, "CREATED", CREATED_W);
            try writer.writeAll(self.fg_color);
            try writer.writeAll(constants.VERTICAL);
            try writer.writeAll(terminal.RESET);
            try self.writeHeaderCell(writer, "LAST ACCESSED", ACCESSED_W);
        },
        .medium => {
            try writer.writeAll(self.fg_color);
            try writer.writeAll(constants.VERTICAL);
            try writer.writeAll(terminal.RESET);
            try self.writeHeaderCell(writer, "REGION", REGION_W);
            try writer.writeAll(self.fg_color);
            try writer.writeAll(constants.VERTICAL);
            try writer.writeAll(terminal.RESET);
            try self.writeHeaderCell(writer, "CREATED", CREATED_W);
        },
        .compact => {},
    }
    try writer.writeAll(self.fg_color);
    try writer.writeAll(constants.VERTICAL);
    try writer.writeAll(terminal.RESET);
}

fn formatEpochSeconds(buf: []u8, secs_f: ?f64) []u8 {
    const secs_val = secs_f orelse return std.fmt.bufPrint(buf, "-", .{}) catch buf[0..0];
    if (secs_val <= 0) return std.fmt.bufPrint(buf, "-", .{}) catch buf[0..0];
    const secs: u64 = @intFromFloat(secs_val);
    const epoch_secs = std.time.epoch.EpochSeconds{ .secs = secs };
    const epoch_day = epoch_secs.getEpochDay();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}", .{
        year_day.year,
        month_day.month.numeric(),
        month_day.day_index + 1,
    }) catch buf[0..0];
}

fn writeItemRow(self: *SecretsView, writer: *std.Io.Writer, item: SecretItem, sel: bool, name_w: usize, mode: Mode) !void {
    try self.writeVert(writer, sel, !sel);

    const content_w = if (name_w >= 2) name_w - 2 else 0;
    const max_name = if (content_w >= 2) content_w - 2 else 0;
    try writer.writeByte(' ');
    try writer.writeAll(if (sel) "▸ " else "  ");
    const shown_name = if (item.name.len > max_name) item.name[0..max_name] else item.name;
    try writer.writeAll(shown_name);
    const name_remaining = max_name - shown_name.len;
    if (name_remaining > 4 and item.description.len > 0) {
        if (!sel) try writer.writeAll(terminal.DIM);
        try writer.writeAll(" · ");
        const max_desc = name_remaining - 3;
        const shown_desc = if (item.description.len > max_desc) item.description[0..max_desc] else item.description;
        try writer.writeAll(shown_desc);
        if (!sel) try writer.writeAll(terminal.RESET);
        const used = 3 + shown_desc.len;
        for (used..name_remaining) |_| try writer.writeByte(' ');
    } else {
        for (shown_name.len..max_name) |_| try writer.writeByte(' ');
    }
    try writer.writeByte(' ');

    switch (mode) {
        .wide => {
            try self.writeVert(writer, sel, !sel);
            try writePaddedCell(writer, item.account_id, ACCOUNT_W);
            try self.writeVert(writer, sel, !sel);
            try writePaddedCell(writer, item.region, REGION_W);
            try self.writeVert(writer, sel, !sel);
            var created_buf: [16]u8 = undefined;
            try writePaddedCell(writer, formatEpochSeconds(&created_buf, item.created_date), CREATED_W);
            try self.writeVert(writer, sel, !sel);
            var accessed_buf: [16]u8 = undefined;
            try writePaddedCell(writer, formatEpochSeconds(&accessed_buf, item.last_accessed_date), ACCESSED_W);
        },
        .medium => {
            try self.writeVert(writer, sel, !sel);
            try writePaddedCell(writer, item.region, REGION_W);
            try self.writeVert(writer, sel, !sel);
            var created_buf: [16]u8 = undefined;
            try writePaddedCell(writer, formatEpochSeconds(&created_buf, item.created_date), CREATED_W);
        },
        .compact => {},
    }

    try self.writeVert(writer, sel, true);
}

fn writeEmptyRow(self: *SecretsView, writer: *std.Io.Writer, name_w: usize, mode: Mode) !void {
    try self.writeVert(writer, false, true);
    for (0..name_w) |_| try writer.writeByte(' ');
    switch (mode) {
        .wide => {
            try self.writeVert(writer, false, true);
            for (0..ACCOUNT_W) |_| try writer.writeByte(' ');
            try self.writeVert(writer, false, true);
            for (0..REGION_W) |_| try writer.writeByte(' ');
            try self.writeVert(writer, false, true);
            for (0..CREATED_W) |_| try writer.writeByte(' ');
            try self.writeVert(writer, false, true);
            for (0..ACCESSED_W) |_| try writer.writeByte(' ');
        },
        .medium => {
            try self.writeVert(writer, false, true);
            for (0..REGION_W) |_| try writer.writeByte(' ');
            try self.writeVert(writer, false, true);
            for (0..CREATED_W) |_| try writer.writeByte(' ');
        },
        .compact => {},
    }
    try self.writeVert(writer, false, true);
}

pub fn render(self: *SecretsView, writer: *std.Io.Writer, size: Coord) !void {
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
                    const msg = std.fmt.bufPrint(&buf, " Error: {s}", .{@errorName(e)}) catch " Error loading secrets";
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
