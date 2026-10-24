const std = @import("std");
const colors_mod = @import("../../../ui/colors.zig");
const Credentials = @import("../../../sdk/credentials/fetcher.zig").Credentials;
const ProfileSet = @import("../../profile_set.zig").ProfileSet;
const terminal = @import("../../../terminal/terminal.zig");
const input = @import("../../../terminal/input.zig");
const Event = @import("../../../event.zig").Event;
const view_mod = @import("../../../ui/view.zig");
const Action = view_mod.Action;
const ViewContext = view_mod.ViewContext;
const Coord = terminal.Coord;
const Ec2 = @import("../../../sdk/clients/ec2/client.zig");
const constants = @import("../../../ui/constants.zig");
const ConfirmView = @import("../../../ui/confirm.zig");
const filter_mod = @import("../../../commands/filter.zig");
const NatGatewayView = @import("nat_gateway.zig");

const NatGatewaysView = @This();
pub const name: []const u8 = "NAT Gateways";

const Mode = enum {
    wide, //   >=150: Name | NAT ID | VPC | Subnet | State | Type | Region
    medium, //   >=110: Name | NAT ID | Subnet | State
    narrow, //   >=70: Name | NAT ID | State
    compact, //   <70: Name
};

const Column = enum { nat_id, vpc_id, subnet_id, state, ctype, region };

fn columnsFor(mode: Mode) []const Column {
    return switch (mode) {
        .wide => &.{ .nat_id, .vpc_id, .subnet_id, .state, .ctype, .region },
        .medium => &.{ .nat_id, .subnet_id, .state },
        .narrow => &.{ .nat_id, .state },
        .compact => &.{},
    };
}

fn columnWidth(col: Column) usize {
    return switch (col) {
        .nat_id => 24,
        .vpc_id => 23,
        .subnet_id => 26,
        .state => 11,
        .ctype => 10,
        .region => 16,
    };
}

fn columnTitle(col: Column) []const u8 {
    return switch (col) {
        .nat_id => "NAT ID",
        .vpc_id => "VPC ID",
        .subnet_id => "SUBNET ID",
        .state => "STATE",
        .ctype => "TYPE",
        .region => "REGION",
    };
}

// ─── Local item ──────────────────────────────────────────────────────────────

const NatGatewayItem = struct {
    allocator: std.mem.Allocator,
    /// Value of the Name tag; empty when the gateway has none.
    name: []u8,
    nat_id: []u8,
    vpc_id: []u8,
    subnet_id: []u8,
    state: []u8,
    /// "public" or "private".
    ctype: []u8,
    region: []u8,
    credentials: Credentials,

    pub fn deinit(self: NatGatewayItem) void {
        self.allocator.free(self.name);
        self.allocator.free(self.nat_id);
        self.allocator.free(self.vpc_id);
        self.allocator.free(self.subnet_id);
        self.allocator.free(self.state);
        self.allocator.free(self.ctype);
        self.allocator.free(self.region);
    }

    fn column(self: NatGatewayItem, col: Column) []const u8 {
        return switch (col) {
            .nat_id => self.nat_id,
            .vpc_id => self.vpc_id,
            .subnet_id => self.subnet_id,
            .state => self.state,
            .ctype => self.ctype,
            .region => self.region,
        };
    }

    fn displayName(self: NatGatewayItem) []const u8 {
        return if (self.name.len > 0) self.name else self.nat_id;
    }
};

fn natToItem(allocator: std.mem.Allocator, n: Ec2.NatGateway, region: []const u8, credentials: Credentials) !NatGatewayItem {
    const item_name = try allocator.dupe(u8, n.name);
    errdefer allocator.free(item_name);
    const nat_id = try allocator.dupe(u8, n.id);
    errdefer allocator.free(nat_id);
    const vpc_id = try allocator.dupe(u8, n.vpc_id);
    errdefer allocator.free(vpc_id);
    const subnet_id = try allocator.dupe(u8, n.subnet_id);
    errdefer allocator.free(subnet_id);
    const state = try allocator.dupe(u8, n.state);
    errdefer allocator.free(state);
    // Gateways created before private NAT existed omit the type; they are public.
    const ctype = try allocator.dupe(u8, if (n.connectivity_type.len > 0) n.connectivity_type else "public");
    errdefer allocator.free(ctype);
    const region_copy = try allocator.dupe(u8, region);
    errdefer allocator.free(region_copy);

    return .{
        .allocator = allocator,
        .name = item_name,
        .nat_id = nat_id,
        .vpc_id = vpc_id,
        .subnet_id = subnet_id,
        .state = state,
        .ctype = ctype,
        .region = region_copy,
        .credentials = credentials,
    };
}

// ─── Concurrency ─────────────────────────────────────────────────────────────

const SharedCtx = struct {
    allocator: std.mem.Allocator,
    mutex: std.atomic.Mutex = .unlocked,
    items: std.ArrayList(NatGatewayItem) = .empty,
    region_ctxs: []*RegionCtx,
    pending: std.atomic.Value(usize),
    done: std.atomic.Value(bool) = .init(false),
    /// Set when the view is torn down mid-fetch so threads stop paginating.
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
};

const State = union(enum) {
    active: *SharedCtx,
    failed: anyerror,
};

fn lockMutex(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

fn fetchRegionThread(ctx: *RegionCtx) void {
    defer {
        const prev = ctx.shared.pending.fetchSub(1, .release);
        if (prev == 1) ctx.shared.done.store(true, .release);
        input.notify();
    }

    var client = Ec2.Client.init(ctx.allocator, .{
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

        const result = client.describeNatGateways(.{ .params = .{
            .max_results = 100,
            .next_token = next_token,
        } }) catch |e| {
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

        lockMutex(&ctx.shared.mutex);
        for (result.nat_gateways) |s| {
            const item = natToItem(ctx.allocator, s, ctx.region, ctx.credentials) catch |e| {
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

        if (next_token == null) break;
        input.notify();
    }
}

/// Spawn one fetch thread per (profile, region).
fn startFetch(
    allocator: std.mem.Allocator,
    io: std.Io,
    profile_set: *const ProfileSet,
    regions: []const []const u8,
) !*SharedCtx {
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
    errdefer {
        shared.cancel.store(true, .release);
        for (region_ctxs[0..spawned]) |rctx| {
            rctx.thread.join();
            rctx.allocator.free(rctx.region);
            rctx.allocator.destroy(rctx);
        }
    }

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

    return shared;
}

/// Cancel, join and free everything owned by `shared`.
fn stopFetch(shared: *SharedCtx) void {
    shared.cancel.store(true, .release);
    for (shared.region_ctxs) |rctx| {
        rctx.thread.join();
        rctx.allocator.free(rctx.region);
        rctx.allocator.destroy(rctx);
    }
    shared.allocator.free(shared.region_ctxs);
    for (shared.items.items) |item| item.deinit();
    shared.items.deinit(shared.allocator);
    shared.allocator.destroy(shared);
}

// ─── Sort ────────────────────────────────────────────────────────────────────

pub const SortKey = enum { name, nat_id, vpc_id, subnet_id, state, ctype, region };

const SortCtx = struct {
    items: []const NatGatewayItem,
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

fn compareField(a: NatGatewayItem, b: NatGatewayItem, key: SortKey) std.math.Order {
    return switch (key) {
        .name => std.mem.order(u8, a.displayName(), b.displayName()),
        .nat_id => std.mem.order(u8, a.nat_id, b.nat_id),
        .vpc_id => std.mem.order(u8, a.vpc_id, b.vpc_id),
        .subnet_id => std.mem.order(u8, a.subnet_id, b.subnet_id),
        .state => std.mem.order(u8, a.state, b.state),
        .ctype => std.mem.order(u8, a.ctype, b.ctype),
        .region => std.mem.order(u8, a.region, b.region),
    };
}

// ─── Filter ──────────────────────────────────────────────────────────────────

const ItemResolver = struct {
    item: NatGatewayItem,

    pub fn resolve(self: ItemResolver, field: []const u8) filter_mod.FieldValue {
        if (std.mem.eql(u8, field, "name")) return .{ .string = self.item.name };
        if (std.mem.eql(u8, field, "nat_id") or std.mem.eql(u8, field, "id")) return .{ .string = self.item.nat_id };
        if (std.mem.eql(u8, field, "vpc_id") or std.mem.eql(u8, field, "vpc")) return .{ .string = self.item.vpc_id };
        if (std.mem.eql(u8, field, "subnet_id") or std.mem.eql(u8, field, "subnet")) return .{ .string = self.item.subnet_id };
        if (std.mem.eql(u8, field, "state")) return .{ .string = self.item.state };
        if (std.mem.eql(u8, field, "type")) return .{ .string = self.item.ctype };
        if (std.mem.eql(u8, field, "region")) return .{ .string = self.item.region };
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
sort_dirty: bool = false,
sort_applied: bool = false,

// ─── Init / deinit ───────────────────────────────────────────────────────────

pub fn init(
    allocator: std.mem.Allocator,
    io: std.Io,
    profile_set: *const ProfileSet,
    regions: []const []const u8,
    color_support: terminal.ColorSupport,
) !NatGatewaysView {
    const colors = colors_mod.purple(color_support);
    const shared = try startFetch(allocator, io, profile_set, regions);

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

pub fn breadcrumb(_: *NatGatewaysView) []const u8 {
    return "VPC " ++ constants.SEP_ARROW ++ " NAT Gateways";
}

pub fn deinit(self: *NatGatewaysView) void {
    if (self.committed_filter) |f| self.alloc.free(f);
    if (self.filter_expr) |*fe| fe.deinit();
    if (self.sorted_indices.len > 0) self.alloc.free(self.sorted_indices);
    switch (self.state) {
        .active => |shared| stopFetch(shared),
        .failed => {},
    }
}

// ─── Filter helpers ──────────────────────────────────────────────────────────

fn effectiveFilter(self: *const NatGatewaysView) []const u8 {
    return if (self.live_filter.len > 0) self.live_filter else self.committed_filter orelse "";
}

fn matchesItem(self: *const NatGatewaysView, item: NatGatewayItem, text_f: []const u8) bool {
    if (!filter_mod.matchesText(item.displayName(), text_f)) return false;
    if (self.filter_expr) |*fe| {
        const resolver = ItemResolver{ .item = item };
        if (!filter_mod.evalExpr(fe.expr, resolver)) return false;
    }
    return true;
}

fn visibleCount(self: *const NatGatewaysView, items: []const NatGatewayItem, text_f: []const u8) usize {
    var n: usize = 0;
    for (items) |item| {
        if (self.matchesItem(item, text_f)) n += 1;
    }
    return n;
}

fn resetSelection(self: *NatGatewaysView) void {
    self.selected = 0;
    self.scroll_offset = 0;
}

pub fn setLiveFilter(self: *NatGatewaysView, text: []const u8) void {
    if (!std.mem.eql(u8, self.live_filter, text)) self.resetSelection();
    self.live_filter = text;
}

pub fn commitFilter(self: *NatGatewaysView, text: []const u8) void {
    if (self.committed_filter) |f| self.alloc.free(f);
    self.committed_filter = if (text.len == 0) null else self.alloc.dupe(u8, text) catch null;
    self.live_filter = "";
    self.resetSelection();
}

pub fn setFilterExpr(self: *NatGatewaysView, result: filter_mod.ParseResult) void {
    if (self.filter_expr) |*fe| fe.deinit();
    self.filter_expr = result;
    self.resetSelection();
}

pub fn clearFilterExpr(self: *NatGatewaysView) void {
    if (self.filter_expr) |*fe| fe.deinit();
    self.filter_expr = null;
    self.resetSelection();
}

// ─── Sort helpers ────────────────────────────────────────────────────────────

fn ensureSorted(self: *NatGatewaysView, items: []const NatGatewayItem) void {
    if (!self.sort_dirty and self.sorted_indices.len == items.len) return;
    if (self.sorted_indices.len > 0) {
        self.alloc.free(self.sorted_indices);
        self.sorted_indices = &.{};
    }
    self.sort_dirty = false;
    const indices = self.alloc.alloc(usize, items.len) catch return;
    for (indices, 0..) |*idx, i| idx.* = i;
    std.mem.sortUnstable(usize, indices, SortCtx{
        .items = items,
        .keys = self.sort_keys[0..self.sort_keys_len],
        .dir = self.sort_dir,
    }, SortCtx.lessThan);
    self.sorted_indices = indices;
}

pub fn setSort(self: *NatGatewaysView, keys: []const SortKey, dir: constants.SortDir) void {
    const n = @min(keys.len, self.sort_keys.len);
    @memcpy(self.sort_keys[0..n], keys[0..n]);
    self.sort_keys_len = if (n > 0) n else 1;
    self.sort_dir = dir;
    self.sort_dirty = true;
    self.sort_applied = true;
    self.resetSelection();
}

pub fn clearSort(self: *NatGatewaysView) void {
    self.sort_keys[0] = .name;
    self.sort_keys_len = 1;
    self.sort_dir = .asc;
    self.sort_dirty = true;
    self.sort_applied = false;
    self.resetSelection();
}

// ─── Manual refresh ──────────────────────────────────────────────────────────

fn refresh(self: *NatGatewaysView) !void {
    switch (self.state) {
        .active => |shared| stopFetch(shared),
        .failed => {},
    }
    // Neither state owns a live SharedCtx now; keep deinit safe if startFetch fails.
    self.state = .{ .failed = error.Refreshing };

    if (self.sorted_indices.len > 0) {
        self.alloc.free(self.sorted_indices);
        self.sorted_indices = &.{};
    }
    self.sort_dirty = true;

    const shared = try startFetch(self.alloc, self.io, self.profile_set, self.regions);
    self.state = .{ .active = shared };
    self.resetSelection();
}

// ─── Event handling ──────────────────────────────────────────────────────────

pub fn handleEvent(self: *NatGatewaysView, event: Event, ctx: ViewContext) !Action {
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
                'r' => self.refresh() catch |e| {
                    self.state = .{ .failed = e };
                },
                'j' => if (count > 0 and self.selected < count - 1) {
                    self.selected += 1;
                },
                'k' => if (self.selected > 0) {
                    self.selected -= 1;
                },
                'g' => {
                    if (self.pending_g) {
                        self.resetSelection();
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
                .active => |shared| {
                    lockMutex(&shared.mutex);
                    defer shared.mutex.unlock();
                    const items = shared.items.items;
                    const filter = self.effectiveFilter();
                    self.ensureSorted(items);

                    var vis: usize = 0;
                    for (self.sorted_indices) |orig_idx| {
                        const item = items[orig_idx];
                        if (!self.matchesItem(item, filter)) continue;
                        if (vis == self.selected) {
                            const v = try NatGatewayView.init(
                                ctx.allocator,
                                ctx.io,
                                item.credentials,
                                item.region,
                                item.nat_id,
                                item.displayName(),
                                self.fg_color,
                                self.bg_color,
                                self.breadcrumb(),
                            );
                            return .{ .push = .{ .vpc_nat_gateway = v } };
                        }
                        vis += 1;
                    }
                },
                .failed => {},
            },
            .escape => {
                if (self.committed_filter) |f| {
                    self.alloc.free(f);
                    self.committed_filter = null;
                    self.resetSelection();
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
    if (width >= 150) return .wide;
    if (width >= 110) return .medium;
    if (width >= 70) return .narrow;
    return .compact;
}

fn nameWidth(inner: usize, mode: Mode) usize {
    var fixed: usize = 0;
    for (columnsFor(mode)) |col| fixed += columnWidth(col) + 1;
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

fn writeVert(self: *NatGatewaysView, writer: *std.Io.Writer, selected: bool, reset: bool) !void {
    if (selected) {
        try writer.writeAll(self.bg_color);
        try writer.writeAll(terminal.FG_BLACK);
    } else {
        try writer.writeAll(self.fg_color);
    }
    try writer.writeAll(constants.VERTICAL);
    if (reset) try writer.writeAll(terminal.RESET);
}

fn writeSepRow(self: *NatGatewaysView, writer: *std.Io.Writer, name_w: usize, mode: Mode, bottom: bool) !void {
    const left = if (bottom) constants.BOTTOM_LEFT else constants.LEFT_T;
    const mid = if (bottom) constants.BOTTOM_T else constants.CROSS;
    const right = if (bottom) constants.BOTTOM_RIGHT else constants.RIGHT_T;

    try writer.writeAll(self.fg_color);
    try writer.writeAll(left);
    for (0..name_w) |_| try writer.writeAll(constants.HORIZONTAL);
    for (columnsFor(mode)) |col| {
        try writer.writeAll(mid);
        for (0..columnWidth(col)) |_| try writer.writeAll(constants.HORIZONTAL);
    }
    try writer.writeAll(right);
    try writer.writeAll(terminal.RESET);
}

fn writeHeaderCell(self: *NatGatewaysView, writer: *std.Io.Writer, text: []const u8, cell_w: usize) !void {
    const content_w = if (cell_w >= 2) cell_w - 2 else 0;
    const text_len = @min(text.len, content_w);
    const pad = content_w - text_len;
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

fn writeHeaderRow(self: *NatGatewaysView, writer: *std.Io.Writer, name_w: usize, mode: Mode) !void {
    try self.writeVert(writer, false, true);
    try self.writeHeaderCell(writer, "NAME", name_w);
    for (columnsFor(mode)) |col| {
        try self.writeVert(writer, false, true);
        try self.writeHeaderCell(writer, columnTitle(col), columnWidth(col));
    }
    try self.writeVert(writer, false, true);
}

fn writeItemRow(self: *NatGatewaysView, writer: *std.Io.Writer, item: NatGatewayItem, sel: bool, name_w: usize, mode: Mode) !void {
    try self.writeVert(writer, sel, !sel);

    const content_w = if (name_w >= 2) name_w - 2 else 0;
    const max_name = if (content_w >= 2) content_w - 2 else 0;
    const display = item.displayName();
    try writer.writeByte(' ');
    try writer.writeAll(if (sel) "▸ " else "  ");
    const shown_name = if (display.len > max_name) display[0..max_name] else display;
    try writer.writeAll(shown_name);
    const name_remaining = max_name - shown_name.len;
    for (0..name_remaining) |_| try writer.writeByte(' ');
    try writer.writeByte(' ');

    for (columnsFor(mode)) |col| {
        try self.writeVert(writer, sel, !sel);
        try writePaddedCell(writer, item.column(col), columnWidth(col));
    }

    try self.writeVert(writer, sel, true);
}

fn writeEmptyRow(self: *NatGatewaysView, writer: *std.Io.Writer, name_w: usize, mode: Mode) !void {
    try self.writeVert(writer, false, true);
    for (0..name_w) |_| try writer.writeByte(' ');
    for (columnsFor(mode)) |col| {
        try self.writeVert(writer, false, true);
        for (0..columnWidth(col)) |_| try writer.writeByte(' ');
    }
    try self.writeVert(writer, false, true);
}

pub fn render(self: *NatGatewaysView, writer: *std.Io.Writer, size: Coord) !void {
    if (size.x < 10 or size.y < 4) return;
    const w: usize = @intCast(size.x);
    const h: usize = @intCast(size.y);
    const inner = w - 2;
    const mode = modeFor(size.x);
    const name_w = nameWidth(inner, mode);
    const show_header = h >= 6;
    const data_rows = if (show_header) h - 3 else h - 1;

    // Transition active → failed once every thread finished with no results and an error.
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
                        stopFetch(shared);
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
                self.resetSelection();
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
                    const msg = std.fmt.bufPrint(&buf, " Error: {s}", .{@errorName(e)}) catch " Error loading NAT gateways";
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

// ============================================================================
// Tests
// ============================================================================

test "nameWidth shrinks with columns" {
    try std.testing.expect(nameWidth(150, .compact) == 150);
    try std.testing.expect(nameWidth(150, .narrow) < 150);
    try std.testing.expect(nameWidth(150, .medium) < nameWidth(150, .narrow));
    try std.testing.expect(nameWidth(150, .wide) < nameWidth(150, .medium));
    try std.testing.expectEqual(@as(usize, 2), nameWidth(10, .wide));
}

test "modeFor thresholds" {
    try std.testing.expectEqual(Mode.wide, modeFor(150));
    try std.testing.expectEqual(Mode.medium, modeFor(110));
    try std.testing.expectEqual(Mode.narrow, modeFor(70));
    try std.testing.expectEqual(Mode.compact, modeFor(69));
}

test "compareField orders by state" {
    var a: NatGatewayItem = undefined;
    a.state = @constCast("available");
    var b: NatGatewayItem = undefined;
    b.state = @constCast("pending");
    try std.testing.expectEqual(std.math.Order.lt, compareField(a, b, .state));
}
