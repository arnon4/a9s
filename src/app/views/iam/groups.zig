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
const Iam = @import("../../../sdk/clients/iam/client.zig");
const constants = @import("../../../ui/constants.zig");
const ConfirmView = @import("../../../ui/confirm.zig");
const IamGroupView = @import("group.zig");
const filter_mod = @import("../../../commands/filter.zig");

const IamGroupsView = @This();
pub const name: []const u8 = "Groups";

// NAME column: IAM group name max = 128 chars, but 64 is a sane visual cap.
// ACCOUNT column: 12-digit AWS account id + 2 padding.
// PATH column: typical paths are short; fixed width keeps the table stable.
// CREATED column: ISO-8601 date "2013-04-18" = 10 chars + 2 padding.
const ACCOUNT_W: usize = 14;
const PATH_W: usize = 20;
const CREATED_W: usize = 14;

pub const GroupSortKey = enum { name, account, path, created };

const SortCtx = struct {
    items: []const GroupItem,
    keys: []const GroupSortKey,
    dir: constants.SortDir,

    fn lessThan(ctx: @This(), a: usize, b: usize) bool {
        for (ctx.keys) |key| {
            const ord = compareField(ctx.items[a], ctx.items[b], key);
            if (ord != .eq) return if (ctx.dir == .asc) ord == .lt else ord == .gt;
        }
        return false;
    }
};

fn compareField(a: GroupItem, b: GroupItem, key: GroupSortKey) std.math.Order {
    return switch (key) {
        .name => std.mem.order(u8, a.name, b.name),
        .account => std.mem.order(u8, a.account_id, b.account_id),
        .path => std.mem.order(u8, a.path, b.path),
        .created => std.mem.order(u8, a.create_date, b.create_date),
    };
}

// ─── Local item ─────────────────────────────────────────────────────────────

const GroupItem = struct {
    allocator: std.mem.Allocator,
    name: []u8,
    arn: []u8,
    account_id: []u8,
    path: []u8,
    create_date: []u8,
    cred_idx: usize,

    pub fn deinit(self: GroupItem) void {
        self.allocator.free(self.name);
        self.allocator.free(self.arn);
        self.allocator.free(self.account_id);
        self.allocator.free(self.path);
        self.allocator.free(self.create_date);
    }
};

const GroupResolver = struct {
    item: GroupItem,

    pub fn resolve(self: GroupResolver, field: []const u8) filter_mod.FieldValue {
        if (std.mem.eql(u8, field, "name")) return .{ .string = self.item.name };
        if (std.mem.eql(u8, field, "arn")) return .{ .string = self.item.arn };
        if (std.mem.eql(u8, field, "account") or std.mem.eql(u8, field, "account_id")) return .{ .string = self.item.account_id };
        if (std.mem.eql(u8, field, "path")) return .{ .string = self.item.path };
        if (std.mem.eql(u8, field, "created") or std.mem.eql(u8, field, "create_date")) return .{ .string = self.item.create_date };
        return .unknown;
    }
};

// Parse account id from IAM group ARN: arn:aws:iam::{account}:group/{name}
fn parseAccountId(arn: []const u8) []const u8 {
    var it = std.mem.splitScalar(u8, arn, ':');
    _ = it.next(); // arn
    _ = it.next(); // aws
    _ = it.next(); // iam
    _ = it.next(); // region (empty for IAM)
    return it.next() orelse "";
}

fn groupToItem(allocator: std.mem.Allocator, g: Iam.IamGroup, cred_idx: usize) !GroupItem {
    const item_name = try allocator.dupe(u8, g.group_name);
    errdefer allocator.free(item_name);
    const arn = try allocator.dupe(u8, g.arn);
    errdefer allocator.free(arn);
    const account_id = try allocator.dupe(u8, parseAccountId(g.arn));
    errdefer allocator.free(account_id);
    const path = try allocator.dupe(u8, g.path);
    errdefer allocator.free(path);
    const create_date = try allocator.dupe(u8, if (g.create_date.len >= 10) g.create_date[0..10] else g.create_date);
    errdefer allocator.free(create_date);
    return .{
        .allocator = allocator,
        .name = item_name,
        .arn = arn,
        .account_id = account_id,
        .path = path,
        .create_date = create_date,
        .cred_idx = cred_idx,
    };
}

// ─── Concurrency ─────────────────────────────────────────────────────────────

const FetchCtx = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    creds: []Credentials,
    mutex: std.atomic.Mutex = .unlocked,
    items: std.ArrayList(GroupItem) = .empty,
    done: std.atomic.Value(bool) = .init(false),
    cancel: std.atomic.Value(bool) = .init(false),
    err: ?anyerror = null,
    thread: std.Thread = undefined,
};

const State = union(enum) {
    loading: *FetchCtx,
    ready: *FetchCtx,
    failed: anyerror,
};

// Records the first error seen across concurrent profile-list threads.
// Caller must NOT hold ctx.mutex when calling this.
fn setErr(ctx: *FetchCtx, e: anyerror) void {
    lockMutex(&ctx.mutex);
    if (ctx.err == null) ctx.err = e;
    ctx.mutex.unlock();
}

// Lists all groups for a single profile (cred_idx into ctx.creds), appending into shared ctx.items.
fn listProfileThread(ctx: *FetchCtx, cred_idx: usize) void {
    var client = Iam.Client.init(ctx.allocator, .{
        .io = ctx.io,
        .credentials = ctx.creds[cred_idx],
    }) catch |e| {
        setErr(ctx, e);
        return;
    };
    defer client.deinit();

    var next_marker: ?[]u8 = null;
    defer if (next_marker) |m| ctx.allocator.free(m);

    while (true) {
        if (ctx.cancel.load(.acquire)) return;

        const result = client.listGroups(.{
            .params = .{ .marker = next_marker },
        }) catch |e| {
            setErr(ctx, e);
            return;
        };
        defer result.deinit();

        if (next_marker) |m| ctx.allocator.free(m);
        next_marker = if (result.next_marker) |m|
            ctx.allocator.dupe(u8, m) catch |e| {
                setErr(ctx, e);
                return;
            }
        else
            null;

        const is_last = result.next_marker == null;

        lockMutex(&ctx.mutex);
        for (result.groups) |g| {
            const item = groupToItem(ctx.allocator, g, cred_idx) catch |e| {
                ctx.mutex.unlock();
                setErr(ctx, e);
                return;
            };
            ctx.items.append(ctx.allocator, item) catch |e| {
                item.deinit();
                ctx.mutex.unlock();
                setErr(ctx, e);
                return;
            };
        }
        ctx.mutex.unlock();

        if (is_last) break;
        input.notify();
    }
}

fn fetchThread(ctx: *FetchCtx) void {
    defer {
        ctx.done.store(true, .release);
        input.notify();
    }

    const list_threads = ctx.allocator.alloc(std.Thread, ctx.creds.len) catch |e| {
        ctx.err = e;
        return;
    };
    defer ctx.allocator.free(list_threads);

    var spawned: usize = 0;
    for (0..ctx.creds.len) |i| {
        list_threads[spawned] = std.Thread.spawn(.{}, listProfileThread, .{ ctx, i }) catch break;
        spawned += 1;
    }
    for (0..spawned) |j| list_threads[j].join();
}

fn lockMutex(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
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
color_support: terminal.ColorSupport,
committed_filter: ?[]u8 = null,
live_filter: []const u8 = "",
filter_expr: ?filter_mod.ParseResult = null,
sort_keys: [4]GroupSortKey = .{ .name, undefined, undefined, undefined },
sort_keys_len: usize = 1,
sort_dir: constants.SortDir = .asc,
sorted_indices: []usize = &.{},
last_sorted_len: usize = 0,
sort_dirty: bool = false,
sort_applied: bool = false,
breadcrumb_buf: [128]u8 = undefined,
breadcrumb_len: usize = 0,

// ─── Init / deinit ───────────────────────────────────────────────────────────

fn spawnFetch(allocator: std.mem.Allocator, io: std.Io, profile_set: *const ProfileSet) !*FetchCtx {
    // Re-read profile_set every call so newly added profiles are picked up on refresh.
    var creds_list: std.ArrayList(Credentials) = .empty;
    defer creds_list.deinit(allocator);
    for (profile_set.entries.items) |*entry| {
        const creds = entry.store.getCredentials() catch continue;
        try creds_list.append(allocator, creds);
    }
    if (creds_list.items.len == 0) return error.NoCredentials;

    const owned_creds = try allocator.dupe(Credentials, creds_list.items);
    errdefer allocator.free(owned_creds);

    const ctx = try allocator.create(FetchCtx);
    errdefer allocator.destroy(ctx);
    ctx.* = .{
        .allocator = allocator,
        .io = io,
        .creds = owned_creds,
    };
    ctx.thread = try std.Thread.spawn(.{}, fetchThread, .{ctx});
    return ctx;
}

pub fn init(
    allocator: std.mem.Allocator,
    io: std.Io,
    profile_set: *const ProfileSet,
    color_support: terminal.ColorSupport,
    parent_breadcrumb: []const u8,
) !IamGroupsView {
    const colors = colors_mod.iam(color_support);
    const ctx = try spawnFetch(allocator, io, profile_set);

    var view = IamGroupsView{
        .fg_color = colors.fg,
        .bg_color = colors.bg,
        .state = .{ .loading = ctx },
        .alloc = allocator,
        .io = io,
        .profile_set = profile_set,
        .color_support = color_support,
    };
    const bc = std.fmt.bufPrint(&view.breadcrumb_buf, "{s} {s} Groups", .{ parent_breadcrumb, constants.SEP_ARROW }) catch view.breadcrumb_buf[0..0];
    view.breadcrumb_len = bc.len;
    return view;
}

fn freeState(self: *IamGroupsView) void {
    switch (self.state) {
        .loading, .ready => |ctx| {
            ctx.cancel.store(true, .release);
            if (!ctx.done.load(.acquire)) ctx.thread.join();
            for (ctx.items.items) |item| item.deinit();
            ctx.items.deinit(ctx.allocator);
            ctx.allocator.free(ctx.creds);
            ctx.allocator.destroy(ctx);
        },
        .failed => {},
    }
}

fn refresh(self: *IamGroupsView) !void {
    self.freeState();
    const ctx = try spawnFetch(self.alloc, self.io, self.profile_set);
    self.state = .{ .loading = ctx };
    self.selected = 0;
    self.scroll_offset = 0;
    self.sort_dirty = true;
}

pub fn breadcrumb(self: *IamGroupsView) []const u8 {
    return self.breadcrumb_buf[0..self.breadcrumb_len];
}

pub fn deinit(self: *IamGroupsView) void {
    if (self.committed_filter) |f| self.alloc.free(f);
    if (self.filter_expr) |*fe| fe.deinit();
    if (self.sorted_indices.len > 0) self.alloc.free(self.sorted_indices);
    self.freeState();
}

fn effectiveFilter(self: *const IamGroupsView) []const u8 {
    if (self.live_filter.len > 0) return self.live_filter;
    return self.committed_filter orelse "";
}

fn matchesGroup(self: *const IamGroupsView, item: GroupItem, text_f: []const u8) bool {
    if (!filter_mod.matchesText(item.name, text_f)) return false;
    if (self.filter_expr) |*fe| {
        const resolver = GroupResolver{ .item = item };
        if (!filter_mod.evalExpr(fe.expr, resolver)) return false;
    }
    return true;
}

fn visibleCount(self: *const IamGroupsView, items: []const GroupItem, text_f: []const u8) usize {
    var n: usize = 0;
    for (items) |item| {
        if (self.matchesGroup(item, text_f)) n += 1;
    }
    return n;
}

fn recomputeSort(self: *IamGroupsView, items: []const GroupItem) void {
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

fn ensureSorted(self: *IamGroupsView, items: []const GroupItem) void {
    if (!self.sort_dirty and self.sorted_indices.len == items.len) return;
    self.recomputeSort(items);
    self.sort_dirty = false;
}

pub fn setSort(self: *IamGroupsView, keys: []const GroupSortKey, dir: constants.SortDir) void {
    const n = @min(keys.len, self.sort_keys.len);
    @memcpy(self.sort_keys[0..n], keys[0..n]);
    self.sort_keys_len = if (n > 0) n else 1;
    self.sort_dir = dir;
    self.sort_dirty = true;
    self.sort_applied = true;
    self.selected = 0;
    self.scroll_offset = 0;
}

pub fn clearSort(self: *IamGroupsView) void {
    self.sort_keys[0] = .name;
    self.sort_keys_len = 1;
    self.sort_dir = .asc;
    self.sort_dirty = true;
    self.sort_applied = false;
    self.selected = 0;
    self.scroll_offset = 0;
}

pub fn setLiveFilter(self: *IamGroupsView, text: []const u8) void {
    if (!std.mem.eql(u8, self.live_filter, text)) {
        self.selected = 0;
        self.scroll_offset = 0;
    }
    self.live_filter = text;
}

pub fn commitFilter(self: *IamGroupsView, text: []const u8) void {
    if (self.committed_filter) |f| self.alloc.free(f);
    self.committed_filter = if (text.len == 0) null else self.alloc.dupe(u8, text) catch null;
    self.live_filter = "";
    self.selected = 0;
    self.scroll_offset = 0;
}

pub fn setFilterExpr(self: *IamGroupsView, result: filter_mod.ParseResult) void {
    if (self.filter_expr) |*fe| fe.deinit();
    self.filter_expr = result;
    self.selected = 0;
    self.scroll_offset = 0;
}

pub fn clearFilterExpr(self: *IamGroupsView) void {
    if (self.filter_expr) |*fe| fe.deinit();
    self.filter_expr = null;
    self.selected = 0;
    self.scroll_offset = 0;
}

// ─── Event handling ───────────────────────────────────────────────────────────

pub fn handleEvent(self: *IamGroupsView, event: Event, vctx: ViewContext) !Action {
    const count: usize = switch (self.state) {
        .loading, .ready => |ctx| blk: {
            lockMutex(&ctx.mutex);
            defer ctx.mutex.unlock();
            break :blk self.visibleCount(ctx.items.items, self.effectiveFilter());
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
                else => self.pending_g = false,
            },
            .down => if (count > 0 and self.selected < count - 1) {
                self.selected += 1;
            },
            .up => if (self.selected > 0) {
                self.selected -= 1;
            },
            .enter => {
                const ctx = switch (self.state) {
                    .loading, .ready => |c| c,
                    .failed => return .none,
                };
                lockMutex(&ctx.mutex);
                const filter = self.effectiveFilter();
                self.ensureSorted(ctx.items.items);
                var vis_idx: usize = 0;
                var found: ?GroupItem = null;
                for (self.sorted_indices) |orig_idx| {
                    const item = ctx.items.items[orig_idx];
                    if (!self.matchesGroup(item, filter)) continue;
                    if (vis_idx == self.selected) {
                        found = item;
                        break;
                    }
                    vis_idx += 1;
                }
                const item = found orelse {
                    ctx.mutex.unlock();
                    return .none;
                };
                const group_name = vctx.allocator.dupe(u8, item.name) catch {
                    ctx.mutex.unlock();
                    return .none;
                };
                const arn = vctx.allocator.dupe(u8, item.arn) catch {
                    vctx.allocator.free(group_name);
                    ctx.mutex.unlock();
                    return .none;
                };
                const path = vctx.allocator.dupe(u8, item.path) catch {
                    vctx.allocator.free(group_name);
                    vctx.allocator.free(arn);
                    ctx.mutex.unlock();
                    return .none;
                };
                const create_date = vctx.allocator.dupe(u8, item.create_date) catch {
                    vctx.allocator.free(group_name);
                    vctx.allocator.free(arn);
                    vctx.allocator.free(path);
                    ctx.mutex.unlock();
                    return .none;
                };
                const cred_idx = item.cred_idx;
                ctx.mutex.unlock();
                defer vctx.allocator.free(group_name);
                defer vctx.allocator.free(arn);
                defer vctx.allocator.free(path);
                defer vctx.allocator.free(create_date);

                const detail = try IamGroupView.init(
                    vctx.allocator,
                    vctx.io,
                    ctx.creds[cred_idx],
                    group_name,
                    arn,
                    path,
                    create_date,
                    self.color_support,
                    self.breadcrumb(),
                );
                return .{ .push = .{ .iam_group = detail } };
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
                    switch (self.state) {
                        .loading, .ready => |ctx| ctx.cancel.store(true, .release),
                        .failed => {},
                    }
                    return .pop;
                }
            },
            else => {},
        },
        else => {},
    }
    return .none;
}

// ─── Layout helpers ──────────────────────────────────────────────────────────

fn nameWidth(inner: usize) usize {
    const dividers = 3; // between NAME|ACCOUNT, ACCOUNT|PATH, PATH|CREATED; outer borders already excluded from inner
    const others = ACCOUNT_W + PATH_W + CREATED_W + dividers;
    return if (inner > others) inner - others else 2;
}

// ─── Drawing helpers ─────────────────────────────────────────────────────────

// Count terminal columns for a UTF-8 string (each codepoint = 1 column).
fn utf8Cols(text: []const u8) usize {
    var cols: usize = 0;
    var i: usize = 0;
    while (i < text.len) {
        const b = text[i];
        i += if (b < 0x80) 1 else if (b < 0xE0) 2 else if (b < 0xF0) 3 else 4;
        cols += 1;
    }
    return cols;
}

// Return byte length of the longest prefix that fits in `max_cols` terminal columns.
fn utf8FitBytes(text: []const u8, max_cols: usize) usize {
    var cols: usize = 0;
    var i: usize = 0;
    while (i < text.len and cols < max_cols) {
        const b = text[i];
        const char_bytes: usize = if (b < 0x80) 1 else if (b < 0xE0) 2 else if (b < 0xF0) 3 else 4;
        cols += 1;
        i += char_bytes;
    }
    return i;
}

fn writePaddedCell(writer: *std.Io.Writer, text: []const u8, cell_w: usize) !void {
    const content_w = if (cell_w >= 2) cell_w - 2 else 0;
    try writer.writeByte(' ');
    const end = utf8FitBytes(text, content_w);
    try writer.writeAll(text[0..end]);
    const shown_cols = utf8Cols(text[0..end]);
    for (shown_cols..content_w) |_| try writer.writeByte(' ');
    try writer.writeByte(' ');
}

fn writeVert(self: *IamGroupsView, writer: *std.Io.Writer, selected: bool, reset: bool) !void {
    if (selected) {
        try writer.writeAll(self.bg_color);
        try writer.writeAll(terminal.FG_BLACK);
    } else {
        try writer.writeAll(self.fg_color);
    }
    try writer.writeAll(constants.VERTICAL);
    if (reset) try writer.writeAll(terminal.RESET);
}

fn writeSepRow(self: *IamGroupsView, writer: *std.Io.Writer, name_w: usize, bottom: bool) !void {
    const left = if (bottom) constants.BOTTOM_LEFT else constants.LEFT_T;
    const mid = if (bottom) constants.BOTTOM_T else constants.CROSS;
    const right = if (bottom) constants.BOTTOM_RIGHT else constants.RIGHT_T;

    try writer.writeAll(self.fg_color);
    try writer.writeAll(left);
    for (0..name_w) |_| try writer.writeAll(constants.HORIZONTAL);
    try writer.writeAll(mid);
    for (0..ACCOUNT_W) |_| try writer.writeAll(constants.HORIZONTAL);
    try writer.writeAll(mid);
    for (0..PATH_W) |_| try writer.writeAll(constants.HORIZONTAL);
    try writer.writeAll(mid);
    for (0..CREATED_W) |_| try writer.writeAll(constants.HORIZONTAL);
    try writer.writeAll(right);
    try writer.writeAll(terminal.RESET);
}

fn writeHeaderCell(self: *IamGroupsView, writer: *std.Io.Writer, text: []const u8, cell_w: usize) !void {
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

fn writeHeaderRow(self: *IamGroupsView, writer: *std.Io.Writer, name_w: usize) !void {
    try writer.writeAll(self.fg_color);
    try writer.writeAll(constants.VERTICAL);
    try writer.writeAll(terminal.RESET);
    try self.writeHeaderCell(writer, "NAME", name_w);
    try writer.writeAll(self.fg_color);
    try writer.writeAll(constants.VERTICAL);
    try writer.writeAll(terminal.RESET);
    try self.writeHeaderCell(writer, "ACCOUNT", ACCOUNT_W);
    try writer.writeAll(self.fg_color);
    try writer.writeAll(constants.VERTICAL);
    try writer.writeAll(terminal.RESET);
    try self.writeHeaderCell(writer, "PATH", PATH_W);
    try writer.writeAll(self.fg_color);
    try writer.writeAll(constants.VERTICAL);
    try writer.writeAll(terminal.RESET);
    try self.writeHeaderCell(writer, "CREATED", CREATED_W);
    try writer.writeAll(self.fg_color);
    try writer.writeAll(constants.VERTICAL);
    try writer.writeAll(terminal.RESET);
}

fn writeGroupRow(self: *IamGroupsView, writer: *std.Io.Writer, item: GroupItem, sel: bool, name_w: usize) !void {
    try self.writeVert(writer, sel, !sel);

    const content_w = if (name_w >= 2) name_w - 2 else 0;
    const max_name = if (content_w >= 2) content_w - 2 else 0;
    try writer.writeByte(' ');
    try writer.writeAll(if (sel) "▸ " else "  ");
    const shown_name = if (item.name.len > max_name) item.name[0..max_name] else item.name;
    try writer.writeAll(shown_name);
    for (shown_name.len..max_name) |_| try writer.writeByte(' ');
    try writer.writeByte(' ');

    try self.writeVert(writer, sel, !sel);
    try writePaddedCell(writer, item.account_id, ACCOUNT_W);

    try self.writeVert(writer, sel, !sel);
    try writePaddedCell(writer, item.path, PATH_W);

    try self.writeVert(writer, sel, !sel);
    try writePaddedCell(writer, item.create_date, CREATED_W);

    try self.writeVert(writer, sel, true);
}

fn writeEmptyRow(self: *IamGroupsView, writer: *std.Io.Writer, name_w: usize) !void {
    try self.writeVert(writer, false, true);
    for (0..name_w) |_| try writer.writeByte(' ');
    try self.writeVert(writer, false, true);
    for (0..ACCOUNT_W) |_| try writer.writeByte(' ');
    try self.writeVert(writer, false, true);
    for (0..PATH_W) |_| try writer.writeByte(' ');
    try self.writeVert(writer, false, true);
    for (0..CREATED_W) |_| try writer.writeByte(' ');
    try self.writeVert(writer, false, true);
}

pub fn render(self: *IamGroupsView, writer: *std.Io.Writer, size: Coord) !void {
    if (size.x < 10 or size.y < 4) return;
    const w: usize = @intCast(size.x);
    const h: usize = @intCast(size.y);
    const inner = w - 2;
    const name_w = nameWidth(inner);
    const show_header = h >= 6;
    const data_rows = if (show_header) h - 3 else h - 1;

    // Transition loading → ready once done.
    switch (self.state) {
        .loading => |ctx| {
            if (ctx.done.load(.acquire)) {
                if (ctx.err) |e| {
                    lockMutex(&ctx.mutex);
                    for (ctx.items.items) |item| item.deinit();
                    ctx.items.deinit(ctx.allocator);
                    ctx.mutex.unlock();
                    ctx.allocator.free(ctx.creds);
                    ctx.allocator.destroy(ctx);
                    self.state = .{ .failed = e };
                } else {
                    self.state = .{ .ready = ctx };
                }
            }
        },
        .ready, .failed => {},
    }

    if (show_header) {
        try self.writeHeaderRow(writer, name_w);
        try writer.writeAll("\r\n");
        try self.writeSepRow(writer, name_w, false);
        try writer.writeAll("\r\n");
    }

    switch (self.state) {
        .loading, .ready => |ctx| {
            const loading = self.state == .loading;
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
            } else if (!loading) {
                self.selected = 0;
                self.scroll_offset = 0;
            }

            self.ensureSorted(items);
            var vis_idx: usize = 0;
            var rendered: usize = 0;
            for (self.sorted_indices) |orig_idx| {
                const item = items[orig_idx];
                if (!self.matchesGroup(item, filter)) continue;
                if (vis_idx >= self.scroll_offset and rendered < data_rows) {
                    try self.writeGroupRow(writer, item, vis_idx == self.selected, name_w);
                    try writer.writeAll("\r\n");
                    rendered += 1;
                }
                vis_idx += 1;
            }
            for (rendered..data_rows) |_| {
                try self.writeEmptyRow(writer, name_w);
                try writer.writeAll("\r\n");
            }
        },
        .failed => |e| {
            for (0..data_rows) |row| {
                try self.writeVert(writer, false, true);
                if (row == 0) {
                    var buf: [128]u8 = undefined;
                    const msg = std.fmt.bufPrint(&buf, " Error: {s}", .{@errorName(e)}) catch " Error loading groups";
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

    try self.writeSepRow(writer, name_w, true);
}
