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
const IamPolicyView = @import("policy.zig");
const filter_mod = @import("../../../commands/filter.zig");

const IamPoliciesView = @This();
pub const name: []const u8 = "Policies";

// ACCOUNT column: 12-digit AWS account id (or "aws") + 2 padding.
// TYPE column: "Customer managed" (17 chars) + 2 padding, rounded up.
// USED AS column: "Permissions boundary" (21 chars) + 2 padding, rounded up.
// DESCRIPTION column: fixed width, truncated.
// NAME column: fills remaining terminal width.
const ACCOUNT_W: usize = 14;
const TYPE_W: usize = 20;
const USED_AS_W: usize = 24;
const DESC_W: usize = 30;
const MIN_NAME_W: usize = 20;

// ─── Local item ─────────────────────────────────────────────────────────────

const PolicyItem = struct {
    allocator: std.mem.Allocator,
    name: []u8,
    arn: []u8,
    account_id: []u8,
    description: []u8,
    attachment_count: u32,
    permissions_boundary_usage_count: u32,
    cred_idx: usize,

    pub fn deinit(self: PolicyItem) void {
        self.allocator.free(self.name);
        self.allocator.free(self.arn);
        self.allocator.free(self.account_id);
        self.allocator.free(self.description);
    }

    fn typeStr(self: PolicyItem) []const u8 {
        return if (std.mem.eql(u8, self.account_id, "aws")) "AWS managed" else "Customer managed";
    }

    fn usedAsStr(self: PolicyItem) []const u8 {
        const attached = self.attachment_count > 0;
        const boundary = self.permissions_boundary_usage_count > 0;
        if (attached and boundary) return "Policy & Boundary";
        if (attached) return "Permissions policy";
        if (boundary) return "Permissions boundary";
        return "Not used";
    }
};

pub const PolicySortKey = enum { name, account, description, type_, used_as };

const SortCtx = struct {
    items: []const PolicyItem,
    keys: []const PolicySortKey,
    dir: constants.SortDir,

    fn lessThan(ctx: @This(), a: usize, b: usize) bool {
        for (ctx.keys) |key| {
            const ord = compareField(ctx.items[a], ctx.items[b], key);
            if (ord != .eq) return if (ctx.dir == .asc) ord == .lt else ord == .gt;
        }
        return false;
    }
};

fn compareField(a: PolicyItem, b: PolicyItem, key: PolicySortKey) std.math.Order {
    return switch (key) {
        .name => std.mem.order(u8, a.name, b.name),
        .account => std.mem.order(u8, a.account_id, b.account_id),
        .description => std.mem.order(u8, a.description, b.description),
        .type_ => std.mem.order(u8, a.typeStr(), b.typeStr()),
        .used_as => std.mem.order(u8, a.usedAsStr(), b.usedAsStr()),
    };
}

const PolicyResolver = struct {
    item: PolicyItem,

    pub fn resolve(self: PolicyResolver, field: []const u8) filter_mod.FieldValue {
        if (std.mem.eql(u8, field, "name")) return .{ .string = self.item.name };
        if (std.mem.eql(u8, field, "arn")) return .{ .string = self.item.arn };
        if (std.mem.eql(u8, field, "account") or std.mem.eql(u8, field, "account_id")) return .{ .string = self.item.account_id };
        if (std.mem.eql(u8, field, "description")) return .{ .string = self.item.description };
        if (std.mem.eql(u8, field, "type")) return .{ .string = self.item.typeStr() };
        if (std.mem.eql(u8, field, "used_as")) return .{ .string = self.item.usedAsStr() };
        return .unknown;
    }
};

// Parse account id from IAM policy ARN: arn:aws:iam::{account}:policy/{name}
// AWS managed policies use the literal account segment "aws".
fn parseAccountId(arn: []const u8) []const u8 {
    var it = std.mem.splitScalar(u8, arn, ':');
    _ = it.next(); // arn
    _ = it.next(); // aws
    _ = it.next(); // iam
    _ = it.next(); // region (empty for IAM)
    return it.next() orelse "";
}

fn policyToItem(allocator: std.mem.Allocator, p: Iam.IamPolicy, cred_idx: usize) !PolicyItem {
    const item_name = try allocator.dupe(u8, p.policy_name);
    errdefer allocator.free(item_name);
    const arn = try allocator.dupe(u8, p.arn);
    errdefer allocator.free(arn);
    const account_id = try allocator.dupe(u8, parseAccountId(p.arn));
    errdefer allocator.free(account_id);
    const description = try allocator.dupe(u8, p.description);
    errdefer allocator.free(description);
    return .{
        .allocator = allocator,
        .name = item_name,
        .arn = arn,
        .account_id = account_id,
        .description = description,
        .attachment_count = p.attachment_count,
        .permissions_boundary_usage_count = p.permissions_boundary_usage_count,
        .cred_idx = cred_idx,
    };
}

// ─── Concurrency ─────────────────────────────────────────────────────────────

const FetchCtx = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    creds: []Credentials,
    mutex: std.atomic.Mutex = .unlocked,
    items: std.ArrayList(PolicyItem) = .empty,
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

// Lists all managed policies for a single profile (cred_idx into ctx.creds), appending into shared ctx.items.
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

        const result = client.listPolicies(.{
            .params = .{ .scope = .all, .marker = next_marker },
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
        for (result.policies) |p| {
            const item = policyToItem(ctx.allocator, p, cred_idx) catch |e| {
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
sort_keys: [4]PolicySortKey = .{ .name, undefined, undefined, undefined },
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
) !IamPoliciesView {
    const colors = colors_mod.iam(color_support);
    const ctx = try spawnFetch(allocator, io, profile_set);

    var view = IamPoliciesView{
        .fg_color = colors.fg,
        .bg_color = colors.bg,
        .state = .{ .loading = ctx },
        .alloc = allocator,
        .io = io,
        .profile_set = profile_set,
        .color_support = color_support,
    };
    const bc = std.fmt.bufPrint(&view.breadcrumb_buf, "{s} {s} Policies", .{ parent_breadcrumb, constants.SEP_ARROW }) catch view.breadcrumb_buf[0..0];
    view.breadcrumb_len = bc.len;
    return view;
}

fn freeState(self: *IamPoliciesView) void {
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

fn refresh(self: *IamPoliciesView) !void {
    self.freeState();
    const ctx = try spawnFetch(self.alloc, self.io, self.profile_set);
    self.state = .{ .loading = ctx };
    self.selected = 0;
    self.scroll_offset = 0;
    self.sort_dirty = true;
}

pub fn breadcrumb(self: *IamPoliciesView) []const u8 {
    return self.breadcrumb_buf[0..self.breadcrumb_len];
}

pub fn deinit(self: *IamPoliciesView) void {
    if (self.committed_filter) |f| self.alloc.free(f);
    if (self.filter_expr) |*fe| fe.deinit();
    if (self.sorted_indices.len > 0) self.alloc.free(self.sorted_indices);
    self.freeState();
}

fn effectiveFilter(self: *const IamPoliciesView) []const u8 {
    if (self.live_filter.len > 0) return self.live_filter;
    return self.committed_filter orelse "";
}

fn matchesPolicy(self: *const IamPoliciesView, item: PolicyItem, text_f: []const u8) bool {
    if (!filter_mod.matchesText(item.name, text_f)) return false;
    if (self.filter_expr) |*fe| {
        const resolver = PolicyResolver{ .item = item };
        if (!filter_mod.evalExpr(fe.expr, resolver)) return false;
    }
    return true;
}

fn visibleCount(self: *const IamPoliciesView, items: []const PolicyItem, text_f: []const u8) usize {
    var n: usize = 0;
    for (items) |item| {
        if (self.matchesPolicy(item, text_f)) n += 1;
    }
    return n;
}

fn recomputeSort(self: *IamPoliciesView, items: []const PolicyItem) void {
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

fn ensureSorted(self: *IamPoliciesView, items: []const PolicyItem) void {
    if (!self.sort_dirty and self.sorted_indices.len == items.len) return;
    self.recomputeSort(items);
    self.sort_dirty = false;
}

pub fn setSort(self: *IamPoliciesView, keys: []const PolicySortKey, dir: constants.SortDir) void {
    const n = @min(keys.len, self.sort_keys.len);
    @memcpy(self.sort_keys[0..n], keys[0..n]);
    self.sort_keys_len = if (n > 0) n else 1;
    self.sort_dir = dir;
    self.sort_dirty = true;
    self.sort_applied = true;
    self.selected = 0;
    self.scroll_offset = 0;
}

pub fn clearSort(self: *IamPoliciesView) void {
    self.sort_keys[0] = .name;
    self.sort_keys_len = 1;
    self.sort_dir = .asc;
    self.sort_dirty = true;
    self.sort_applied = false;
    self.selected = 0;
    self.scroll_offset = 0;
}

pub fn setLiveFilter(self: *IamPoliciesView, text: []const u8) void {
    if (!std.mem.eql(u8, self.live_filter, text)) {
        self.selected = 0;
        self.scroll_offset = 0;
    }
    self.live_filter = text;
}

pub fn commitFilter(self: *IamPoliciesView, text: []const u8) void {
    if (self.committed_filter) |f| self.alloc.free(f);
    self.committed_filter = if (text.len == 0) null else self.alloc.dupe(u8, text) catch null;
    self.live_filter = "";
    self.selected = 0;
    self.scroll_offset = 0;
}

pub fn setFilterExpr(self: *IamPoliciesView, result: filter_mod.ParseResult) void {
    if (self.filter_expr) |*fe| fe.deinit();
    self.filter_expr = result;
    self.selected = 0;
    self.scroll_offset = 0;
}

pub fn clearFilterExpr(self: *IamPoliciesView) void {
    if (self.filter_expr) |*fe| fe.deinit();
    self.filter_expr = null;
    self.selected = 0;
    self.scroll_offset = 0;
}

// ─── Event handling ───────────────────────────────────────────────────────────

pub fn handleEvent(self: *IamPoliciesView, event: Event, vctx: ViewContext) !Action {
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
                var found: ?PolicyItem = null;
                for (self.sorted_indices) |orig_idx| {
                    const item = ctx.items.items[orig_idx];
                    if (!self.matchesPolicy(item, filter)) continue;
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
                const policy_name = vctx.allocator.dupe(u8, item.name) catch {
                    ctx.mutex.unlock();
                    return .none;
                };
                const arn = vctx.allocator.dupe(u8, item.arn) catch {
                    vctx.allocator.free(policy_name);
                    ctx.mutex.unlock();
                    return .none;
                };
                const cred_idx = item.cred_idx;
                ctx.mutex.unlock();
                defer vctx.allocator.free(policy_name);
                defer vctx.allocator.free(arn);

                const detail = try IamPolicyView.init(
                    vctx.allocator,
                    vctx.io,
                    ctx.creds[cred_idx],
                    policy_name,
                    arn,
                    self.fg_color,
                    self.bg_color,
                    self.breadcrumb(),
                );
                return .{ .push = .{ .iam_policy = detail } };
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
    const others = ACCOUNT_W + DESC_W + TYPE_W + USED_AS_W + 4;
    return if (inner > others) inner - others else MIN_NAME_W;
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

fn writeVert(self: *IamPoliciesView, writer: *std.Io.Writer, selected: bool, reset: bool) !void {
    if (selected) {
        try writer.writeAll(self.bg_color);
        try writer.writeAll(terminal.FG_BLACK);
    } else {
        try writer.writeAll(self.fg_color);
    }
    try writer.writeAll(constants.VERTICAL);
    if (reset) try writer.writeAll(terminal.RESET);
}

fn writeSepRow(self: *IamPoliciesView, writer: *std.Io.Writer, name_w: usize, bottom: bool) !void {
    const left = if (bottom) constants.BOTTOM_LEFT else constants.LEFT_T;
    const mid = if (bottom) constants.BOTTOM_T else constants.CROSS;
    const right = if (bottom) constants.BOTTOM_RIGHT else constants.RIGHT_T;

    try writer.writeAll(self.fg_color);
    try writer.writeAll(left);
    for (0..ACCOUNT_W) |_| try writer.writeAll(constants.HORIZONTAL);
    try writer.writeAll(mid);
    for (0..name_w) |_| try writer.writeAll(constants.HORIZONTAL);
    try writer.writeAll(mid);
    for (0..DESC_W) |_| try writer.writeAll(constants.HORIZONTAL);
    try writer.writeAll(mid);
    for (0..TYPE_W) |_| try writer.writeAll(constants.HORIZONTAL);
    try writer.writeAll(mid);
    for (0..USED_AS_W) |_| try writer.writeAll(constants.HORIZONTAL);
    try writer.writeAll(right);
    try writer.writeAll(terminal.RESET);
}

fn writeHeaderCell(self: *IamPoliciesView, writer: *std.Io.Writer, text: []const u8, cell_w: usize) !void {
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

fn writeHeaderRow(self: *IamPoliciesView, writer: *std.Io.Writer, name_w: usize) !void {
    try writer.writeAll(self.fg_color);
    try writer.writeAll(constants.VERTICAL);
    try writer.writeAll(terminal.RESET);
    try self.writeHeaderCell(writer, "ACCOUNT", ACCOUNT_W);
    try writer.writeAll(self.fg_color);
    try writer.writeAll(constants.VERTICAL);
    try writer.writeAll(terminal.RESET);
    try self.writeHeaderCell(writer, "NAME", name_w);
    try writer.writeAll(self.fg_color);
    try writer.writeAll(constants.VERTICAL);
    try writer.writeAll(terminal.RESET);
    try self.writeHeaderCell(writer, "DESCRIPTION", DESC_W);
    try writer.writeAll(self.fg_color);
    try writer.writeAll(constants.VERTICAL);
    try writer.writeAll(terminal.RESET);
    try self.writeHeaderCell(writer, "TYPE", TYPE_W);
    try writer.writeAll(self.fg_color);
    try writer.writeAll(constants.VERTICAL);
    try writer.writeAll(terminal.RESET);
    try self.writeHeaderCell(writer, "USED AS", USED_AS_W);
    try writer.writeAll(self.fg_color);
    try writer.writeAll(constants.VERTICAL);
    try writer.writeAll(terminal.RESET);
}

fn writePolicyRow(self: *IamPoliciesView, writer: *std.Io.Writer, item: PolicyItem, sel: bool, name_w: usize) !void {
    try self.writeVert(writer, sel, !sel);
    try writePaddedCell(writer, item.account_id, ACCOUNT_W);

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
    const desc = if (item.description.len > 0) item.description else "-";
    try writePaddedCell(writer, desc, DESC_W);

    try self.writeVert(writer, sel, !sel);
    try writePaddedCell(writer, item.typeStr(), TYPE_W);

    try self.writeVert(writer, sel, !sel);
    try writePaddedCell(writer, item.usedAsStr(), USED_AS_W);
    try self.writeVert(writer, sel, true);
}

fn writeEmptyRow(self: *IamPoliciesView, writer: *std.Io.Writer, name_w: usize) !void {
    try self.writeVert(writer, false, true);
    for (0..ACCOUNT_W) |_| try writer.writeByte(' ');
    try self.writeVert(writer, false, true);
    for (0..name_w) |_| try writer.writeByte(' ');
    try self.writeVert(writer, false, true);
    for (0..DESC_W) |_| try writer.writeByte(' ');
    try self.writeVert(writer, false, true);
    for (0..TYPE_W) |_| try writer.writeByte(' ');
    try self.writeVert(writer, false, true);
    for (0..USED_AS_W) |_| try writer.writeByte(' ');
    try self.writeVert(writer, false, true);
}

pub fn render(self: *IamPoliciesView, writer: *std.Io.Writer, size: Coord) !void {
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
                if (!self.matchesPolicy(item, filter)) continue;
                if (vis_idx >= self.scroll_offset and rendered < data_rows) {
                    try self.writePolicyRow(writer, item, vis_idx == self.selected, name_w);
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
                    const msg = std.fmt.bufPrint(&buf, " Error: {s}", .{@errorName(e)}) catch " Error loading policies";
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
