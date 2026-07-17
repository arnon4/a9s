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
const IamRoleView = @import("role.zig");
const filter_mod = @import("../../../commands/filter.zig");

const IamRolesView = @This();
pub const name: []const u8 = "Roles";

// NAME column: IAM role name max = 64 chars content + 4 (prefix "▸ " + side spaces).
// ACCOUNT column: 12-digit AWS account id + 2 padding.
// ACTIVITY column: ISO-8601 timestamp "2026-06-27T14:31:29Z" = 20 chars + 2 padding.
// TRUSTED column: fills remaining terminal width.
const NAME_W: usize = 68;
const ACCOUNT_W: usize = 14;
const ACTIVITY_W: usize = 22;

const Mode = enum {
    wide,    // >=120: NAME | TRUSTED ENTITIES | LAST ACTIVITY
    compact, //  <120: NAME | LAST ACTIVITY
};

pub const RoleSortKey = enum { name, account, created, activity };

const SortCtx = struct {
    items: []const RoleItem,
    keys: []const RoleSortKey,
    dir: constants.SortDir,

    fn lessThan(ctx: @This(), a: usize, b: usize) bool {
        for (ctx.keys) |key| {
            const ord = compareField(ctx.items[a], ctx.items[b], key);
            if (ord != .eq) return if (ctx.dir == .asc) ord == .lt else ord == .gt;
        }
        return false;
    }
};

fn compareField(a: RoleItem, b: RoleItem, key: RoleSortKey) std.math.Order {
    return switch (key) {
        .name => std.mem.order(u8, a.name, b.name),
        .account => std.mem.order(u8, a.account_id, b.account_id),
        .created => std.mem.order(u8, a.create_date, b.create_date),
        .activity => std.mem.order(u8, a.last_used orelse "", b.last_used orelse ""),
    };
}

// ─── Local item ─────────────────────────────────────────────────────────────

const RoleItem = struct {
    allocator: std.mem.Allocator,
    name: []u8,
    arn: []u8,
    account_id: []u8,
    create_date: []u8,
    cred_idx: usize,
    trusted_entity: ?[]u8 = null,
    last_used: ?[]u8 = null,

    pub fn deinit(self: RoleItem) void {
        self.allocator.free(self.name);
        self.allocator.free(self.arn);
        self.allocator.free(self.account_id);
        self.allocator.free(self.create_date);
        if (self.trusted_entity) |t| self.allocator.free(t);
        if (self.last_used) |l| self.allocator.free(l);
    }
};

const RoleResolver = struct {
    item: RoleItem,

    pub fn resolve(self: RoleResolver, field: []const u8) filter_mod.FieldValue {
        if (std.mem.eql(u8, field, "name")) return .{ .string = self.item.name };
        if (std.mem.eql(u8, field, "arn")) return .{ .string = self.item.arn };
        if (std.mem.eql(u8, field, "account") or std.mem.eql(u8, field, "account_id")) return .{ .string = self.item.account_id };
        if (std.mem.eql(u8, field, "created") or std.mem.eql(u8, field, "create_date")) return .{ .string = self.item.create_date };
        if (std.mem.eql(u8, field, "trusted") or std.mem.eql(u8, field, "trusted_entity")) return .{ .string = self.item.trusted_entity orelse "" };
        if (std.mem.eql(u8, field, "activity") or std.mem.eql(u8, field, "last_used")) return .{ .string = self.item.last_used orelse "" };
        return .unknown;
    }
};

// Parse account id from IAM role ARN: arn:aws:iam::{account}:role/{name}
fn parseAccountId(arn: []const u8) []const u8 {
    var it = std.mem.splitScalar(u8, arn, ':');
    _ = it.next(); // arn
    _ = it.next(); // aws
    _ = it.next(); // iam
    _ = it.next(); // region (empty for IAM)
    return it.next() orelse "";
}

fn roleToItem(allocator: std.mem.Allocator, r: Iam.IamRole, cred_idx: usize) !RoleItem {
    const item_name = try allocator.dupe(u8, r.role_name);
    errdefer allocator.free(item_name);
    const arn = try allocator.dupe(u8, r.arn);
    errdefer allocator.free(arn);
    const account_id = try allocator.dupe(u8, parseAccountId(r.arn));
    errdefer allocator.free(account_id);
    const create_date = try allocator.dupe(u8, if (r.create_date.len >= 10) r.create_date[0..10] else r.create_date);
    errdefer allocator.free(create_date);
    return .{
        .allocator = allocator,
        .name = item_name,
        .arn = arn,
        .account_id = account_id,
        .create_date = create_date,
        .cred_idx = cred_idx,
    };
}

// ─── Concurrency ─────────────────────────────────────────────────────────────

const ENRICH_WORKERS = 8;

const FetchCtx = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    creds: []Credentials,
    mutex: std.atomic.Mutex = .unlocked,
    items: std.ArrayList(RoleItem) = .empty,
    done: std.atomic.Value(bool) = .init(false),
    cancel: std.atomic.Value(bool) = .init(false),
    enrich_index: std.atomic.Value(usize) = .init(0),
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

// Lists all roles for a single profile (cred_idx into ctx.creds), appending into shared ctx.items.
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

        const result = client.listRoles(.{
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
        for (result.roles) |r| {
            const item = roleToItem(ctx.allocator, r, cred_idx) catch |e| {
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

fn enrichWorker(ctx: *FetchCtx, total: usize) void {
    // Lazily built per cred_idx, since items span multiple profiles/credentials.
    var clients = ctx.allocator.alloc(?Iam.Client, ctx.creds.len) catch return;
    defer ctx.allocator.free(clients);
    for (clients) |*c| c.* = null;
    defer for (clients) |*c| if (c.*) |*cl| cl.deinit();

    while (true) {
        if (ctx.cancel.load(.acquire)) return;
        const i = ctx.enrich_index.fetchAdd(1, .acq_rel);
        if (i >= total) return;

        lockMutex(&ctx.mutex);
        const role_name_copy = ctx.allocator.dupe(u8, ctx.items.items[i].name) catch {
            ctx.mutex.unlock();
            continue;
        };
        const cred_idx = ctx.items.items[i].cred_idx;
        ctx.mutex.unlock();
        defer ctx.allocator.free(role_name_copy);

        if (clients[cred_idx] == null) {
            clients[cred_idx] = Iam.Client.init(ctx.allocator, .{
                .io = ctx.io,
                .credentials = ctx.creds[cred_idx],
            }) catch continue;
        }
        const client = &clients[cred_idx].?;

        const gr = client.getRole(.{ .role_name = role_name_copy }) catch continue;
        defer gr.deinit();

        const trusted = Iam.extractTrustedEntities(ctx.allocator, gr.assume_role_policy_document) catch null;
        const last_used: ?[]u8 = if (gr.last_used_date) |d| ctx.allocator.dupe(u8, d) catch null else null;

        lockMutex(&ctx.mutex);
        if (ctx.items.items[i].trusted_entity) |t| ctx.allocator.free(t);
        if (ctx.items.items[i].last_used) |l| ctx.allocator.free(l);
        ctx.items.items[i].trusted_entity = trusted;
        ctx.items.items[i].last_used = last_used;
        ctx.mutex.unlock();

        input.notify();
    }
}

fn fetchThread(ctx: *FetchCtx) void {
    defer {
        ctx.done.store(true, .release);
        input.notify();
    }

    // Phase 1: list roles for every profile in parallel.
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

    if (ctx.cancel.load(.acquire)) return;

    // Notify UI so Phase 1 results appear before enrichment starts.
    input.notify();

    // Phase 2: enrich with GetRole in parallel, across all profiles' items.
    const total = blk: {
        lockMutex(&ctx.mutex);
        const n = ctx.items.items.len;
        ctx.mutex.unlock();
        break :blk n;
    };

    var workers: [ENRICH_WORKERS]std.Thread = undefined;
    var espawned: usize = 0;
    for (0..ENRICH_WORKERS) |_| {
        workers[espawned] = std.Thread.spawn(.{}, enrichWorker, .{ ctx, total }) catch break;
        espawned += 1;
    }
    for (0..espawned) |j| workers[j].join();
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
sort_keys: [4]RoleSortKey = .{ .name, undefined, undefined, undefined },
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
) !IamRolesView {
    const colors = colors_mod.iam(color_support);
    const ctx = try spawnFetch(allocator, io, profile_set);

    var view = IamRolesView{
        .fg_color = colors.fg,
        .bg_color = colors.bg,
        .state = .{ .loading = ctx },
        .alloc = allocator,
        .io = io,
        .profile_set = profile_set,
        .color_support = color_support,
    };
    const bc = std.fmt.bufPrint(&view.breadcrumb_buf, "{s} {s} Roles", .{ parent_breadcrumb, constants.SEP_ARROW }) catch view.breadcrumb_buf[0..0];
    view.breadcrumb_len = bc.len;
    return view;
}

fn freeState(self: *IamRolesView) void {
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

fn refresh(self: *IamRolesView) !void {
    self.freeState();
    const ctx = try spawnFetch(self.alloc, self.io, self.profile_set);
    self.state = .{ .loading = ctx };
    self.selected = 0;
    self.scroll_offset = 0;
    self.sort_dirty = true;
}

pub fn breadcrumb(self: *IamRolesView) []const u8 {
    return self.breadcrumb_buf[0..self.breadcrumb_len];
}

pub fn deinit(self: *IamRolesView) void {
    if (self.committed_filter) |f| self.alloc.free(f);
    if (self.filter_expr) |*fe| fe.deinit();
    if (self.sorted_indices.len > 0) self.alloc.free(self.sorted_indices);
    self.freeState();
}

fn effectiveFilter(self: *const IamRolesView) []const u8 {
    if (self.live_filter.len > 0) return self.live_filter;
    return self.committed_filter orelse "";
}

fn matchesRole(self: *const IamRolesView, item: RoleItem, text_f: []const u8) bool {
    if (!filter_mod.matchesText(item.name, text_f)) return false;
    if (self.filter_expr) |*fe| {
        const resolver = RoleResolver{ .item = item };
        if (!filter_mod.evalExpr(fe.expr, resolver)) return false;
    }
    return true;
}

fn visibleCount(self: *const IamRolesView, items: []const RoleItem, text_f: []const u8) usize {
    var n: usize = 0;
    for (items) |item| {
        if (self.matchesRole(item, text_f)) n += 1;
    }
    return n;
}

fn recomputeSort(self: *IamRolesView, items: []const RoleItem) void {
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

fn ensureSorted(self: *IamRolesView, items: []const RoleItem) void {
    if (!self.sort_dirty and self.sorted_indices.len == items.len) return;
    self.recomputeSort(items);
    self.sort_dirty = false;
}

pub fn setSort(self: *IamRolesView, keys: []const RoleSortKey, dir: constants.SortDir) void {
    const n = @min(keys.len, self.sort_keys.len);
    @memcpy(self.sort_keys[0..n], keys[0..n]);
    self.sort_keys_len = if (n > 0) n else 1;
    self.sort_dir = dir;
    self.sort_dirty = true;
    self.sort_applied = true;
    self.selected = 0;
    self.scroll_offset = 0;
}

pub fn clearSort(self: *IamRolesView) void {
    self.sort_keys[0] = .name;
    self.sort_keys_len = 1;
    self.sort_dir = .asc;
    self.sort_dirty = true;
    self.sort_applied = false;
    self.selected = 0;
    self.scroll_offset = 0;
}

pub fn setLiveFilter(self: *IamRolesView, text: []const u8) void {
    if (!std.mem.eql(u8, self.live_filter, text)) {
        self.selected = 0;
        self.scroll_offset = 0;
    }
    self.live_filter = text;
}

pub fn commitFilter(self: *IamRolesView, text: []const u8) void {
    if (self.committed_filter) |f| self.alloc.free(f);
    self.committed_filter = if (text.len == 0) null else self.alloc.dupe(u8, text) catch null;
    self.live_filter = "";
    self.selected = 0;
    self.scroll_offset = 0;
}

pub fn setFilterExpr(self: *IamRolesView, result: filter_mod.ParseResult) void {
    if (self.filter_expr) |*fe| fe.deinit();
    self.filter_expr = result;
    self.selected = 0;
    self.scroll_offset = 0;
}

pub fn clearFilterExpr(self: *IamRolesView) void {
    if (self.filter_expr) |*fe| fe.deinit();
    self.filter_expr = null;
    self.selected = 0;
    self.scroll_offset = 0;
}

// ─── Event handling ───────────────────────────────────────────────────────────

pub fn handleEvent(self: *IamRolesView, event: Event, vctx: ViewContext) !Action {
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
                var found: ?RoleItem = null;
                for (self.sorted_indices) |orig_idx| {
                    const item = ctx.items.items[orig_idx];
                    if (!self.matchesRole(item, filter)) continue;
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
                const role_name = vctx.allocator.dupe(u8, item.name) catch {
                    ctx.mutex.unlock();
                    return .none;
                };
                const arn = vctx.allocator.dupe(u8, item.arn) catch {
                    vctx.allocator.free(role_name);
                    ctx.mutex.unlock();
                    return .none;
                };
                const create_date = vctx.allocator.dupe(u8, item.create_date) catch {
                    vctx.allocator.free(role_name);
                    vctx.allocator.free(arn);
                    ctx.mutex.unlock();
                    return .none;
                };
                const cred_idx = item.cred_idx;
                ctx.mutex.unlock();
                defer vctx.allocator.free(role_name);
                defer vctx.allocator.free(arn);
                defer vctx.allocator.free(create_date);

                const detail = try IamRoleView.init(
                    vctx.allocator,
                    vctx.io,
                    ctx.creds[cred_idx],
                    role_name,
                    arn,
                    create_date,
                    self.color_support,
                    self.breadcrumb(),
                );
                return .{ .push = .{ .iam_role = detail } };
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

fn modeFor(width: i16) Mode {
    if (width >= 120) return .wide;
    return .compact;
}

fn nameWidth(inner: usize, mode: Mode) usize {
    return switch (mode) {
        .wide => blk: {
            // Leave at least 10 chars for the TRUSTED column.
            const min_trusted = 10;
            const others = ACCOUNT_W + 1 + ACTIVITY_W + 2 + min_trusted;
            const avail = if (inner > others) inner - others else 2;
            break :blk @min(NAME_W, avail);
        },
        .compact => blk: {
            const others = ACCOUNT_W + ACTIVITY_W + 3;
            break :blk if (inner > others) inner - others else 2;
        },
    };
}

// TRUSTED fills whatever is left after NAME, ACCOUNT and ACTIVITY columns.
// Wide mode row: 1(left) + name_w + 1(sep) + account_w + 1(sep) + trusted_w + 1(sep) + ACTIVITY_W + 1(right) = w
// So name_w + account_w + trusted_w + ACTIVITY_W = w - 5 = inner - 3.
fn trustedWidth(inner: usize, name_w: usize) usize {
    const used = name_w + ACCOUNT_W + ACTIVITY_W + 3;
    return if (inner > used) inner - used else 0;
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

fn writeVert(self: *IamRolesView, writer: *std.Io.Writer, selected: bool, reset: bool) !void {
    if (selected) {
        try writer.writeAll(self.bg_color);
        try writer.writeAll(terminal.FG_BLACK);
    } else {
        try writer.writeAll(self.fg_color);
    }
    try writer.writeAll(constants.VERTICAL);
    if (reset) try writer.writeAll(terminal.RESET);
}

fn writeSepRow(self: *IamRolesView, writer: *std.Io.Writer, name_w: usize, trusted_w: usize, mode: Mode, bottom: bool) !void {
    const left = if (bottom) constants.BOTTOM_LEFT else constants.LEFT_T;
    const mid = if (bottom) constants.BOTTOM_T else constants.CROSS;
    const right = if (bottom) constants.BOTTOM_RIGHT else constants.RIGHT_T;

    try writer.writeAll(self.fg_color);
    try writer.writeAll(left);
    for (0..name_w) |_| try writer.writeAll(constants.HORIZONTAL);
    try writer.writeAll(mid);
    for (0..ACCOUNT_W) |_| try writer.writeAll(constants.HORIZONTAL);
    if (mode == .wide) {
        try writer.writeAll(mid);
        for (0..trusted_w) |_| try writer.writeAll(constants.HORIZONTAL);
    }
    try writer.writeAll(mid);
    for (0..ACTIVITY_W) |_| try writer.writeAll(constants.HORIZONTAL);
    try writer.writeAll(right);
    try writer.writeAll(terminal.RESET);
}

fn writeHeaderCell(self: *IamRolesView, writer: *std.Io.Writer, text: []const u8, cell_w: usize) !void {
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

fn writeHeaderRow(self: *IamRolesView, writer: *std.Io.Writer, name_w: usize, trusted_w: usize, mode: Mode) !void {
    try writer.writeAll(self.fg_color);
    try writer.writeAll(constants.VERTICAL);
    try writer.writeAll(terminal.RESET);
    try self.writeHeaderCell(writer, "NAME", name_w);
    try writer.writeAll(self.fg_color);
    try writer.writeAll(constants.VERTICAL);
    try writer.writeAll(terminal.RESET);
    try self.writeHeaderCell(writer, "ACCOUNT", ACCOUNT_W);
    if (mode == .wide) {
        try writer.writeAll(self.fg_color);
        try writer.writeAll(constants.VERTICAL);
        try writer.writeAll(terminal.RESET);
        try self.writeHeaderCell(writer, "TRUSTED ENTITIES", trusted_w);
    }
    try writer.writeAll(self.fg_color);
    try writer.writeAll(constants.VERTICAL);
    try writer.writeAll(terminal.RESET);
    try self.writeHeaderCell(writer, "LAST ACTIVITY", ACTIVITY_W);
    try writer.writeAll(self.fg_color);
    try writer.writeAll(constants.VERTICAL);
    try writer.writeAll(terminal.RESET);
}

fn writeRoleRow(self: *IamRolesView, writer: *std.Io.Writer, item: RoleItem, loading: bool, sel: bool, name_w: usize, trusted_w: usize, mode: Mode) !void {
    try self.writeVert(writer, sel, !sel);

    const content_w = if (name_w >= 2) name_w - 2 else 0;
    const max_name = if (content_w >= 2) content_w - 2 else 0;
    try writer.writeByte(' ');
    try writer.writeAll(if (sel) "▸ " else "  ");
    const shown_name = if (item.name.len > max_name) item.name[0..max_name] else item.name;
    try writer.writeAll(shown_name);
    for (shown_name.len..max_name) |_| try writer.writeByte(' ');
    try writer.writeByte(' ');

    const placeholder = if (loading) "…" else "-";

    try self.writeVert(writer, sel, !sel);
    try writePaddedCell(writer, item.account_id, ACCOUNT_W);

    if (mode == .wide) {
        try self.writeVert(writer, sel, !sel);
        const trusted = item.trusted_entity orelse placeholder;
        try writePaddedCell(writer, trusted, trusted_w);
    }

    try self.writeVert(writer, sel, !sel);
    const last = item.last_used orelse placeholder;
    try writePaddedCell(writer, last, ACTIVITY_W);
    try self.writeVert(writer, sel, true);
}

fn writeEmptyRow(self: *IamRolesView, writer: *std.Io.Writer, name_w: usize, trusted_w: usize, mode: Mode) !void {
    try self.writeVert(writer, false, true);
    for (0..name_w) |_| try writer.writeByte(' ');
    try self.writeVert(writer, false, true);
    for (0..ACCOUNT_W) |_| try writer.writeByte(' ');
    if (mode == .wide) {
        try self.writeVert(writer, false, true);
        for (0..trusted_w) |_| try writer.writeByte(' ');
    }
    try self.writeVert(writer, false, true);
    for (0..ACTIVITY_W) |_| try writer.writeByte(' ');
    try self.writeVert(writer, false, true);
}

pub fn render(self: *IamRolesView, writer: *std.Io.Writer, size: Coord) !void {
    if (size.x < 10 or size.y < 4) return;
    const w: usize = @intCast(size.x);
    const h: usize = @intCast(size.y);
    const inner = w - 2;
    const mode = modeFor(size.x);
    const name_w = nameWidth(inner, mode);
    const trusted_w = if (mode == .wide) trustedWidth(inner, name_w) else 0;
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
        try self.writeHeaderRow(writer, name_w, trusted_w, mode);
        try writer.writeAll("\r\n");
        try self.writeSepRow(writer, name_w, trusted_w, mode, false);
        try writer.writeAll("\r\n");
    }

    switch (self.state) {
        .loading => |ctx| {
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
            }

            self.ensureSorted(items);
            var vis_idx: usize = 0;
            var rendered: usize = 0;
            for (self.sorted_indices) |orig_idx| {
                const item = items[orig_idx];
                if (!self.matchesRole(item, filter)) continue;
                if (vis_idx >= self.scroll_offset and rendered < data_rows) {
                    try self.writeRoleRow(writer, item, true, vis_idx == self.selected, name_w, trusted_w, mode);
                    try writer.writeAll("\r\n");
                    rendered += 1;
                }
                vis_idx += 1;
            }
            for (rendered..data_rows) |_| {
                try self.writeEmptyRow(writer, name_w, trusted_w, mode);
                try writer.writeAll("\r\n");
            }
        },
        .ready => |ctx| {
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
                if (!self.matchesRole(item, filter)) continue;
                if (vis_idx >= self.scroll_offset and rendered < data_rows) {
                    try self.writeRoleRow(writer, item, false, vis_idx == self.selected, name_w, trusted_w, mode);
                    try writer.writeAll("\r\n");
                    rendered += 1;
                }
                vis_idx += 1;
            }
            for (rendered..data_rows) |_| {
                try self.writeEmptyRow(writer, name_w, trusted_w, mode);
                try writer.writeAll("\r\n");
            }
        },
        .failed => |e| {
            for (0..data_rows) |row| {
                try self.writeVert(writer, false, true);
                if (row == 0) {
                    var buf: [128]u8 = undefined;
                    const msg = std.fmt.bufPrint(&buf, " Error: {s}", .{@errorName(e)}) catch " Error loading roles";
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

    try self.writeSepRow(writer, name_w, trusted_w, mode, true);
}
