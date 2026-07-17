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
const credential_report = @import("../../../sdk/clients/iam/credential_report.zig");
const constants = @import("../../../ui/constants.zig");
const ConfirmView = @import("../../../ui/confirm.zig");
const IamUserView = @import("user.zig");
const filter_mod = @import("../../../commands/filter.zig");

const IamUsersView = @This();
pub const name: []const u8 = "Users";

// Column widths. Headers are centered within their cell (see writeHeaderCell),
// so each width must fit "<header text> + 2 padding" at minimum.
const PATH_W: usize = 10;
const GROUPS_W: usize = 20;
const ACTIVITY_W: usize = 22; // ISO-8601 timestamp "2026-06-27T14:31:29Z" = 20 chars + 2 padding.
const MFA_W: usize = 10;
const PW_AGE_W: usize = 16;
const CONSOLE_W: usize = 22;
const ACCOUNT_W: usize = 14; // 12-digit AWS account id + 2 padding.
const KEY_AGE_W: usize = 16;
const KEY_LAST_USED_W: usize = 22;

const Mode = enum {
    compact, // NAME | LAST ACTIVITY
    medium, // NAME | GROUPS | LAST ACTIVITY | MFA | ACCESS KEY LAST USED
    wide, // NAME | PATH | GROUPS | LAST ACTIVITY | MFA | PASSWORD AGE | CONSOLE SIGN-IN | ACCOUNT ID | ACTIVE KEY AGE | ACCESS KEY LAST USED
};

const MEDIUM_MIN_WIDTH: usize = 110;
const WIDE_MIN_WIDTH: usize = 200;

fn modeFor(width: i16) Mode {
    if (width >= WIDE_MIN_WIDTH) return .wide;
    if (width >= MEDIUM_MIN_WIDTH) return .medium;
    return .compact;
}

// Sum of fixed-width columns (excluding NAME) and the number of internal
// dividers they introduce, per mode. NAME always consumes whatever remains
// so the table exactly fills the available width.
fn fixedWidth(mode: Mode) usize {
    return switch (mode) {
        .compact => ACTIVITY_W,
        .medium => GROUPS_W + ACTIVITY_W + MFA_W + KEY_LAST_USED_W,
        .wide => PATH_W + GROUPS_W + ACTIVITY_W + MFA_W + PW_AGE_W + CONSOLE_W + ACCOUNT_W + KEY_AGE_W + KEY_LAST_USED_W,
    };
}

fn columnCount(mode: Mode) usize {
    return switch (mode) {
        .compact => 2,
        .medium => 5,
        .wide => 10,
    };
}

pub const UserSortKey = enum { name, account, created, activity };

const SortCtx = struct {
    items: []const UserItem,
    keys: []const UserSortKey,
    dir: constants.SortDir,

    fn lessThan(ctx: @This(), a: usize, b: usize) bool {
        for (ctx.keys) |key| {
            const ord = compareField(ctx.items[a], ctx.items[b], key);
            if (ord != .eq) return if (ctx.dir == .asc) ord == .lt else ord == .gt;
        }
        return false;
    }
};

fn compareField(a: UserItem, b: UserItem, key: UserSortKey) std.math.Order {
    return switch (key) {
        .name => std.mem.order(u8, a.name, b.name),
        .account => std.mem.order(u8, a.account_id, b.account_id),
        .created => std.mem.order(u8, a.create_date, b.create_date),
        .activity => std.mem.order(u8, a.lastActivity() orelse "", b.lastActivity() orelse ""),
    };
}

// ─── Enrichment (groups, keys, mfa, password) ────────────────────────────────

const Enrichment = struct {
    /// Comma-joined group names. Empty if the user belongs to no groups.
    groups: []u8,
    mfa_active: bool,
    password_enabled: bool,
    /// Owned. Null if the user has no password or the report doesn't know.
    password_last_changed: ?[]u8,
    /// Owned. Null if the user has no access keys.
    access_key_id: ?[]u8,
    /// Owned. Paired with access_key_id.
    access_key_created: ?[]u8,
    /// Owned. Null if the key has never been used (but still exists).
    access_key_last_used: ?[]u8,

    fn deinit(self: Enrichment, allocator: std.mem.Allocator) void {
        allocator.free(self.groups);
        if (self.password_last_changed) |d| allocator.free(d);
        if (self.access_key_id) |k| allocator.free(k);
        if (self.access_key_created) |c| allocator.free(c);
        if (self.access_key_last_used) |u| allocator.free(u);
    }
};

// ─── Local item ─────────────────────────────────────────────────────────────

const UserItem = struct {
    allocator: std.mem.Allocator,
    name: []u8,
    arn: []u8,
    account_id: []u8,
    create_date: []u8,
    path: []u8,
    cred_idx: usize,
    password_last_used: ?[]u8 = null,
    enrichment: ?Enrichment = null,

    pub fn deinit(self: UserItem) void {
        self.allocator.free(self.name);
        self.allocator.free(self.arn);
        self.allocator.free(self.account_id);
        self.allocator.free(self.create_date);
        self.allocator.free(self.path);
        if (self.password_last_used) |p| self.allocator.free(p);
        if (self.enrichment) |e| e.deinit(self.allocator);
    }

    /// The more recent of console sign-in and access key usage, as a raw
    /// ISO-8601 string (lexically comparable). Null if neither is known.
    fn lastActivity(self: UserItem) ?[]const u8 {
        const console = self.password_last_used;
        const key: ?[]const u8 = if (self.enrichment) |e| e.access_key_last_used else null;
        if (console) |c| {
            if (key) |k| return if (std.mem.order(u8, c, k) == .lt) k else c;
            return c;
        }
        return key;
    }
};

const UserResolver = struct {
    item: UserItem,

    pub fn resolve(self: UserResolver, field: []const u8) filter_mod.FieldValue {
        if (std.mem.eql(u8, field, "name")) return .{ .string = self.item.name };
        if (std.mem.eql(u8, field, "arn")) return .{ .string = self.item.arn };
        if (std.mem.eql(u8, field, "path")) return .{ .string = self.item.path };
        if (std.mem.eql(u8, field, "account") or std.mem.eql(u8, field, "account_id")) return .{ .string = self.item.account_id };
        if (std.mem.eql(u8, field, "created") or std.mem.eql(u8, field, "create_date")) return .{ .string = self.item.create_date };
        if (std.mem.eql(u8, field, "activity") or std.mem.eql(u8, field, "last_activity")) return .{ .string = self.item.lastActivity() orelse "" };
        if (std.mem.eql(u8, field, "groups")) return .{ .string = if (self.item.enrichment) |e| e.groups else "" };
        if (std.mem.eql(u8, field, "mfa")) return .{ .string = if (self.item.enrichment) |e| (if (e.mfa_active) "true" else "false") else "" };
        return .unknown;
    }
};

// Parse account id from IAM user ARN: arn:aws:iam::{account}:user/{name}
fn parseAccountId(arn: []const u8) []const u8 {
    var it = std.mem.splitScalar(u8, arn, ':');
    _ = it.next(); // arn
    _ = it.next(); // aws
    _ = it.next(); // iam
    _ = it.next(); // region (empty for IAM)
    return it.next() orelse "";
}

fn userToItem(allocator: std.mem.Allocator, u: Iam.IamUser, cred_idx: usize) !UserItem {
    const item_name = try allocator.dupe(u8, u.user_name);
    errdefer allocator.free(item_name);
    const arn = try allocator.dupe(u8, u.arn);
    errdefer allocator.free(arn);
    const account_id = try allocator.dupe(u8, parseAccountId(u.arn));
    errdefer allocator.free(account_id);
    const create_date = try allocator.dupe(u8, if (u.create_date.len >= 10) u.create_date[0..10] else u.create_date);
    errdefer allocator.free(create_date);
    const path = try allocator.dupe(u8, u.path);
    errdefer allocator.free(path);
    const password_last_used: ?[]u8 = if (u.password_last_used) |p| try allocator.dupe(u8, p) else null;
    return .{
        .allocator = allocator,
        .name = item_name,
        .arn = arn,
        .account_id = account_id,
        .create_date = create_date,
        .path = path,
        .cred_idx = cred_idx,
        .password_last_used = password_last_used,
    };
}

// ─── Date/age helpers ────────────────────────────────────────────────────────

// Days-since-epoch for a Gregorian civil date (Howard Hinnant's algorithm).
fn daysFromCivil(y: i64, m: i64, d: i64) i64 {
    const yy = if (m <= 2) y - 1 else y;
    const era = @divFloor(if (yy >= 0) yy else yy - 399, 400);
    const yoe = yy - era * 400; // [0, 399]
    const mp = @mod(m + 9, 12); // [0, 11]
    const doy = @divFloor(153 * mp + 2, 5) + d - 1; // [0, 365]
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy; // [0, 146096]
    return era * 146097 + doe - 719468;
}

fn parseIsoDatePrefix(s: []const u8) ?struct { y: i64, m: i64, d: i64 } {
    if (s.len < 10) return null;
    const y = std.fmt.parseInt(i64, s[0..4], 10) catch return null;
    const m = std.fmt.parseInt(i64, s[5..7], 10) catch return null;
    const d = std.fmt.parseInt(i64, s[8..10], 10) catch return null;
    return .{ .y = y, .m = m, .d = d };
}

fn ageDaysFromNow(io: std.Io, date_str: []const u8) ?i64 {
    const parsed = parseIsoDatePrefix(date_str) orelse return null;
    const target_days = daysFromCivil(parsed.y, parsed.m, parsed.d);
    const now_s: i64 = @intCast(@divFloor(std.Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_s));
    const now_days = @divFloor(now_s, 86400);
    const age = now_days - target_days;
    return if (age >= 0) age else 0;
}

fn formatAgeDays(io: std.Io, buf: []u8, date_str: []const u8) []const u8 {
    const days = ageDaysFromNow(io, date_str) orelse return "-";
    return std.fmt.bufPrint(buf, "{d}d", .{days}) catch "-";
}

// Blocks the calling thread for roughly `ms` milliseconds via the io backend.
fn sleepMs(io: std.Io, ms: u64) void {
    var futex = std.atomic.Value(u32).init(0);
    std.Io.futexWaitTimeout(io, u32, &futex.raw, 0, .{
        .duration = .{ .raw = .{ .nanoseconds = ms * std.time.ns_per_ms }, .clock = .real },
    }) catch {};
}

// ─── Concurrency ─────────────────────────────────────────────────────────────

const ENRICH_WORKERS = 8;

const FetchCtx = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    creds: []Credentials,
    mutex: std.atomic.Mutex = .unlocked,
    items: std.ArrayList(UserItem) = .empty,
    /// One optional parsed credential report per entry in `creds`, fetched once
    /// up front (Phase 1.5) since it covers every user in that account.
    credential_reports: []?credential_report.CredentialReport = &.{},
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

// Lists all users for a single profile (cred_idx into ctx.creds), appending into shared ctx.items.
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

        const result = client.listUsers(.{
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
        for (result.users) |u| {
            const item = userToItem(ctx.allocator, u, cred_idx) catch |e| {
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

// Generates (if needed) and fetches+parses the account's credential report.
// Returns null on any error; enrichment simply falls back to placeholders.
fn fetchCredentialReportFor(ctx: *FetchCtx, cred_idx: usize) ?credential_report.CredentialReport {
    var client = Iam.Client.init(ctx.allocator, .{
        .io = ctx.io,
        .credentials = ctx.creds[cred_idx],
    }) catch return null;
    defer client.deinit();

    var attempts: usize = 0;
    const complete = while (attempts < 15) : (attempts += 1) {
        if (ctx.cancel.load(.acquire)) return null;
        var gen = client.generateCredentialReport() catch return null;
        defer gen.deinit();
        if (gen.state == .COMPLETE) break true;
        sleepMs(ctx.io, 200);
    } else false;
    if (!complete) return null;

    var report = client.getCredentialReport() catch return null;
    defer report.deinit();
    return credential_report.parse(ctx.allocator, report.content) catch null;
}

fn joinNames(allocator: std.mem.Allocator, names: []const []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    for (names, 0..) |n, i| {
        if (i > 0) try out.appendSlice(allocator, ", ");
        try out.appendSlice(allocator, n);
    }
    return out.toOwnedSlice(allocator);
}

fn fetchGroups(ctx: *FetchCtx, client: *Iam.Client, user_name: []const u8) []u8 {
    var names: std.ArrayList([]const u8) = .empty;
    defer names.deinit(ctx.allocator);

    var marker: ?[]u8 = null;
    defer if (marker) |m| ctx.allocator.free(m);

    while (true) {
        const result = client.listGroupsForUser(.{
            .user_name = user_name,
            .params = .{ .marker = marker },
        }) catch break;
        defer result.deinit();

        for (result.groups) |g| {
            names.append(ctx.allocator, g.group_name) catch continue;
        }

        if (marker) |m| ctx.allocator.free(m);
        marker = if (result.next_marker) |m| ctx.allocator.dupe(u8, m) catch null else null;
        if (result.next_marker == null) break;
    }

    return joinNames(ctx.allocator, names.items) catch (ctx.allocator.dupe(u8, "") catch "");
}

const KeyInfo = struct {
    access_key_id: []u8,
    access_key_created: []u8,
    access_key_last_used: ?[]u8,
};

fn fetchAccessKey(ctx: *FetchCtx, client: *Iam.Client, user_name: []const u8) ?KeyInfo {
    const result = client.listAccessKeys(.{ .user_name = user_name }) catch return null;
    defer result.deinit();
    if (result.access_keys.len == 0) return null;

    var chosen = result.access_keys[0];
    for (result.access_keys) |k| {
        if (std.mem.eql(u8, k.status, "Active")) {
            chosen = k;
            break;
        }
    }

    const access_key_id = ctx.allocator.dupe(u8, chosen.access_key_id) catch return null;
    errdefer ctx.allocator.free(access_key_id);
    const access_key_created = ctx.allocator.dupe(u8, chosen.create_date) catch return null;
    errdefer ctx.allocator.free(access_key_created);

    const last_used_result = client.getAccessKeyLastUsed(.{ .access_key_id = chosen.access_key_id }) catch null;
    const access_key_last_used: ?[]u8 = if (last_used_result) |r| blk: {
        defer r.deinit();
        break :blk if (r.last_used_date) |d| ctx.allocator.dupe(u8, d) catch null else null;
    } else null;

    return .{
        .access_key_id = access_key_id,
        .access_key_created = access_key_created,
        .access_key_last_used = access_key_last_used,
    };
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
        const user_name_copy = ctx.allocator.dupe(u8, ctx.items.items[i].name) catch {
            ctx.mutex.unlock();
            continue;
        };
        const cred_idx = ctx.items.items[i].cred_idx;
        ctx.mutex.unlock();
        defer ctx.allocator.free(user_name_copy);

        if (clients[cred_idx] == null) {
            clients[cred_idx] = Iam.Client.init(ctx.allocator, .{
                .io = ctx.io,
                .credentials = ctx.creds[cred_idx],
            }) catch continue;
        }
        const client = &clients[cred_idx].?;

        const groups = fetchGroups(ctx, client, user_name_copy);
        const key_info = fetchAccessKey(ctx, client, user_name_copy);

        const report = if (cred_idx < ctx.credential_reports.len) ctx.credential_reports[cred_idx] else null;
        const info: ?credential_report.UserCredentialInfo = if (report) |*r| r.get(user_name_copy) else null;

        const password_last_changed: ?[]u8 = if (info) |ci|
            if (ci.password_last_changed) |d| ctx.allocator.dupe(u8, d) catch null else null
        else
            null;

        const enrichment = Enrichment{
            .groups = groups,
            .mfa_active = if (info) |ci| ci.mfa_active else false,
            .password_enabled = if (info) |ci| ci.password_enabled else false,
            .password_last_changed = password_last_changed,
            .access_key_id = if (key_info) |k| k.access_key_id else null,
            .access_key_created = if (key_info) |k| k.access_key_created else null,
            .access_key_last_used = if (key_info) |k| k.access_key_last_used else null,
        };

        lockMutex(&ctx.mutex);
        if (ctx.items.items[i].enrichment) |old| old.deinit(ctx.allocator);
        ctx.items.items[i].enrichment = enrichment;
        ctx.mutex.unlock();

        input.notify();
    }
}

fn fetchThread(ctx: *FetchCtx) void {
    defer {
        ctx.done.store(true, .release);
        input.notify();
    }

    // Phase 1: list users for every profile in parallel.
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
    input.notify();

    // Phase 1.5: fetch each account's credential report once (covers every user in it).
    ctx.credential_reports = ctx.allocator.alloc(?credential_report.CredentialReport, ctx.creds.len) catch &.{};
    for (ctx.credential_reports) |*r| r.* = null;
    for (0..ctx.creds.len) |i| {
        if (ctx.cancel.load(.acquire)) return;
        ctx.credential_reports[i] = fetchCredentialReportFor(ctx, i);
    }

    if (ctx.cancel.load(.acquire)) return;
    input.notify();

    // Phase 2: enrich with groups/keys/credential-report data in parallel.
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
sort_keys: [4]UserSortKey = .{ .name, undefined, undefined, undefined },
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
) !IamUsersView {
    const colors = colors_mod.iam(color_support);
    const ctx = try spawnFetch(allocator, io, profile_set);

    var view = IamUsersView{
        .fg_color = colors.fg,
        .bg_color = colors.bg,
        .state = .{ .loading = ctx },
        .alloc = allocator,
        .io = io,
        .profile_set = profile_set,
        .color_support = color_support,
    };
    const bc = std.fmt.bufPrint(&view.breadcrumb_buf, "{s} {s} Users", .{ parent_breadcrumb, constants.SEP_ARROW }) catch view.breadcrumb_buf[0..0];
    view.breadcrumb_len = bc.len;
    return view;
}

fn freeState(self: *IamUsersView) void {
    switch (self.state) {
        .loading, .ready => |ctx| {
            ctx.cancel.store(true, .release);
            if (!ctx.done.load(.acquire)) ctx.thread.join();
            for (ctx.items.items) |item| item.deinit();
            ctx.items.deinit(ctx.allocator);
            for (ctx.credential_reports) |*r| if (r.*) |*rep| rep.deinit();
            if (ctx.credential_reports.len > 0) ctx.allocator.free(ctx.credential_reports);
            ctx.allocator.free(ctx.creds);
            ctx.allocator.destroy(ctx);
        },
        .failed => {},
    }
}

fn refresh(self: *IamUsersView) !void {
    self.freeState();
    const ctx = try spawnFetch(self.alloc, self.io, self.profile_set);
    self.state = .{ .loading = ctx };
    self.selected = 0;
    self.scroll_offset = 0;
    self.sort_dirty = true;
}

pub fn breadcrumb(self: *IamUsersView) []const u8 {
    return self.breadcrumb_buf[0..self.breadcrumb_len];
}

pub fn deinit(self: *IamUsersView) void {
    if (self.committed_filter) |f| self.alloc.free(f);
    if (self.filter_expr) |*fe| fe.deinit();
    if (self.sorted_indices.len > 0) self.alloc.free(self.sorted_indices);
    self.freeState();
}

fn effectiveFilter(self: *const IamUsersView) []const u8 {
    if (self.live_filter.len > 0) return self.live_filter;
    return self.committed_filter orelse "";
}

fn matchesUser(self: *const IamUsersView, item: UserItem, text_f: []const u8) bool {
    if (!filter_mod.matchesText(item.name, text_f)) return false;
    if (self.filter_expr) |*fe| {
        const resolver = UserResolver{ .item = item };
        if (!filter_mod.evalExpr(fe.expr, resolver)) return false;
    }
    return true;
}

fn visibleCount(self: *const IamUsersView, items: []const UserItem, text_f: []const u8) usize {
    var n: usize = 0;
    for (items) |item| {
        if (self.matchesUser(item, text_f)) n += 1;
    }
    return n;
}

fn recomputeSort(self: *IamUsersView, items: []const UserItem) void {
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

fn ensureSorted(self: *IamUsersView, items: []const UserItem) void {
    if (!self.sort_dirty and self.sorted_indices.len == items.len) return;
    self.recomputeSort(items);
    self.sort_dirty = false;
}

pub fn setSort(self: *IamUsersView, keys: []const UserSortKey, dir: constants.SortDir) void {
    const n = @min(keys.len, self.sort_keys.len);
    @memcpy(self.sort_keys[0..n], keys[0..n]);
    self.sort_keys_len = if (n > 0) n else 1;
    self.sort_dir = dir;
    self.sort_dirty = true;
    self.sort_applied = true;
    self.selected = 0;
    self.scroll_offset = 0;
}

pub fn clearSort(self: *IamUsersView) void {
    self.sort_keys[0] = .name;
    self.sort_keys_len = 1;
    self.sort_dir = .asc;
    self.sort_dirty = true;
    self.sort_applied = false;
    self.selected = 0;
    self.scroll_offset = 0;
}

pub fn setLiveFilter(self: *IamUsersView, text: []const u8) void {
    if (!std.mem.eql(u8, self.live_filter, text)) {
        self.selected = 0;
        self.scroll_offset = 0;
    }
    self.live_filter = text;
}

pub fn commitFilter(self: *IamUsersView, text: []const u8) void {
    if (self.committed_filter) |f| self.alloc.free(f);
    self.committed_filter = if (text.len == 0) null else self.alloc.dupe(u8, text) catch null;
    self.live_filter = "";
    self.selected = 0;
    self.scroll_offset = 0;
}

pub fn setFilterExpr(self: *IamUsersView, result: filter_mod.ParseResult) void {
    if (self.filter_expr) |*fe| fe.deinit();
    self.filter_expr = result;
    self.selected = 0;
    self.scroll_offset = 0;
}

pub fn clearFilterExpr(self: *IamUsersView) void {
    if (self.filter_expr) |*fe| fe.deinit();
    self.filter_expr = null;
    self.selected = 0;
    self.scroll_offset = 0;
}

// ─── Event handling ───────────────────────────────────────────────────────────

pub fn handleEvent(self: *IamUsersView, event: Event, vctx: ViewContext) !Action {
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
                var found: ?UserItem = null;
                for (self.sorted_indices) |orig_idx| {
                    const item = ctx.items.items[orig_idx];
                    if (!self.matchesUser(item, filter)) continue;
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
                const user_name = vctx.allocator.dupe(u8, item.name) catch {
                    ctx.mutex.unlock();
                    return .none;
                };
                const arn = vctx.allocator.dupe(u8, item.arn) catch {
                    vctx.allocator.free(user_name);
                    ctx.mutex.unlock();
                    return .none;
                };
                const create_date = vctx.allocator.dupe(u8, item.create_date) catch {
                    vctx.allocator.free(user_name);
                    vctx.allocator.free(arn);
                    ctx.mutex.unlock();
                    return .none;
                };
                const cred_idx = item.cred_idx;
                ctx.mutex.unlock();
                defer vctx.allocator.free(user_name);
                defer vctx.allocator.free(arn);
                defer vctx.allocator.free(create_date);

                const detail = try IamUserView.init(
                    vctx.allocator,
                    vctx.io,
                    ctx.creds[cred_idx],
                    user_name,
                    arn,
                    create_date,
                    self.color_support,
                    self.breadcrumb(),
                );
                return .{ .push = .{ .iam_user = detail } };
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

fn nameWidth(inner: usize, mode: Mode) usize {
    const dividers = columnCount(mode) - 1;
    const others = fixedWidth(mode) + dividers;
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

fn writeVert(self: *IamUsersView, writer: *std.Io.Writer, selected: bool, reset: bool) !void {
    if (selected) {
        try writer.writeAll(self.bg_color);
        try writer.writeAll(terminal.FG_BLACK);
    } else {
        try writer.writeAll(self.fg_color);
    }
    try writer.writeAll(constants.VERTICAL);
    if (reset) try writer.writeAll(terminal.RESET);
}

fn columnWidths(mode: Mode, name_w: usize, buf: []usize) []const usize {
    switch (mode) {
        .compact => {
            buf[0] = name_w;
            buf[1] = ACTIVITY_W;
            return buf[0..2];
        },
        .medium => {
            buf[0] = name_w;
            buf[1] = GROUPS_W;
            buf[2] = ACTIVITY_W;
            buf[3] = MFA_W;
            buf[4] = KEY_LAST_USED_W;
            return buf[0..5];
        },
        .wide => {
            buf[0] = name_w;
            buf[1] = PATH_W;
            buf[2] = GROUPS_W;
            buf[3] = ACTIVITY_W;
            buf[4] = MFA_W;
            buf[5] = PW_AGE_W;
            buf[6] = CONSOLE_W;
            buf[7] = ACCOUNT_W;
            buf[8] = KEY_AGE_W;
            buf[9] = KEY_LAST_USED_W;
            return buf[0..10];
        },
    }
}

fn columnHeaders(mode: Mode) []const []const u8 {
    return switch (mode) {
        .compact => &.{ "NAME", "LAST ACTIVITY" },
        .medium => &.{ "NAME", "GROUPS", "LAST ACTIVITY", "MFA", "ACCESS KEY LAST USED" },
        .wide => &.{ "NAME", "PATH", "GROUPS", "LAST ACTIVITY", "MFA", "PASSWORD AGE", "CONSOLE SIGN-IN", "ACCOUNT ID", "ACTIVE KEY AGE", "ACCESS KEY LAST USED" },
    };
}

fn writeSepRow(self: *IamUsersView, writer: *std.Io.Writer, widths: []const usize, bottom: bool) !void {
    const left = if (bottom) constants.BOTTOM_LEFT else constants.LEFT_T;
    const mid = if (bottom) constants.BOTTOM_T else constants.CROSS;
    const right = if (bottom) constants.BOTTOM_RIGHT else constants.RIGHT_T;

    try writer.writeAll(self.fg_color);
    try writer.writeAll(left);
    for (widths, 0..) |wdt, i| {
        for (0..wdt) |_| try writer.writeAll(constants.HORIZONTAL);
        try writer.writeAll(if (i + 1 < widths.len) mid else right);
    }
    try writer.writeAll(terminal.RESET);
}

fn writeHeaderCell(self: *IamUsersView, writer: *std.Io.Writer, text: []const u8, cell_w: usize) !void {
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

fn writeHeaderRow(self: *IamUsersView, writer: *std.Io.Writer, widths: []const usize, headers: []const []const u8) !void {
    for (widths, headers) |wdt, h| {
        try writer.writeAll(self.fg_color);
        try writer.writeAll(constants.VERTICAL);
        try writer.writeAll(terminal.RESET);
        try self.writeHeaderCell(writer, h, wdt);
    }
    try writer.writeAll(self.fg_color);
    try writer.writeAll(constants.VERTICAL);
    try writer.writeAll(terminal.RESET);
}

fn writeUserRow(self: *IamUsersView, writer: *std.Io.Writer, item: UserItem, loading: bool, sel: bool, mode: Mode, name_w: usize) !void {
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
    const e = item.enrichment;

    if (mode == .wide) {
        try self.writeVert(writer, sel, !sel);
        try writePaddedCell(writer, item.path, PATH_W);
    }

    if (mode != .compact) {
        try self.writeVert(writer, sel, !sel);
        const groups = if (e) |en| (if (en.groups.len > 0) en.groups else "-") else placeholder;
        try writePaddedCell(writer, groups, GROUPS_W);
    }

    try self.writeVert(writer, sel, !sel);
    const activity = item.lastActivity() orelse (if (loading and e == null) placeholder else "Never");
    try writePaddedCell(writer, activity, ACTIVITY_W);

    if (mode != .compact) {
        try self.writeVert(writer, sel, !sel);
        const mfa = if (e) |en| (if (en.mfa_active) "Enabled" else "Disabled") else placeholder;
        try writePaddedCell(writer, mfa, MFA_W);
    }

    if (mode == .wide) {
        try self.writeVert(writer, sel, !sel);
        var pw_buf: [16]u8 = undefined;
        const pw_age = if (e) |en|
            (if (en.password_last_changed) |d| formatAgeDays(self.io, &pw_buf, d) else "-")
        else
            placeholder;
        try writePaddedCell(writer, pw_age, PW_AGE_W);

        try self.writeVert(writer, sel, !sel);
        const console = item.password_last_used orelse (if (loading and e == null) placeholder else "Never");
        try writePaddedCell(writer, console, CONSOLE_W);

        try self.writeVert(writer, sel, !sel);
        try writePaddedCell(writer, item.account_id, ACCOUNT_W);

        try self.writeVert(writer, sel, !sel);
        var age_buf: [16]u8 = undefined;
        const key_age = if (e) |en|
            (if (en.access_key_created) |d| formatAgeDays(self.io, &age_buf, d) else "-")
        else
            placeholder;
        try writePaddedCell(writer, key_age, KEY_AGE_W);
    }

    if (mode != .compact) {
        try self.writeVert(writer, sel, !sel);
        const key_last_used = if (e) |en|
            (if (en.access_key_id == null) "-" else (en.access_key_last_used orelse "Never"))
        else
            placeholder;
        try writePaddedCell(writer, key_last_used, KEY_LAST_USED_W);
    }

    try self.writeVert(writer, sel, true);
}

fn writeEmptyRow(self: *IamUsersView, writer: *std.Io.Writer, widths: []const usize) !void {
    for (widths) |wdt| {
        try self.writeVert(writer, false, true);
        for (0..wdt) |_| try writer.writeByte(' ');
    }
    try self.writeVert(writer, false, true);
}

pub fn render(self: *IamUsersView, writer: *std.Io.Writer, size: Coord) !void {
    if (size.x < 10 or size.y < 4) return;
    const w: usize = @intCast(size.x);
    const h: usize = @intCast(size.y);
    const inner = w - 2;
    const mode = modeFor(size.x);
    const name_w = nameWidth(inner, mode);
    var widths_buf: [10]usize = undefined;
    const widths = columnWidths(mode, name_w, &widths_buf);
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
                    for (ctx.credential_reports) |*r| if (r.*) |*rep| rep.deinit();
                    if (ctx.credential_reports.len > 0) ctx.allocator.free(ctx.credential_reports);
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
        try self.writeHeaderRow(writer, widths, columnHeaders(mode));
        try writer.writeAll("\r\n");
        try self.writeSepRow(writer, widths, false);
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
                if (!self.matchesUser(item, filter)) continue;
                if (vis_idx >= self.scroll_offset and rendered < data_rows) {
                    try self.writeUserRow(writer, item, loading, vis_idx == self.selected, mode, name_w);
                    try writer.writeAll("\r\n");
                    rendered += 1;
                }
                vis_idx += 1;
            }
            for (rendered..data_rows) |_| {
                try self.writeEmptyRow(writer, widths);
                try writer.writeAll("\r\n");
            }
        },
        .failed => |e| {
            for (0..data_rows) |row| {
                try self.writeVert(writer, false, true);
                if (row == 0) {
                    var buf: [128]u8 = undefined;
                    const msg = std.fmt.bufPrint(&buf, " Error: {s}", .{@errorName(e)}) catch " Error loading users";
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

    try self.writeSepRow(writer, widths, true);
}
