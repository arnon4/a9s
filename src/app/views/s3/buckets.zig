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
const S3 = @import("../../../sdk/clients/s3/client.zig");
const constants = @import("../../../ui/constants.zig");
const S3ObjectsView = @import("objects.zig").S3ObjectsView;
const ConfirmView = @import("../../../ui/confirm.zig");
const CW = @import("../../../sdk/clients/cloudwatch/get/metric_data.zig");
const headBucket = @import("../../../sdk/clients/s3/head/bucket.zig").HeadBucket;
const filter_mod = @import("../../../commands/filter.zig");
const ProfileSet = @import("../../profile_set.zig").ProfileSet;
const ProfileEntry = @import("../../profile_set.zig").ProfileEntry;

pub const BucketSortKey = enum { name, region, creation_date, size, account };

const SortCtx = struct {
    items: []const S3.Bucket,
    sizes: ?*const std.StringHashMap(u64),
    profile_accounts: ?*const std.StringHashMap([]const u8),
    keys: []const BucketSortKey,
    dir: constants.SortDir,

    fn lessThan(ctx: @This(), a: usize, b: usize) bool {
        for (ctx.keys) |key| {
            const ord = compareField(ctx.items[a], ctx.items[b], key, ctx.sizes, ctx.profile_accounts);
            if (ord != .eq) return if (ctx.dir == .asc) ord == .lt else ord == .gt;
        }
        return false;
    }
};

const REGION_W: usize = 16;
const ACCOUNT_W: usize = 14;
const CREATED_W: usize = 12;
const SIZE_W: usize = 10;

const Mode = enum {
    wide,
    medium,
    compact,
};

pub const SourceCtx = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    credentials: Credentials,
    region: []u8,
    profile_name: []const u8,
    shared: *LoadCtx,
    thread: std.Thread = undefined,
    err: ?anyerror = null,
    done: std.atomic.Value(bool) = .init(false),
};

pub const LoadCtx = struct {
    allocator: std.mem.Allocator,
    mutex: std.atomic.Mutex = .unlocked,
    items: std.ArrayList(S3.Bucket) = .empty,
    sources: []*SourceCtx,
    pending: std.atomic.Value(usize),
    done: std.atomic.Value(bool) = .init(false),
};

const SizeCtx = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    creds_per_bucket: []Credentials,
    region: []u8,
    bucket_names: [][]u8,
    thread: std.Thread,
    sizes: std.StringHashMap(u64),
    err: ?anyerror = null,
    done: std.atomic.Value(bool),
};

const RegionCtx = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    creds_per_bucket: []Credentials,
    load_ctx: *LoadCtx,
    bucket_names: [][]u8,
    thread: std.Thread,
    fetched_count: std.atomic.Value(usize),
    done: std.atomic.Value(bool),
};

const RegionTaskArgs = struct {
    allocator: std.mem.Allocator,
    credentials: Credentials,
    bucket_name: []const u8,
    bucket_idx: usize,
    load_ctx: *LoadCtx,
    fetched_count: *std.atomic.Value(usize),
};

/// Busy-spin until the mutex is acquired.
/// Safe only for very short critical sections (list append, index update).
/// Do NOT hold the lock across I/O or allocation.
fn lockMutex(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

pub fn compareField(a: S3.Bucket, b: S3.Bucket, key: BucketSortKey, sizes: ?*const std.StringHashMap(u64), profile_accounts: ?*const std.StringHashMap([]const u8)) std.math.Order {
    return switch (key) {
        .name => std.mem.order(u8, a.name, b.name),
        .region => std.mem.order(u8, a.region, b.region),
        .creation_date => std.mem.order(u8, a.creation_date, b.creation_date),
        .size => blk: {
            const unknown = std.math.maxInt(u64);
            const sa = if (sizes) |m| (m.get(a.name) orelse unknown) else unknown;
            const sb = if (sizes) |m| (m.get(b.name) orelse unknown) else unknown;
            break :blk std.math.order(sa, sb);
        },
        .account => blk: {
            const sa = if (profile_accounts) |m| (m.get(a.profile_name) orelse a.profile_name) else a.profile_name;
            const sb = if (profile_accounts) |m| (m.get(b.profile_name) orelse b.profile_name) else b.profile_name;
            break :blk std.mem.order(u8, sa, sb);
        },
    };
}

fn modeFor(width: i16) Mode {
    if (width >= @intFromEnum(constants.Size.wide)) return .wide;
    if (width >= @intFromEnum(constants.Size.medium)) return .medium;
    return .compact;
}

fn nameWidth(inner: usize, mode: Mode) usize {
    const fixed: usize = switch (mode) {
        .wide => REGION_W + ACCOUNT_W + CREATED_W + SIZE_W + 4,
        .medium => REGION_W + CREATED_W + 2,
        .compact => REGION_W + 1,
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

fn writeDateCell(writer: *std.Io.Writer, iso: []const u8) !void {
    const date = if (iso.len >= 10) iso[0..10] else iso;
    try writePaddedCell(writer, date, CREATED_W);
}

fn regionTask(io: std.Io, args: *RegionTaskArgs) error{Canceled}!void {
    const head_result = headBucket(args.allocator, io, args.bucket_name, null, args.credentials) catch |err| {
        if (err == error.Canceled) return error.Canceled;
        std.log.err("HeadBucket failed for {s}: {}", .{ args.bucket_name, err });
        return;
    };
    const new_region = args.allocator.dupe(u8, head_result.region) catch {
        head_result.deinit();
        return;
    };
    head_result.deinit();
    lockMutex(&args.load_ctx.mutex);
    if (args.bucket_idx < args.load_ctx.items.items.len) {
        const b = &args.load_ctx.items.items[args.bucket_idx];
        b.allocator.free(b.region);
        b.region = new_region;
    } else {
        args.allocator.free(new_region);
    }
    args.load_ctx.mutex.unlock();
    _ = args.fetched_count.fetchAdd(1, .monotonic);
    input.notify();
}

fn regionFetchThread(ctx: *RegionCtx) void {
    defer {
        ctx.done.store(true, .release);
        input.notify();
    }
    const n = ctx.bucket_names.len;
    if (n == 0) return;

    const tasks = ctx.allocator.alloc(RegionTaskArgs, n) catch return;
    defer ctx.allocator.free(tasks);

    for (ctx.bucket_names, 0..) |bucket_name, i| {
        tasks[i] = .{
            .allocator = ctx.allocator,
            .credentials = ctx.creds_per_bucket[i],
            .bucket_name = bucket_name,
            .bucket_idx = i,
            .load_ctx = ctx.load_ctx,
            .fetched_count = &ctx.fetched_count,
        };
    }

    var group: std.Io.Group = .{
        .token = std.atomic.Value(?*anyopaque).init(null),
        .state = 0,
    };
    for (tasks) |*t| {
        group.async(ctx.io, regionTask, .{ ctx.io, t });
    }
    group.await(ctx.io) catch {};
}

fn sizeFetchThread(ctx: *SizeCtx) void {
    defer {
        ctx.done.store(true, .release);
        input.notify();
    }

    const alloc = ctx.allocator;
    const now_ns = std.Io.Timestamp.now(ctx.io, .real).nanoseconds;
    const now_s: i64 = @intCast(@divTrunc(now_ns, std.time.ns_per_s));
    const start_time = now_s - 172800;

    const names = ctx.bucket_names;

    // Process buckets grouped by account (matched via access_key_id). Each group
    // gets its own CloudWatch call so we use the right account's credentials.
    var processed = alloc.alloc(bool, names.len) catch return;
    defer alloc.free(processed);
    @memset(processed, false);

    const endpoint = std.fmt.allocPrint(alloc, "https://monitoring.{s}.amazonaws.com/", .{ctx.region}) catch return;
    defer alloc.free(endpoint);

    var gi: usize = 0;
    while (gi < names.len) {
        if (processed[gi]) {
            gi += 1;
            continue;
        }

        const group_creds = ctx.creds_per_bucket[gi];

        // Collect indices of all buckets sharing this access_key_id.
        var group: std.ArrayList(usize) = .empty;
        defer group.deinit(alloc);
        for (ctx.creds_per_bucket, 0..) |bc, i| {
            if (!processed[i] and std.mem.eql(u8, bc.access_key_id, group_creds.access_key_id)) {
                group.append(alloc, i) catch continue;
                processed[i] = true;
            }
        }

        // Issue CloudWatch requests for this group in batches of 500.
        const batch_size = 500;
        var offset: usize = 0;
        while (offset < group.items.len) {
            const end = @min(offset + batch_size, group.items.len);
            const batch_indices = group.items[offset..end];

            var arena = std.heap.ArenaAllocator.init(alloc);
            defer arena.deinit();
            const a = arena.allocator();

            const dims_buf = a.alloc([2]CW.Dimension, batch_indices.len) catch {
                offset = end;
                continue;
            };
            const queries = a.alloc(CW.MetricDataQuery, batch_indices.len) catch {
                offset = end;
                continue;
            };
            var id_bufs: [500][8]u8 = undefined;

            for (batch_indices, 0..) |idx, k| {
                dims_buf[k] = .{
                    .{ .name = "BucketName", .value = names[idx] },
                    .{ .name = "StorageType", .value = "StandardStorage" },
                };
                // Encode the original names index so result parsing maps back correctly.
                const id = std.fmt.bufPrint(&id_bufs[k], "b{d}", .{idx}) catch unreachable;
                queries[k] = .{
                    .id = id,
                    .metric_stat = .{
                        .metric = .{
                            .namespace = "AWS/S3",
                            .metric_name = "BucketSizeBytes",
                            .dimensions = &dims_buf[k],
                        },
                        .period = 86400,
                        .stat = "Average",
                    },
                };
            }

            const result = CW.getMetricDataWithIo(
                alloc,
                ctx.io,
                group_creds,
                ctx.region,
                endpoint,
                .{
                    .start_time = start_time,
                    .end_time = now_s,
                    .queries = queries,
                },
            ) catch |e| {
                std.log.err("GetMetricData (bucket sizes): region={s} err={}", .{ ctx.region, e });
                ctx.err = e;
                offset = end;
                continue;
            };
            defer result.deinit();

            for (result.metric_data_results) |r| {
                if (r.status_code != .complete and r.status_code != .partial_data) continue;
                if (r.values.len == 0) continue;
                const idx_str = if (r.id.len > 1 and r.id[0] == 'b') r.id[1..] else continue;
                const idx = std.fmt.parseInt(usize, idx_str, 10) catch continue;
                if (idx >= names.len) continue;
                const bytes: u64 = @intFromFloat(r.values[0]);
                ctx.sizes.put(names[idx], bytes) catch continue;
            }

            offset = end;
        }

        while (gi < names.len and processed[gi]) gi += 1;
    }
}

fn fetchSourceThread(src: *SourceCtx) void {
    defer {
        src.done.store(true, .release);
        const prev = src.shared.pending.fetchSub(1, .release);
        if (prev == 1) {
            src.shared.done.store(true, .release);
        }
        input.notify();
    }

    std.log.debug("ListBuckets: fetch start profile={s} region='{s}'", .{ src.profile_name, src.region });

    var s3_client = S3.Client.init(src.allocator, .{
        .region = src.region,
        .io = src.io,
        .credentials = src.credentials,
    }) catch |e| {
        std.log.err("ListBuckets: S3 client init failed profile={s} err={}", .{ src.profile_name, e });
        src.err = e;
        return;
    };
    std.log.debug("ListBuckets: endpoint='{s}' profile={s}", .{ s3_client.endpoint, src.profile_name });
    defer s3_client.deinit();

    const alloc = src.allocator;
    var next_token: ?[]u8 = null;
    defer if (next_token) |t| alloc.free(t);

    while (true) {
        const result = s3_client.listBuckets(.{
            .continuation_token = next_token,
        }) catch |e| {
            std.log.err("ListBuckets: request failed profile={s} err={}", .{ src.profile_name, e });
            src.err = e;
            return;
        };
        defer result.deinit();

        if (next_token) |t| alloc.free(t);
        next_token = if (result.next_continuation_token) |t|
            alloc.dupe(u8, t) catch |e| {
                src.err = e;
                return;
            }
        else
            null;

        const is_last = !result.is_truncated;

        lockMutex(&src.shared.mutex);
        outer: for (result.buckets) |b| {
            var cloned = b.clone(alloc) catch |e| {
                src.err = e;
                break :outer;
            };
            if (src.profile_name.len > 0) {
                cloned.profile_name = alloc.dupe(u8, src.profile_name) catch b.profile_name;
            }
            src.shared.items.append(alloc, cloned) catch |e| {
                cloned.deinit();
                src.err = e;
                break :outer;
            };
        }
        const had_error = src.err != null;
        src.shared.mutex.unlock();

        if (had_error or is_last) break;
        input.notify();
    }
}

pub fn S3BucketsViewGeneric(comptime fetchFn: fn (*SourceCtx) void) type {
    return struct {
        const Self = @This();
        pub const name: []const u8 = "Buckets";

        const State = union(enum) {
            active: *LoadCtx,
            failed: anyerror,
        };

        const SourceInfo = struct {
            credentials: Credentials,
            profile_name: []u8,
            account_id: []u8,

            fn deinit(self: SourceInfo, allocator: std.mem.Allocator) void {
                allocator.free(self.profile_name);
                allocator.free(self.account_id);
            }
        };

        const BucketResolver = struct {
            bucket: S3.Bucket,
            size: ?u64,

            pub fn resolve(self: BucketResolver, field: []const u8) filter_mod.FieldValue {
                if (std.mem.eql(u8, field, "name")) return .{ .string = self.bucket.name };
                if (std.mem.eql(u8, field, "region")) return .{ .string = self.bucket.region };
                if (std.mem.eql(u8, field, "profile")) return .{ .string = self.bucket.profile_name };
                if (std.mem.eql(u8, field, "created") or std.mem.eql(u8, field, "creation_date"))
                    return .{ .string = if (self.bucket.creation_date.len >= 10) self.bucket.creation_date[0..10] else self.bucket.creation_date };
                if (std.mem.eql(u8, field, "size")) {
                    if (self.size) |s| return .{ .bytes = s };
                    return .unknown;
                }
                return .unknown;
            }
        };

        fg_color: []const u8,
        bg_color: []const u8,
        state: State,
        selected: usize = 0,
        scroll_offset: usize = 0,
        pending_g: bool = false,
        alloc: std.mem.Allocator,
        io: std.Io,
        sources: []SourceInfo,
        multi_source: bool,
        region_buf: [64]u8,
        region_len: usize,
        account_buf: [16]u8 = undefined,
        account_len: usize = 0,
        size_ctx: ?*SizeCtx = null,
        region_ctx: ?*RegionCtx = null,
        committed_filter: ?[]u8 = null,
        live_filter: []const u8 = "",
        filter_expr: ?filter_mod.ParseResult = null,
        sort_keys: [4]BucketSortKey = .{ .name, undefined, undefined, undefined },
        sort_keys_len: usize = 1,
        sort_dir: constants.SortDir = .asc,
        sorted_indices: []usize = &.{},
        last_sorted_len: usize = 0,
        last_size_ready: bool = false,
        last_region_count: usize = 0,
        sort_dirty: bool = false,
        sort_applied: bool = false,

        fn matchesBucket(self: *const Self, b: S3.Bucket, text_f: []const u8, sizes: ?*const std.StringHashMap(u64)) bool {
            if (!filter_mod.matchesText(b.name, text_f)) return false;
            if (self.filter_expr) |*fe| {
                const resolver = BucketResolver{
                    .bucket = b,
                    .size = if (sizes) |m| m.get(b.name) else null,
                };
                if (!filter_mod.evalExpr(fe.expr, resolver)) return false;
            }
            return true;
        }

        fn visibleCount(self: *const Self, items: []const S3.Bucket, text_f: []const u8, sizes: ?*const std.StringHashMap(u64)) usize {
            var n: usize = 0;
            for (items) |b| {
                if (self.matchesBucket(b, text_f, sizes)) n += 1;
            }
            return n;
        }

        fn effectiveFilter(self: *const Self) []const u8 {
            if (self.live_filter.len > 0) return self.live_filter else return self.committed_filter orelse "";
        }

        fn recomputeSort(self: *Self, items: []const S3.Bucket, sizes: ?*const std.StringHashMap(u64)) void {
            if (self.sorted_indices.len > 0) {
                self.alloc.free(self.sorted_indices);
                self.sorted_indices = &.{};
            }
            const indices = self.alloc.alloc(usize, items.len) catch return;
            for (indices, 0..) |*idx, i| idx.* = i;
            var accounts = std.StringHashMap([]const u8).init(self.alloc);
            defer accounts.deinit();
            for (self.sources) |si| {
                if (si.account_id.len > 0) accounts.put(si.profile_name, si.account_id) catch {};
            }
            const accounts_ptr: ?*const std.StringHashMap([]const u8) = if (accounts.count() > 0) &accounts else null;
            std.mem.sortUnstable(usize, indices, SortCtx{
                .items = items,
                .sizes = sizes,
                .profile_accounts = accounts_ptr,
                .keys = self.sort_keys[0..self.sort_keys_len],
                .dir = self.sort_dir,
            }, SortCtx.lessThan);
            self.sorted_indices = indices;
            self.last_sorted_len = items.len;
        }

        fn ensureSorted(self: *Self, items: []const S3.Bucket) void {
            const size_ready = self.size_ctx != null and self.size_ctx.?.done.load(.acquire);
            const region_count = if (self.region_ctx) |rc| rc.fetched_count.load(.acquire) else 0;
            if (!self.sort_dirty and
                self.sorted_indices.len == items.len and
                size_ready == self.last_size_ready and
                region_count == self.last_region_count) return;
            const sizes_ptr: ?*const std.StringHashMap(u64) = if (size_ready) &self.size_ctx.?.sizes else null;
            self.recomputeSort(items, sizes_ptr);
            self.last_size_ready = size_ready;
            self.last_region_count = region_count;
            self.sort_dirty = false;
        }

        pub fn setSort(self: *Self, keys: []const BucketSortKey, dir: constants.SortDir) void {
            const n = @min(keys.len, self.sort_keys.len);
            @memcpy(self.sort_keys[0..n], keys[0..n]);
            self.sort_keys_len = if (n > 0) n else 1;
            self.sort_dir = dir;
            self.sort_dirty = true;
            self.sort_applied = true;
            self.selected = 0;
            self.scroll_offset = 0;
        }

        pub fn clearSort(self: *Self) void {
            self.sort_keys[0] = .name;
            self.sort_keys_len = 1;
            self.sort_dir = .asc;
            self.sort_dirty = true;
            self.sort_applied = false;
            self.selected = 0;
            self.scroll_offset = 0;
        }

        pub fn setLiveFilter(self: *Self, text: []const u8) void {
            if (!std.mem.eql(u8, self.live_filter, text)) {
                self.selected = 0;
                self.scroll_offset = 0;
            }
            self.live_filter = text;
        }

        pub fn commitFilter(self: *Self, text: []const u8) void {
            if (self.committed_filter) |f| self.alloc.free(f);
            if (text.len == 0) {
                self.committed_filter = null;
            } else {
                self.committed_filter = self.alloc.dupe(u8, text) catch null;
            }
            self.live_filter = "";
            self.selected = 0;
            self.scroll_offset = 0;
        }

        pub fn setFilterExpr(self: *Self, result: filter_mod.ParseResult) void {
            if (self.filter_expr) |*fe| fe.deinit();
            self.filter_expr = result;
            self.selected = 0;
            self.scroll_offset = 0;
        }

        pub fn clearFilterExpr(self: *Self) void {
            if (self.filter_expr) |*fe| fe.deinit();
            self.filter_expr = null;
            self.selected = 0;
            self.scroll_offset = 0;
        }

        pub fn init(
            allocator: std.mem.Allocator,
            io: std.Io,
            profile_set: *const ProfileSet,
            region: []const u8,
            color_support: terminal.ColorSupport,
        ) !Self {
            const colors = colors_mod.green(color_support);
            const fg_color = colors.fg;
            const bg_color = colors.bg;

            var source_list: std.ArrayList(SourceInfo) = .empty;
            defer {
                for (source_list.items) |si| si.deinit(allocator);
                source_list.deinit(allocator);
            }

            for (profile_set.entries.items) |*entry| {
                const creds = entry.store.getCredentials() catch continue;
                const profile_name = try allocator.dupe(u8, entry.name);
                errdefer allocator.free(profile_name);
                const account_id = try allocator.dupe(u8, entry.account_id orelse "");
                errdefer allocator.free(account_id);
                try source_list.append(allocator, .{
                    .credentials = creds,
                    .profile_name = profile_name,
                    .account_id = account_id,
                });
            }

            if (source_list.items.len == 0) return error.NoCredentials;

            const sources_owned = try source_list.toOwnedSlice(allocator);
            source_list = .empty;
            errdefer {
                for (sources_owned) |si| si.deinit(allocator);
                allocator.free(sources_owned);
            }

            const new_ctx = try allocator.create(LoadCtx);
            errdefer allocator.destroy(new_ctx);

            const new_sources = try allocator.alloc(*SourceCtx, sources_owned.len);
            errdefer allocator.free(new_sources);

            new_ctx.* = .{
                .allocator = allocator,
                .sources = new_sources,
                .pending = std.atomic.Value(usize).init(sources_owned.len),
                .done = std.atomic.Value(bool).init(false),
            };

            var region_buf: [64]u8 = undefined;
            const rlen = @min(region.len, region_buf.len);
            @memcpy(region_buf[0..rlen], region[0..rlen]);

            var spawned: usize = 0;
            errdefer for (new_sources[0..spawned]) |src| {
                src.thread.join();
                src.allocator.free(src.region);
                allocator.destroy(src);
            };

            for (sources_owned, 0..) |si, i| {
                const src = try allocator.create(SourceCtx);
                errdefer allocator.destroy(src);
                const region_copy = try allocator.dupe(u8, region[0..rlen]);
                errdefer allocator.free(region_copy);
                src.* = .{
                    .allocator = allocator,
                    .io = io,
                    .credentials = si.credentials,
                    .region = region_copy,
                    .profile_name = si.profile_name,
                    .shared = new_ctx,
                    .done = std.atomic.Value(bool).init(false),
                };
                src.thread = try std.Thread.spawn(.{}, fetchFn, .{src});
                new_sources[i] = src;
                spawned += 1;
            }

            var view = Self{
                .fg_color = fg_color,
                .bg_color = bg_color,
                .state = .{ .active = new_ctx },
                .alloc = allocator,
                .io = io,
                .sources = sources_owned,
                .multi_source = sources_owned.len > 1,
                .region_buf = region_buf,
                .region_len = rlen,
            };

            if (!view.multi_source and profile_set.entries.items.len > 0) {
                if (profile_set.entries.items[0].account_id) |aid| {
                    const alen = @min(aid.len, view.account_buf.len);
                    @memcpy(view.account_buf[0..alen], aid[0..alen]);
                    view.account_len = alen;
                }
            }

            return view;
        }

        pub fn breadcrumb(_: *Self) []const u8 {
            return "Buckets";
        }

        fn deinitRegionCtx(self: *Self) void {
            const ctx = self.region_ctx orelse return;
            if (!ctx.done.load(.acquire)) ctx.thread.join();
            for (ctx.bucket_names) |n| ctx.allocator.free(n);
            ctx.allocator.free(ctx.bucket_names);
            ctx.allocator.free(ctx.creds_per_bucket);
            ctx.allocator.destroy(ctx);
            self.region_ctx = null;
        }

        fn deinitSizeCtx(self: *Self) void {
            const ctx = self.size_ctx orelse return;
            if (!ctx.done.load(.acquire)) {
                ctx.thread.join();
            }
            for (ctx.bucket_names) |n| ctx.allocator.free(n);
            ctx.allocator.free(ctx.bucket_names);
            ctx.allocator.free(ctx.creds_per_bucket);
            ctx.allocator.free(ctx.region);
            ctx.sizes.deinit();
            ctx.allocator.destroy(ctx);
            self.size_ctx = null;
        }

        pub fn deinit(self: *Self) void {
            if (self.committed_filter) |f| self.alloc.free(f);
            if (self.filter_expr) |*fe| fe.deinit();
            if (self.sorted_indices.len > 0) self.alloc.free(self.sorted_indices);
            self.deinitRegionCtx();
            self.deinitSizeCtx();
            switch (self.state) {
                .active => |ctx| {
                    for (ctx.sources) |src| {
                        if (!src.done.load(.acquire)) src.thread.join();
                        src.allocator.free(src.region);
                        src.allocator.destroy(src);
                    }
                    ctx.allocator.free(ctx.sources);
                    for (ctx.items.items) |b| b.deinit();
                    ctx.items.deinit(ctx.allocator);
                    ctx.allocator.destroy(ctx);
                },
                .failed => {},
            }
            for (self.sources) |si| si.deinit(self.alloc);
            self.alloc.free(self.sources);
        }

        fn refresh(self: *Self) !void {
            if (self.committed_filter) |f| self.alloc.free(f);
            self.committed_filter = null;
            self.live_filter = "";
            if (self.filter_expr) |*fe| fe.deinit();
            self.filter_expr = null;
            if (self.sorted_indices.len > 0) {
                self.alloc.free(self.sorted_indices);
                self.sorted_indices = &.{};
            }
            self.last_sorted_len = 0;
            self.last_size_ready = false;
            self.last_region_count = 0;
            self.sort_dirty = true;
            self.sort_applied = false;
            self.deinitRegionCtx();
            self.deinitSizeCtx();
            switch (self.state) {
                .active => |ctx| {
                    var all_done = true;
                    for (ctx.sources) |src| {
                        if (!src.done.load(.acquire)) {
                            all_done = false;
                            break;
                        }
                    }
                    if (!all_done) return;
                    for (ctx.sources) |src| {
                        src.allocator.free(src.region);
                        src.allocator.destroy(src);
                    }
                    ctx.allocator.free(ctx.sources);
                    for (ctx.items.items) |b| b.deinit();
                    ctx.items.deinit(ctx.allocator);
                    ctx.allocator.destroy(ctx);
                },
                .failed => {},
            }
            const alloc = self.alloc;
            const new_ctx = try alloc.create(LoadCtx);
            errdefer alloc.destroy(new_ctx);

            const new_sources = try alloc.alloc(*SourceCtx, self.sources.len);
            errdefer alloc.free(new_sources);

            var spawned: usize = 0;
            errdefer for (new_sources[0..spawned]) |src| {
                src.thread.join();
                src.allocator.free(src.region);
                alloc.destroy(src);
            };

            new_ctx.* = .{
                .allocator = alloc,
                .sources = new_sources,
                .pending = std.atomic.Value(usize).init(self.sources.len),
                .done = std.atomic.Value(bool).init(false),
            };

            for (self.sources, 0..) |si, i| {
                const src = try alloc.create(SourceCtx);
                errdefer alloc.destroy(src);
                const region_copy = try alloc.dupe(u8, self.region_buf[0..self.region_len]);
                errdefer alloc.free(region_copy);
                src.* = .{
                    .allocator = alloc,
                    .io = self.io,
                    .credentials = si.credentials,
                    .region = region_copy,
                    .profile_name = si.profile_name,
                    .shared = new_ctx,
                    .done = std.atomic.Value(bool).init(false),
                };
                src.thread = try std.Thread.spawn(.{}, fetchFn, .{src});
                new_sources[i] = src;
                spawned += 1;
            }

            self.state = .{ .active = new_ctx };
            self.selected = 0;
            self.scroll_offset = 0;
        }

        pub fn handleEvent(self: *Self, event: Event, ctx: ViewContext) !Action {
            const filter = self.effectiveFilter();
            const count: usize = switch (self.state) {
                .active => |lctx| blk: {
                    lockMutex(&lctx.mutex);
                    defer lctx.mutex.unlock();
                    const sizes_ptr: ?*const std.StringHashMap(u64) =
                        if (self.size_ctx) |sc| if (sc.done.load(.acquire)) &sc.sizes else null else null;
                    break :blk self.visibleCount(lctx.items.items, filter, sizes_ptr);
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
                            const enter_items = lctx.items.items;
                            const enter_sizes: ?*const std.StringHashMap(u64) =
                                if (self.size_ctx) |sc| if (sc.done.load(.acquire)) &sc.sizes else null else null;
                            self.ensureSorted(enter_items);
                            var vis: usize = 0;
                            var found: ?[]const u8 = null;
                            var found_region: []const u8 = "";
                            var found_profile: []const u8 = "";
                            for (self.sorted_indices) |orig_idx| {
                                const b = enter_items[orig_idx];
                                if (!self.matchesBucket(b, filter, enter_sizes)) continue;
                                if (vis == self.selected) {
                                    found = b.name;
                                    found_region = b.region;
                                    found_profile = b.profile_name;
                                    break;
                                }
                                vis += 1;
                            }
                            lctx.mutex.unlock();
                            if (found) |bname| {
                                if (found_region.len == 0 or std.mem.eql(u8, found_region, "-")) return .none;
                                if (self.committed_filter) |f| self.alloc.free(f);
                                self.committed_filter = null;
                                self.live_filter = "";
                                self.clearSort();
                                var creds = self.sources[0].credentials;
                                for (self.sources) |si| {
                                    if (std.mem.eql(u8, si.profile_name, found_profile)) {
                                        creds = si.credentials;
                                        break;
                                    }
                                }
                                const v = try S3ObjectsView.init(ctx.allocator, ctx.io, creds, found_region, bname, ctx.color_support);
                                return .{ .push = .{ .s3_objects = v } };
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

        fn writeVert(self: *Self, writer: *std.Io.Writer, selected: bool, reset: bool) !void {
            if (selected) {
                try writer.writeAll(self.bg_color);
                try writer.writeAll(terminal.FG_BLACK);
            } else {
                try writer.writeAll(self.fg_color);
            }
            try writer.writeAll(constants.VERTICAL);
            if (reset) try writer.writeAll(terminal.RESET);
        }

        fn writeSepRow(self: *Self, writer: *std.Io.Writer, name_w: usize, mode: Mode, bottom: bool) !void {
            const left = if (bottom) constants.BOTTOM_LEFT else constants.LEFT_T;
            const mid = if (bottom) constants.BOTTOM_T else constants.CROSS;
            const right = if (bottom) constants.BOTTOM_RIGHT else constants.RIGHT_T;

            try writer.writeAll(self.fg_color);
            try writer.writeAll(left);
            for (0..name_w) |_| try writer.writeAll(constants.HORIZONTAL);
            try writer.writeAll(mid);
            for (0..REGION_W) |_| try writer.writeAll(constants.HORIZONTAL);
            switch (mode) {
                .wide => {
                    try writer.writeAll(mid);
                    for (0..ACCOUNT_W) |_| try writer.writeAll(constants.HORIZONTAL);
                    try writer.writeAll(mid);
                    for (0..CREATED_W) |_| try writer.writeAll(constants.HORIZONTAL);
                    try writer.writeAll(mid);
                    for (0..SIZE_W) |_| try writer.writeAll(constants.HORIZONTAL);
                },
                .medium => {
                    try writer.writeAll(mid);
                    for (0..CREATED_W) |_| try writer.writeAll(constants.HORIZONTAL);
                },
                .compact => {},
            }
            try writer.writeAll(right);
            try writer.writeAll(terminal.RESET);
        }

        fn writeHeaderCell(self: *Self, writer: *std.Io.Writer, text: []const u8, cell_w: usize) !void {
            const content_w = if (cell_w >= 2) cell_w - 2 else 0;
            const text_len = @min(text.len, content_w);
            const pad = if (content_w > text_len) content_w - text_len else 0;
            const left = pad / 2;
            const right = pad - left;
            try writer.writeByte(' ');
            try writer.writeAll(self.bg_color);
            try writer.writeAll(terminal.FG_BLACK);
            for (0..left) |_| try writer.writeByte(' ');
            try writer.writeAll(text[0..text_len]);
            for (0..right) |_| try writer.writeByte(' ');
            try writer.writeAll(terminal.RESET);
            try writer.writeByte(' ');
        }

        fn writeHeaderRow(self: *Self, writer: *std.Io.Writer, name_w: usize, mode: Mode) !void {
            try writer.writeAll(self.fg_color);
            try writer.writeAll(constants.VERTICAL);
            try writer.writeAll(terminal.RESET);
            try self.writeHeaderCell(writer, "NAME", name_w);
            try writer.writeAll(self.fg_color);
            try writer.writeAll(constants.VERTICAL);
            try writer.writeAll(terminal.RESET);
            try self.writeHeaderCell(writer, "REGION", REGION_W);
            switch (mode) {
                .wide => {
                    try writer.writeAll(self.fg_color);
                    try writer.writeAll(constants.VERTICAL);
                    try writer.writeAll(terminal.RESET);
                    try self.writeHeaderCell(writer, "ACCOUNT", ACCOUNT_W);
                    try writer.writeAll(self.fg_color);
                    try writer.writeAll(constants.VERTICAL);
                    try writer.writeAll(terminal.RESET);
                    try self.writeHeaderCell(writer, "CREATED", CREATED_W);
                    try writer.writeAll(self.fg_color);
                    try writer.writeAll(constants.VERTICAL);
                    try writer.writeAll(terminal.RESET);
                    try self.writeHeaderCell(writer, "SIZE", SIZE_W);
                },
                .medium => {
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

        fn writeBucketRow(self: *Self, writer: *std.Io.Writer, b: S3.Bucket, sel: bool, name_w: usize, mode: Mode) !void {
            try self.writeVert(writer, sel, !sel);

            const content_w = if (name_w >= 2) name_w - 2 else 0;
            const max_name = if (content_w >= 2) content_w - 2 else 0;
            try writer.writeByte(' ');
            try writer.writeAll(if (sel) "▸ " else "  ");
            const shown = if (b.name.len > max_name) b.name[0..max_name] else b.name;
            try writer.writeAll(shown);
            for (shown.len..max_name) |_| try writer.writeByte(' ');
            try writer.writeByte(' ');

            try self.writeVert(writer, sel, !sel);
            try writePaddedCell(writer, b.region, REGION_W);

            switch (mode) {
                .wide => {
                    try self.writeVert(writer, sel, !sel);
                    const account_str: []const u8 = if (self.multi_source) blk: {
                        for (self.sources) |si| {
                            if (std.mem.eql(u8, si.profile_name, b.profile_name)) {
                                break :blk if (si.account_id.len > 0) si.account_id else b.profile_name;
                            }
                        }
                        break :blk b.profile_name;
                    } else if (self.account_len > 0)
                        self.account_buf[0..self.account_len]
                    else
                        "-";
                    try writePaddedCell(writer, account_str, ACCOUNT_W);
                    try self.writeVert(writer, sel, !sel);
                    try writeDateCell(writer, b.creation_date);
                    try self.writeVert(writer, sel, !sel);
                    var size_buf: [16]u8 = undefined;
                    const size_str: []const u8 = blk: {
                        if (self.size_ctx) |sc| {
                            if (sc.done.load(.acquire)) {
                                if (sc.sizes.get(b.name)) |bytes| {
                                    break :blk format_mod.size(&size_buf, bytes);
                                }
                            }
                        }
                        break :blk "-";
                    };
                    try writePaddedCell(writer, size_str, SIZE_W);
                },
                .medium => {
                    try self.writeVert(writer, sel, !sel);
                    try writeDateCell(writer, b.creation_date);
                },
                .compact => {},
            }

            try self.writeVert(writer, sel, true);
        }

        fn writeEmptyRow(self: *Self, writer: *std.Io.Writer, name_w: usize, mode: Mode) !void {
            try self.writeVert(writer, false, true);
            for (0..name_w) |_| try writer.writeByte(' ');
            try self.writeVert(writer, false, true);
            for (0..REGION_W) |_| try writer.writeByte(' ');
            switch (mode) {
                .wide => {
                    try self.writeVert(writer, false, true);
                    for (0..ACCOUNT_W) |_| try writer.writeByte(' ');
                    try self.writeVert(writer, false, true);
                    for (0..CREATED_W) |_| try writer.writeByte(' ');
                    try self.writeVert(writer, false, true);
                    for (0..SIZE_W) |_| try writer.writeByte(' ');
                },
                .medium => {
                    try self.writeVert(writer, false, true);
                    for (0..CREATED_W) |_| try writer.writeByte(' ');
                },
                .compact => {},
            }
            try self.writeVert(writer, false, true);
        }

        fn spawnRegionFetch(self: *Self, items: []const S3.Bucket) void {
            if (self.region_ctx != null) return;
            const alloc = self.alloc;
            const ctx = alloc.create(RegionCtx) catch return;
            const bucket_names = alloc.alloc([]u8, items.len) catch {
                alloc.destroy(ctx);
                return;
            };
            const creds_per_bucket = alloc.alloc(Credentials, items.len) catch {
                alloc.free(bucket_names);
                alloc.destroy(ctx);
                return;
            };
            var n_copied: usize = 0;
            for (items, 0..) |b, i| {
                var creds = self.sources[0].credentials;
                for (self.sources) |si| {
                    if (std.mem.eql(u8, si.profile_name, b.profile_name)) {
                        creds = si.credentials;
                        break;
                    }
                }
                creds_per_bucket[i] = creds;
                bucket_names[i] = alloc.dupe(u8, b.name) catch {
                    for (bucket_names[0..n_copied]) |bn| alloc.free(bn);
                    alloc.free(bucket_names);
                    alloc.free(creds_per_bucket);
                    alloc.destroy(ctx);
                    return;
                };
                n_copied += 1;
            }
            ctx.* = .{
                .allocator = alloc,
                .io = self.io,
                .creds_per_bucket = creds_per_bucket,
                .load_ctx = switch (self.state) {
                    .active => |lctx| lctx,
                    .failed => {
                        for (bucket_names) |bn| alloc.free(bn);
                        alloc.free(bucket_names);
                        alloc.free(creds_per_bucket);
                        alloc.destroy(ctx);
                        return;
                    },
                },
                .bucket_names = bucket_names,
                .thread = undefined,
                .fetched_count = std.atomic.Value(usize).init(0),
                .done = std.atomic.Value(bool).init(false),
            };
            ctx.thread = std.Thread.spawn(.{}, regionFetchThread, .{ctx}) catch {
                for (bucket_names) |bn| alloc.free(bn);
                alloc.free(bucket_names);
                alloc.free(creds_per_bucket);
                alloc.destroy(ctx);
                return;
            };
            self.region_ctx = ctx;
        }

        fn spawnSizeFetch(self: *Self, items: []const S3.Bucket) void {
            if (self.size_ctx != null) return;

            const alloc = self.alloc;
            const ctx = alloc.create(SizeCtx) catch return;

            const region = alloc.dupe(u8, self.region_buf[0..self.region_len]) catch {
                alloc.destroy(ctx);
                return;
            };

            const bucket_names = alloc.alloc([]u8, items.len) catch {
                alloc.free(region);
                alloc.destroy(ctx);
                return;
            };
            const creds_per_bucket = alloc.alloc(Credentials, items.len) catch {
                alloc.free(bucket_names);
                alloc.free(region);
                alloc.destroy(ctx);
                return;
            };
            var n_copied: usize = 0;
            for (items, 0..) |b, i| {
                var creds = self.sources[0].credentials;
                for (self.sources) |si| {
                    if (std.mem.eql(u8, si.profile_name, b.profile_name)) {
                        creds = si.credentials;
                        break;
                    }
                }
                creds_per_bucket[i] = creds;
                bucket_names[i] = alloc.dupe(u8, b.name) catch {
                    for (bucket_names[0..n_copied]) |bn| alloc.free(bn);
                    alloc.free(bucket_names);
                    alloc.free(creds_per_bucket);
                    alloc.free(region);
                    alloc.destroy(ctx);
                    return;
                };
                n_copied += 1;
            }

            ctx.* = .{
                .allocator = alloc,
                .io = self.io,
                .creds_per_bucket = creds_per_bucket,
                .region = region,
                .bucket_names = bucket_names,
                .thread = undefined,
                .sizes = std.StringHashMap(u64).init(alloc),
                .done = std.atomic.Value(bool).init(false),
            };

            ctx.thread = std.Thread.spawn(.{}, sizeFetchThread, .{ctx}) catch {
                for (bucket_names) |bn| alloc.free(bn);
                alloc.free(bucket_names);
                alloc.free(creds_per_bucket);
                alloc.free(region);
                ctx.sizes.deinit();
                alloc.destroy(ctx);
                return;
            };

            self.size_ctx = ctx;
        }

        pub fn render(self: *Self, writer: *std.Io.Writer, size: Coord) !void {
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
                        const n_items = ctx.items.items.len;
                        ctx.mutex.unlock();
                        var all_errored = true;
                        var first_err: ?anyerror = null;
                        for (ctx.sources) |src| {
                            if (src.err) |e| {
                                if (first_err == null) first_err = e;
                            } else {
                                all_errored = false;
                            }
                        }
                        if (all_errored and n_items == 0) {
                            for (ctx.sources) |src| {
                                if (src.err) |e| {
                                    std.log.err("ListBuckets: all sources failed profile={s} err={}", .{ src.profile_name, e });
                                } else {
                                    std.log.err("ListBuckets: source marked failed but no error set profile={s}", .{src.profile_name});
                                }
                            }
                            for (ctx.sources) |src| {
                                src.allocator.free(src.region);
                                src.allocator.destroy(src);
                            }
                            ctx.allocator.free(ctx.sources);
                            for (ctx.items.items) |b| b.deinit();
                            ctx.items.deinit(ctx.allocator);
                            ctx.allocator.destroy(ctx);
                            self.state = .{ .failed = first_err orelse error.UnknownAwsError };
                        } else if (n_items > 0) {
                            lockMutex(&ctx.mutex);
                            if (self.size_ctx == null) self.spawnSizeFetch(ctx.items.items);
                            if (self.region_ctx == null) self.spawnRegionFetch(ctx.items.items);
                            ctx.mutex.unlock();
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
                    const render_sizes: ?*const std.StringHashMap(u64) =
                        if (self.size_ctx) |sc| if (sc.done.load(.acquire)) &sc.sizes else null else null;
                    const vis_total = self.visibleCount(items, filter, render_sizes);

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
                        const b = items[orig_idx];
                        if (!self.matchesBucket(b, filter, render_sizes)) continue;
                        if (vis_idx >= self.scroll_offset and rendered < data_rows) {
                            try self.writeBucketRow(writer, b, vis_idx == self.selected, name_w, mode);
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
                            const msg = std.fmt.bufPrint(&buf, " Error: {s}", .{@errorName(e)}) catch " Error loading buckets";
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
    };
}

pub const S3BucketsView = S3BucketsViewGeneric(fetchSourceThread);

// ============================================================================
// Tests
// ============================================================================

fn makeTestBucket(allocator: std.mem.Allocator, bname: []const u8, region: []const u8, creation_date: []const u8) !S3.Bucket {
    return .{
        .allocator = allocator,
        .name = try allocator.dupe(u8, bname),
        .region = try allocator.dupe(u8, region),
        .creation_date = try allocator.dupe(u8, creation_date),
    };
}

test "compareField name ordering" {
    const alloc = std.testing.allocator;
    var a = try makeTestBucket(alloc, "aaa", "us-east-1", "2024-01-01");
    defer a.deinit();
    var b = try makeTestBucket(alloc, "bbb", "us-east-1", "2024-01-01");
    defer b.deinit();
    try std.testing.expectEqual(std.math.Order.lt, compareField(a, b, .name, null, null));
    try std.testing.expectEqual(std.math.Order.gt, compareField(b, a, .name, null, null));
    try std.testing.expectEqual(std.math.Order.eq, compareField(a, a, .name, null, null));
}

test "compareField region ordering" {
    const alloc = std.testing.allocator;
    var a = try makeTestBucket(alloc, "bucket", "ap-southeast-1", "2024-01-01");
    defer a.deinit();
    var b = try makeTestBucket(alloc, "bucket", "us-east-1", "2024-01-01");
    defer b.deinit();
    try std.testing.expectEqual(std.math.Order.lt, compareField(a, b, .region, null, null));
}

test "compareField size null sizes treated as unknown" {
    const alloc = std.testing.allocator;
    var a = try makeTestBucket(alloc, "a", "us-east-1", "2024-01-01");
    defer a.deinit();
    var b = try makeTestBucket(alloc, "b", "us-east-1", "2024-01-01");
    defer b.deinit();
    // both unknown → equal
    try std.testing.expectEqual(std.math.Order.eq, compareField(a, b, .size, null, null));
}

test "matchesTextFilter basic" {
    try std.testing.expect(filter_mod.matchesText("my-bucket", "bucket"));
    try std.testing.expect(filter_mod.matchesText("my-bucket", "my"));
    try std.testing.expect(!filter_mod.matchesText("my-bucket", "xyz"));
}

test "matchesTextFilter empty filter matches all" {
    try std.testing.expect(filter_mod.matchesText("anything", ""));
    try std.testing.expect(filter_mod.matchesText("", ""));
}

test "matchesTextFilter case insensitive" {
    try std.testing.expect(filter_mod.matchesText("My-Bucket", "bucket"));
    try std.testing.expect(filter_mod.matchesText("MY-BUCKET", "my-bucket"));
}

test "formatBytes bytes" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("512 B", format_mod.size(&buf, 512));
}

test "formatBytes kilobytes" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("1.5 KB", format_mod.size(&buf, 1536));
}

test "formatBytes megabytes" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("2.0 MB", format_mod.size(&buf, 2 * 1024 * 1024));
}
