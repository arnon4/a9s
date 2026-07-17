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
const S3ObjectView = @import("object.zig").S3ObjectView;
const constants = @import("../../../ui/constants.zig");
const mime_mod = @import("../../../sdk/clients/s3/mime.zig");
const ConfirmView = @import("../../../ui/confirm.zig");
const filter_mod = @import("../../../commands/filter.zig");

pub const ObjectSortKey = enum { key, size, last_modified, storage_class };

const ObjectSortCtx = struct {
    items: []const S3.S3Object,
    keys: []const ObjectSortKey,
    dir: constants.SortDir,

    fn lessThan(ctx: @This(), a: usize, b: usize) bool {
        for (ctx.keys) |key| {
            const ord = compareObjectField(ctx.items[a], ctx.items[b], key);
            if (ord != .eq) return if (ctx.dir == .asc) ord == .lt else ord == .gt;
        }
        return false;
    }
};

pub fn compareObjectField(a: S3.S3Object, b: S3.S3Object, key: ObjectSortKey) std.math.Order {
    return switch (key) {
        .key => std.mem.order(u8, a.key, b.key),
        .size => std.math.order(a.size, b.size),
        .last_modified => std.mem.order(u8, a.last_modified, b.last_modified),
        .storage_class => std.mem.order(u8, @tagName(a.storage_class), @tagName(b.storage_class)),
    };
}

const SIZE_W: usize = 10;
const MODIFIED_W: usize = 12;
const CLASS_W: usize = 22;
const MIME_W: usize = 22;

const Mode = enum {
    wide,
    medium,
    compact,
};

const HeadTaskArgs = struct {
    allocator: std.mem.Allocator,
    credentials: Credentials,
    region: []const u8,
    endpoint: []const u8,
    virtual_hosted: bool,
    bucket: []const u8,
    key: []const u8,
    out: *?[]u8,
};

fn headTask(io: std.Io, args: *HeadTaskArgs) error{Canceled}!void {
    const result = S3.headObjectWithIo(
        args.allocator,
        io,
        args.virtual_hosted,
        args.endpoint,
        args.region,
        args.credentials,
        .{ .bucket = args.bucket, .key = args.key },
    ) catch |e| {
        if (e == error.Canceled) return error.Canceled;
        std.log.err("HeadObject: failed bucket={s} key={s} err={}", .{ args.bucket, args.key, e });
        return;
    };
    args.out.* = result.content_type;
    if (result.server_side_encryption) |s| args.allocator.free(s);
    if (result.object_lock_mode) |s| args.allocator.free(s);
    if (result.object_lock_legal_hold) |s| args.allocator.free(s);
    if (result.checksum_value) |s| args.allocator.free(s);
}

pub const LoadCtx = struct {
    client: S3.Client,
    thread: std.Thread,
    bucket: []const u8,
    mutex: std.atomic.Mutex = .unlocked,
    items: std.ArrayList(S3.S3Object) = .empty,
    mime_types: ?[]?[]u8 = null,
    err: ?anyerror = null,
    done: std.atomic.Value(bool),
    head_done: std.atomic.Value(bool),
};

const State = union(enum) {
    active: *LoadCtx,
    failed: anyerror,
};

fn lockMutex(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

fn headAll(ctx: *LoadCtx) void {
    const alloc = ctx.client.allocator;
    const n = ctx.items.items.len;
    if (n == 0) return;

    const mt = alloc.alloc(?[]u8, n) catch return;
    @memset(mt, null);
    ctx.mime_types = mt;

    const tasks = alloc.alloc(HeadTaskArgs, n) catch return;
    defer alloc.free(tasks);

    for (ctx.items.items, 0..) |obj, i| {
        tasks[i] = .{
            .allocator = alloc,
            .credentials = ctx.client.credentials,
            .region = ctx.client.region,
            .endpoint = ctx.client.endpoint,
            .virtual_hosted = ctx.client.virtual_hosted,
            .bucket = ctx.bucket,
            .key = obj.key,
            .out = &mt[i],
        };
    }

    var group: std.Io.Group = .{
        .token = std.atomic.Value(?*anyopaque).init(null),
        .state = 0,
    };
    for (tasks) |*t| {
        group.async(ctx.client.io, headTask, .{ ctx.client.io, t });
    }
    group.await(ctx.client.io) catch {};
}

fn fetchThread(ctx: *LoadCtx) void {
    defer {
        ctx.done.store(true, .release);
        input.notify();
    }
    const alloc = ctx.client.allocator;
    var next_token: ?[]u8 = null;
    defer if (next_token) |t| alloc.free(t);

    while (true) {
        const result = ctx.client.listObjects(.{
            .bucket = ctx.bucket,
            .query_params = .{ .continuation_token = next_token, .fetch_owner = true },
        }) catch |e| {
            std.log.err("ListObjects: request failed bucket={s} err={}", .{ ctx.bucket, e });
            lockMutex(&ctx.mutex);
            ctx.err = e;
            ctx.mutex.unlock();
            return;
        };
        defer result.deinit();

        if (next_token) |t| alloc.free(t);
        next_token = if (result.next_continuation_token) |t|
            alloc.dupe(u8, t) catch |e| {
                lockMutex(&ctx.mutex);
                ctx.err = e;
                ctx.mutex.unlock();
                return;
            }
        else
            null;

        const is_last = !result.is_truncated;

        lockMutex(&ctx.mutex);
        outer: for (result.objects) |obj| {
            const cloned = obj.clone(alloc) catch |e| {
                ctx.err = e;
                break :outer;
            };
            ctx.items.append(alloc, cloned) catch |e| {
                cloned.deinit();
                ctx.err = e;
                break :outer;
            };
        }
        const had_error = ctx.err != null;
        ctx.mutex.unlock();

        if (had_error or is_last) break;
    }

    {
        lockMutex(&ctx.mutex);
        const had_error = ctx.err != null;
        ctx.mutex.unlock();
        if (had_error) return;
    }

    headAll(ctx);
    ctx.head_done.store(true, .release);
    input.notify();
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
    try writePaddedCell(writer, date, MODIFIED_W);
}

fn writeSizeCell(writer: *std.Io.Writer, bytes: u64) !void {
    var buf: [16]u8 = undefined;
    try writePaddedCell(writer, format_mod.size(&buf, bytes), SIZE_W);
}

fn modeFor(width: i16) Mode {
    if (width >= @intFromEnum(constants.Size.wide)) return .wide;
    if (width >= @intFromEnum(constants.Size.medium)) return .medium;
    return .compact;
}

fn nameWidth(inner: usize, mode: Mode) usize {
    const fixed: usize = switch (mode) {
        .wide => SIZE_W + MODIFIED_W + CLASS_W + MIME_W + 4,
        .medium => SIZE_W + MODIFIED_W + 2,
        .compact => SIZE_W + 1,
    };
    return if (inner > fixed + 2) inner - fixed else 2;
}

fn freeCtx(ctx: *LoadCtx) void {
    const alloc = ctx.client.allocator;
    ctx.thread.join();
    for (ctx.items.items) |obj| obj.deinit();
    ctx.items.deinit(alloc);
    if (ctx.mime_types) |mt| {
        for (mt) |m| if (m) |s| alloc.free(s);
        alloc.free(mt);
    }
    ctx.client.deinit();
    alloc.destroy(ctx);
}

pub fn S3ObjectsViewGeneric(comptime fetchFn: fn (*LoadCtx) void) type {
    return struct {
        const Self = @This();
        pub const name: []const u8 = "S3 Objects";

        fg_color: []const u8,
        bg_color: []const u8,
        state: State,
        selected: usize = 0,
        scroll_offset: usize = 0,
        pending_g: bool = false,
        breadcrumb_buf: [256]u8 = undefined,
        breadcrumb_len: usize = 0,
        alloc: std.mem.Allocator,
        io: std.Io,
        credentials: Credentials,
        bucket_buf: [512]u8,
        bucket_len: usize,
        region_buf: [64]u8,
        region_len: usize,
        committed_filter: ?[]u8 = null,
        live_filter: []const u8 = "",
        filter_expr: ?filter_mod.ParseResult = null,
        sort_keys: [4]ObjectSortKey = .{ .key, undefined, undefined, undefined },
        sort_keys_len: usize = 1,
        sort_dir: constants.SortDir = .asc,
        sorted_indices: []usize = &.{},
        last_sorted_len: usize = 0,
        sort_dirty: bool = false,
        sort_applied: bool = false,

        fn recomputeSort(self: *Self, items: []const S3.S3Object) void {
            if (self.sorted_indices.len > 0) {
                self.alloc.free(self.sorted_indices);
                self.sorted_indices = &.{};
            }
            const indices = self.alloc.alloc(usize, items.len) catch return;
            for (indices, 0..) |*idx, i| idx.* = i;
            std.mem.sortUnstable(usize, indices, ObjectSortCtx{
                .items = items,
                .keys = self.sort_keys[0..self.sort_keys_len],
                .dir = self.sort_dir,
            }, ObjectSortCtx.lessThan);
            self.sorted_indices = indices;
            self.last_sorted_len = items.len;
        }

        fn ensureSorted(self: *Self, items: []const S3.S3Object) void {
            if (!self.sort_dirty and self.sorted_indices.len == items.len) return;
            self.recomputeSort(items);
            self.sort_dirty = false;
        }

        pub fn setSort(self: *Self, keys: []const ObjectSortKey, dir: constants.SortDir) void {
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
            self.sort_keys[0] = .key;
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

        fn effectiveFilter(self: *const Self) []const u8 {
            if (self.live_filter.len > 0) return self.live_filter;
            return self.committed_filter orelse "";
        }

        const ObjectResolver = struct {
            obj: S3.S3Object,

            pub fn resolve(self: ObjectResolver, field: []const u8) filter_mod.FieldValue {
                if (std.mem.eql(u8, field, "key") or std.mem.eql(u8, field, "name"))
                    return .{ .string = self.obj.key };
                if (std.mem.eql(u8, field, "size")) return .{ .bytes = self.obj.size };
                if (std.mem.eql(u8, field, "modified") or std.mem.eql(u8, field, "last_modified"))
                    return .{ .string = self.obj.last_modified };
                if (std.mem.eql(u8, field, "class") or std.mem.eql(u8, field, "storage_class"))
                    return .{ .string = @tagName(self.obj.storage_class) };
                return .unknown;
            }
        };

        fn matchesObject(self: *const Self, obj: S3.S3Object, text_f: []const u8) bool {
            if (!filter_mod.matchesText(obj.key, text_f)) return false;
            if (self.filter_expr) |*fe| {
                if (!filter_mod.evalExpr(fe.expr, ObjectResolver{ .obj = obj })) return false;
            }
            return true;
        }

        fn visibleCount(self: *const Self, items: []const S3.S3Object, text_f: []const u8) usize {
            var n: usize = 0;
            for (items) |obj| {
                if (self.matchesObject(obj, text_f)) n += 1;
            }
            return n;
        }

        pub fn init(
            allocator: std.mem.Allocator,
            io: std.Io,
            credentials: Credentials,
            region: []const u8,
            bucket: []const u8,
            color_support: terminal.ColorSupport,
        ) !Self {
            const colors = colors_mod.green(color_support);
            const fg_color = colors.fg;
            const bg_color = colors.bg;

            const ctx = try allocator.create(LoadCtx);
            errdefer allocator.destroy(ctx);

            ctx.* = .{
                .client = try S3.Client.init(allocator, .{
                    .region = region,
                    .io = io,
                    .credentials = credentials,
                }),
                .thread = undefined,
                .bucket = bucket,
                .done = std.atomic.Value(bool).init(false),
                .head_done = std.atomic.Value(bool).init(false),
            };
            errdefer ctx.client.deinit();

            ctx.thread = try std.Thread.spawn(.{}, fetchFn, .{ctx});
            errdefer ctx.thread.join();

            var bc_buf: [256]u8 = undefined;
            const bc = std.fmt.bufPrint(&bc_buf, "Buckets {s} {s}", .{ constants.SEP_ARROW, bucket }) catch bc_buf[0..0];

            var view = Self{
                .fg_color = fg_color,
                .bg_color = bg_color,
                .state = .{ .active = ctx },
                .breadcrumb_buf = bc_buf,
                .breadcrumb_len = bc.len,
                .alloc = allocator,
                .io = io,
                .credentials = credentials,
                .bucket_buf = undefined,
                .bucket_len = 0,
                .region_buf = undefined,
                .region_len = 0,
            };

            const blen = @min(bucket.len, view.bucket_buf.len);
            @memcpy(view.bucket_buf[0..blen], bucket[0..blen]);
            view.bucket_len = blen;

            const rlen = @min(region.len, view.region_buf.len);
            @memcpy(view.region_buf[0..rlen], region[0..rlen]);
            view.region_len = rlen;

            return view;
        }

        pub fn breadcrumb(self: *Self) []const u8 {
            return self.breadcrumb_buf[0..self.breadcrumb_len];
        }

        pub fn deinit(self: *Self) void {
            if (self.committed_filter) |f| self.alloc.free(f);
            if (self.filter_expr) |*fe| fe.deinit();
            if (self.sorted_indices.len > 0) self.alloc.free(self.sorted_indices);
            switch (self.state) {
                .active => |ctx| freeCtx(ctx),
                .failed => {},
            }
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
            self.sort_dirty = true;
            self.sort_applied = false;
            switch (self.state) {
                .active => |ctx| {
                    if (!ctx.done.load(.acquire)) return;
                    freeCtx(ctx);
                },
                .failed => {},
            }
            const alloc = self.alloc;
            const new_ctx = try alloc.create(LoadCtx);
            errdefer alloc.destroy(new_ctx);
            new_ctx.* = .{
                .client = try S3.Client.init(alloc, .{
                    .region = self.region_buf[0..self.region_len],
                    .io = self.io,
                    .credentials = self.credentials,
                }),
                .thread = undefined,
                .bucket = self.bucket_buf[0..self.bucket_len],
                .done = std.atomic.Value(bool).init(false),
                .head_done = std.atomic.Value(bool).init(false),
            };
            errdefer new_ctx.client.deinit();
            new_ctx.thread = try std.Thread.spawn(.{}, fetchFn, .{new_ctx});
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
                    break :blk self.visibleCount(lctx.items.items, filter);
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
                            .active => |lctx| {
                                lockMutex(&lctx.mutex);
                                const enter_items = lctx.items.items;
                                self.ensureSorted(enter_items);
                                var vis: usize = 0;
                                var found_idx: ?usize = null;
                                for (self.sorted_indices) |orig_idx_| {
                                    const obj = enter_items[orig_idx_];
                                    if (!self.matchesObject(obj, filter)) continue;
                                    if (vis == self.selected) {
                                        found_idx = orig_idx_;
                                        break;
                                    }
                                    vis += 1;
                                }
                                const orig_idx = found_idx orelse {
                                    lctx.mutex.unlock();
                                    return .none;
                                };
                                const obj_cloned = lctx.items.items[orig_idx].clone(ctx.allocator) catch {
                                    lctx.mutex.unlock();
                                    return .none;
                                };
                                const mime_from_head: ?[]const u8 = if (lctx.head_done.load(.acquire))
                                    if (lctx.mime_types) |mt| (if (orig_idx < mt.len) mt[orig_idx] else null) else null
                                else
                                    null;
                                const obj_key = lctx.items.items[orig_idx].key;
                                const mime: ?[]const u8 = mime_mod.fromExtension(obj_key) orelse
                                    if (mime_from_head) |m| (if (m.len > 0) m else null) else null;
                                const bucket = lctx.bucket;
                                const endpoint = lctx.client.endpoint;
                                const virtual_hosted = lctx.client.virtual_hosted;
                                const region = lctx.client.region;
                                const creds = lctx.client.credentials;
                                lctx.mutex.unlock();
                                defer obj_cloned.deinit();

                                if (self.committed_filter) |f| self.alloc.free(f);
                                self.committed_filter = null;
                                self.live_filter = "";
                                self.clearSort();

                                const v = try S3ObjectView.init(
                                    ctx.allocator,
                                    ctx.io,
                                    creds,
                                    endpoint,
                                    virtual_hosted,
                                    bucket,
                                    region,
                                    obj_cloned,
                                    mime,
                                    ctx.color_support,
                                );
                                return .{ .push = .{ .s3_object = v } };
                            },
                            .failed => return .none,
                        }
                    },
                    .escape => {
                        if (self.committed_filter != null) {
                            if (self.committed_filter) |f| self.alloc.free(f);
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
            for (0..SIZE_W) |_| try writer.writeAll(constants.HORIZONTAL);
            switch (mode) {
                .wide => {
                    try writer.writeAll(mid);
                    for (0..MODIFIED_W) |_| try writer.writeAll(constants.HORIZONTAL);
                    try writer.writeAll(mid);
                    for (0..CLASS_W) |_| try writer.writeAll(constants.HORIZONTAL);
                    try writer.writeAll(mid);
                    for (0..MIME_W) |_| try writer.writeAll(constants.HORIZONTAL);
                },
                .medium => {
                    try writer.writeAll(mid);
                    for (0..MODIFIED_W) |_| try writer.writeAll(constants.HORIZONTAL);
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
            try self.writeHeaderCell(writer, "KEY", name_w);
            try writer.writeAll(self.fg_color);
            try writer.writeAll(constants.VERTICAL);
            try writer.writeAll(terminal.RESET);
            try self.writeHeaderCell(writer, "SIZE", SIZE_W);
            switch (mode) {
                .wide => {
                    try writer.writeAll(self.fg_color);
                    try writer.writeAll(constants.VERTICAL);
                    try writer.writeAll(terminal.RESET);
                    try self.writeHeaderCell(writer, "MODIFIED", MODIFIED_W);
                    try writer.writeAll(self.fg_color);
                    try writer.writeAll(constants.VERTICAL);
                    try writer.writeAll(terminal.RESET);
                    try self.writeHeaderCell(writer, "CLASS", CLASS_W);
                    try writer.writeAll(self.fg_color);
                    try writer.writeAll(constants.VERTICAL);
                    try writer.writeAll(terminal.RESET);
                    try self.writeHeaderCell(writer, "MIME TYPE", MIME_W);
                },
                .medium => {
                    try writer.writeAll(self.fg_color);
                    try writer.writeAll(constants.VERTICAL);
                    try writer.writeAll(terminal.RESET);
                    try self.writeHeaderCell(writer, "MODIFIED", MODIFIED_W);
                },
                .compact => {},
            }
            try writer.writeAll(self.fg_color);
            try writer.writeAll(constants.VERTICAL);
            try writer.writeAll(terminal.RESET);
        }

        fn writeObjectRow(self: *Self, writer: *std.Io.Writer, obj: S3.S3Object, mime: ?[]const u8, sel: bool, name_w: usize, mode: Mode) !void {
            try self.writeVert(writer, sel, !sel);

            const content_w = if (name_w >= 2) name_w - 2 else 0;
            const max_key = if (content_w >= 2) content_w - 2 else 0;
            try writer.writeByte(' ');
            try writer.writeAll(if (sel) "▸ " else "  ");
            const shown = if (obj.key.len > max_key) obj.key[0..max_key] else obj.key;
            try writer.writeAll(shown);
            for (shown.len..max_key) |_| try writer.writeByte(' ');
            try writer.writeByte(' ');

            try self.writeVert(writer, sel, !sel);
            try writeSizeCell(writer, obj.size);

            switch (mode) {
                .wide => {
                    try self.writeVert(writer, sel, !sel);
                    try writeDateCell(writer, obj.last_modified);
                    try self.writeVert(writer, sel, !sel);
                    try writePaddedCell(writer, @tagName(obj.storage_class), CLASS_W);
                    try self.writeVert(writer, sel, !sel);
                    try writePaddedCell(writer, mime orelse "-", MIME_W);
                },
                .medium => {
                    try self.writeVert(writer, sel, !sel);
                    try writeDateCell(writer, obj.last_modified);
                },
                .compact => {},
            }

            try self.writeVert(writer, sel, true);
        }

        fn writeEmptyRow(self: *Self, writer: *std.Io.Writer, name_w: usize, mode: Mode) !void {
            try self.writeVert(writer, false, true);
            for (0..name_w) |_| try writer.writeByte(' ');
            try self.writeVert(writer, false, true);
            for (0..SIZE_W) |_| try writer.writeByte(' ');
            switch (mode) {
                .wide => {
                    try self.writeVert(writer, false, true);
                    for (0..MODIFIED_W) |_| try writer.writeByte(' ');
                    try self.writeVert(writer, false, true);
                    for (0..CLASS_W) |_| try writer.writeByte(' ');
                    try self.writeVert(writer, false, true);
                    for (0..MIME_W) |_| try writer.writeByte(' ');
                },
                .medium => {
                    try self.writeVert(writer, false, true);
                    for (0..MODIFIED_W) |_| try writer.writeByte(' ');
                },
                .compact => {},
            }
            try self.writeVert(writer, false, true);
        }

        pub fn render(self: *Self, writer: *std.Io.Writer, size: Coord) !void {
            if (size.x < 10 or size.y < 4) return;
            const h: usize = @intCast(size.y);
            const inner = @as(usize, @intCast(size.x)) - 2;
            const mode = modeFor(size.x);
            const name_w = nameWidth(inner, mode);
            const show_header = h >= 6;
            const data_rows = if (show_header) h - 3 else h - 1;

            switch (self.state) {
                .active => |ctx| {
                    if (ctx.done.load(.acquire)) {
                        lockMutex(&ctx.mutex);
                        const err = ctx.err;
                        ctx.mutex.unlock();
                        if (err) |e| {
                            std.log.err("ListObjects: load failed bucket={s} err={}", .{ ctx.bucket, e });
                            freeCtx(ctx);
                            self.state = .{ .failed = e };
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

                    const head_ready = ctx.head_done.load(.acquire);
                    self.ensureSorted(items);
                    var vis_idx: usize = 0;
                    var rendered: usize = 0;
                    for (self.sorted_indices) |orig_idx| {
                        const obj = items[orig_idx];
                        if (!self.matchesObject(obj, filter)) continue;
                        if (vis_idx >= self.scroll_offset and rendered < data_rows) {
                            const mime_from_head: ?[]const u8 = if (head_ready)
                                if (ctx.mime_types) |mt| (if (orig_idx < mt.len) mt[orig_idx] else null) else null
                            else
                                null;
                            const mime: ?[]const u8 = mime_mod.fromExtension(obj.key) orelse
                                if (mime_from_head) |m| (if (m.len > 0) m else null) else null;
                            try self.writeObjectRow(writer, obj, mime, vis_idx == self.selected, name_w, mode);
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
                            const msg = std.fmt.bufPrint(&buf, " Error: {s}", .{@errorName(e)}) catch " Error loading objects";
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

pub const S3ObjectsView = S3ObjectsViewGeneric(fetchThread);

// ============================================================================
// Tests
// ============================================================================

fn makeTestObject(allocator: std.mem.Allocator, key: []const u8, size: u64) !S3.S3Object {
    return S3.S3Object{
        .allocator = allocator,
        .key = try allocator.dupe(u8, key),
        .last_modified = try allocator.dupe(u8, ""),
        .etag = try allocator.dupe(u8, ""),
        .size = size,
        .storage_class = .STANDARD,
        .checksum_algorithm = null,
        .checksum_type = null,
        .owner = null,
        .restore_status = null,
    };
}

test "compareObjectField key order" {
    const allocator = std.testing.allocator;
    var a = try makeTestObject(allocator, "aaa", 0);
    defer a.deinit();
    var b = try makeTestObject(allocator, "bbb", 0);
    defer b.deinit();
    try std.testing.expectEqual(std.math.Order.lt, compareObjectField(a, b, .key));
    try std.testing.expectEqual(std.math.Order.gt, compareObjectField(b, a, .key));
    try std.testing.expectEqual(std.math.Order.eq, compareObjectField(a, a, .key));
}

test "compareObjectField size order" {
    const allocator = std.testing.allocator;
    var small = try makeTestObject(allocator, "", 100);
    defer small.deinit();
    var large = try makeTestObject(allocator, "", 200);
    defer large.deinit();
    try std.testing.expectEqual(std.math.Order.lt, compareObjectField(small, large, .size));
}

test "matchesTextFilter basic" {
    try std.testing.expect(filter_mod.matchesText("hello-world.txt", "world"));
    try std.testing.expect(filter_mod.matchesText("hello-world.txt", "WORLD"));
    try std.testing.expect(!filter_mod.matchesText("hello-world.txt", "xyz"));
}

test "matchesTextFilter empty filter" {
    try std.testing.expect(filter_mod.matchesText("anything", ""));
}

test "formatSize bytes" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("512 B", format_mod.size(&buf, 512));
}

test "formatSize kilobytes" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("1.0 KB", format_mod.size(&buf, 1024));
}
