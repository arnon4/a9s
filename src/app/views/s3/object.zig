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
const props_mod = @import("../../../ui/props.zig");
const S3ObjectContentView = @import("object_content.zig").S3ObjectContentView;
const S3DownloadView = @import("download.zig");
const constants = @import("../../../ui/constants.zig");
const mime_mod = @import("../../../sdk/clients/s3/mime.zig");
const ConfirmView = @import("../../../ui/confirm.zig");

pub const HeadCtx = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    credentials: Credentials,
    endpoint: []u8,
    virtual_hosted: bool,
    region: []const u8,
    bucket: []const u8,
    key: []const u8,
    thread: std.Thread,
    content_type: ?[]u8 = null,
    sse: ?[]u8 = null,
    lock_mode: ?[]u8 = null,
    legal_hold: ?[]u8 = null,
    checksum_value: ?[]u8 = null,
    err: ?anyerror = null,
    done: std.atomic.Value(bool),
};

/// Fetches S3 object metadata via two sequential HeadObject calls.
///
/// The first call retrieves standard metadata (content-type, SSE, lock mode,
/// legal hold). The second adds `x-amz-checksum-mode: ENABLED` to retrieve
/// the full checksum value, which S3 only returns when explicitly requested.
/// Results are merged: the checksum value from call 2 overwrites call 1.
fn headThread(ctx: *HeadCtx) void {
    defer {
        ctx.done.store(true, .release);
        input.notify();
    }
    const result = S3.headObjectWithIo(
        ctx.allocator,
        ctx.io,
        ctx.virtual_hosted,
        ctx.endpoint,
        ctx.region,
        ctx.credentials,
        .{ .bucket = ctx.bucket, .key = ctx.key },
    ) catch |e| {
        std.log.err("S3 headObject {s}/{s}: {s}", .{ ctx.bucket, ctx.key, @errorName(e) });
        ctx.err = e;
        return;
    };
    ctx.content_type = result.content_type;
    ctx.sse = result.server_side_encryption;
    ctx.lock_mode = result.object_lock_mode;
    ctx.legal_hold = result.object_lock_legal_hold;
    ctx.checksum_value = result.checksum_value;

    const cresult = S3.headObjectWithIo(
        ctx.allocator,
        ctx.io,
        ctx.virtual_hosted,
        ctx.endpoint,
        ctx.region,
        ctx.credentials,
        .{ .bucket = ctx.bucket, .key = ctx.key, .checksum_mode = true },
    ) catch return;
    defer {
        ctx.allocator.free(cresult.content_type);
        if (cresult.server_side_encryption) |s| ctx.allocator.free(s);
        if (cresult.object_lock_mode) |s| ctx.allocator.free(s);
        if (cresult.object_lock_legal_hold) |s| ctx.allocator.free(s);
    }
    if (cresult.checksum_value) |cv| {
        if (ctx.checksum_value) |old| ctx.allocator.free(old);
        ctx.checksum_value = cv;
    }
}

pub fn isTextMimeType(ct: []const u8) bool {
    const base = if (std.mem.indexOfScalar(u8, ct, ';')) |i| ct[0..i] else ct;
    const trimmed = std.mem.trimEnd(u8, base, " ");
    if (std.mem.startsWith(u8, trimmed, "text/")) return true;
    const text_app = [_][]const u8{
        "application/json",
        "application/xml",
        "application/javascript",
        "application/x-javascript",
        "application/typescript",
        "application/x-ndjson",
        "application/yaml",
        "application/toml",
    };
    for (text_app) |t| {
        if (std.mem.eql(u8, trimmed, t)) return true;
    }
    return false;
}

pub fn S3ObjectViewGeneric(comptime headFn: fn (*HeadCtx) void) type {
    return struct {
        const Self = @This();
        pub const name: []const u8 = "S3 Object";

        fg_color: []const u8,
        bg_color: []const u8,
        scroll: usize = 0,
        action_idx: usize = 0,
        pending_g: bool = false,
        breadcrumb_buf: [256]u8 = undefined,
        breadcrumb_len: usize = 0,
        key: []u8,
        bucket: []u8,
        region: []u8,
        s3_uri: []u8,
        arn: []u8,
        object_url: []u8,
        etag: []u8,
        last_modified: []u8,
        owner_str: []u8,
        mime_type: ?[]u8,
        storage_class_str: []const u8,
        checksum_algo_str: []const u8,
        checksum_type_str: []const u8,
        size: u64,
        head_ctx: *HeadCtx,
        io: std.Io,

        pub fn init(
            allocator: std.mem.Allocator,
            io: std.Io,
            credentials: Credentials,
            endpoint: []const u8,
            virtual_hosted: bool,
            bucket: []const u8,
            region: []const u8,
            obj: S3.S3Object,
            mime_type: ?[]const u8,
            color_support: terminal.ColorSupport,
        ) !Self {
            const colors = colors_mod.green(color_support);
            const fg_color = colors.fg;
            const bg_color = colors.bg;

            const key = try allocator.dupe(u8, obj.key);
            errdefer allocator.free(key);
            const bucket_owned = try allocator.dupe(u8, bucket);
            errdefer allocator.free(bucket_owned);
            const region_owned = try allocator.dupe(u8, region);
            errdefer allocator.free(region_owned);
            const s3_uri = try std.fmt.allocPrint(allocator, "s3://{s}/{s}", .{ bucket, obj.key });
            errdefer allocator.free(s3_uri);
            const arn = try std.fmt.allocPrint(allocator, "arn:aws:s3:::{s}/{s}", .{ bucket, obj.key });
            errdefer allocator.free(arn);
            const object_url = try std.fmt.allocPrint(allocator, "https://{s}.s3.{s}.amazonaws.com/{s}", .{ bucket, region, obj.key });
            errdefer allocator.free(object_url);
            const etag = try allocator.dupe(u8, obj.etag);
            errdefer allocator.free(etag);
            const last_modified = try allocator.dupe(u8, obj.last_modified);
            errdefer allocator.free(last_modified);
            const owner_str = if (obj.owner) |o|
                try allocator.dupe(u8, if (o.display_name.len > 0) o.display_name else o.id)
            else
                try allocator.dupe(u8, "-");
            errdefer allocator.free(owner_str);
            const mime_owned: ?[]u8 = if (mime_type) |m| try allocator.dupe(u8, m) else null;
            errdefer if (mime_owned) |m| allocator.free(m);

            const head_ctx = try allocator.create(HeadCtx);
            errdefer allocator.destroy(head_ctx);
            const endpoint_owned = try allocator.dupe(u8, endpoint);
            errdefer allocator.free(endpoint_owned);

            head_ctx.* = .{
                .allocator = allocator,
                .io = io,
                .credentials = credentials,
                .endpoint = endpoint_owned,
                .virtual_hosted = virtual_hosted,
                .region = region_owned,
                .bucket = bucket_owned,
                .key = key,
                .thread = undefined,
                .done = std.atomic.Value(bool).init(false),
            };
            head_ctx.thread = try std.Thread.spawn(.{}, headFn, .{head_ctx});
            errdefer head_ctx.thread.join();

            var bc_buf: [256]u8 = undefined;
            const bc = std.fmt.bufPrint(&bc_buf, "Buckets {s} {s} {s} Objects", .{ constants.SEP_ARROW, bucket, constants.SEP_ARROW }) catch bc_buf[0..0];

            return Self{
                .fg_color = fg_color,
                .bg_color = bg_color,
                .breadcrumb_buf = bc_buf,
                .breadcrumb_len = bc.len,
                .key = key,
                .bucket = bucket_owned,
                .region = region_owned,
                .s3_uri = s3_uri,
                .arn = arn,
                .object_url = object_url,
                .etag = etag,
                .last_modified = last_modified,
                .owner_str = owner_str,
                .mime_type = mime_owned,
                .storage_class_str = @tagName(obj.storage_class),
                .checksum_algo_str = if (obj.checksum_algorithm) |a| @tagName(a) else "-",
                .checksum_type_str = if (obj.checksum_type) |t| @tagName(t) else "-",
                .size = obj.size,
                .head_ctx = head_ctx,
                .io = io,
            };
        }

        pub fn breadcrumb(self: *Self) []const u8 {
            return self.breadcrumb_buf[0..self.breadcrumb_len];
        }

        pub fn deinit(self: *Self) void {
            const alloc = self.head_ctx.allocator;
            self.head_ctx.thread.join();
            alloc.free(self.head_ctx.endpoint);
            if (self.head_ctx.content_type) |s| alloc.free(s);
            if (self.head_ctx.sse) |s| alloc.free(s);
            if (self.head_ctx.lock_mode) |s| alloc.free(s);
            if (self.head_ctx.legal_hold) |s| alloc.free(s);
            if (self.head_ctx.checksum_value) |s| alloc.free(s);
            alloc.destroy(self.head_ctx);
            alloc.free(self.key);
            alloc.free(self.bucket);
            alloc.free(self.region);
            alloc.free(self.s3_uri);
            alloc.free(self.arn);
            alloc.free(self.object_url);
            alloc.free(self.etag);
            alloc.free(self.last_modified);
            alloc.free(self.owner_str);
            if (self.mime_type) |m| alloc.free(m);
        }

        fn refresh(self: *Self) !void {
            if (!self.head_ctx.done.load(.acquire)) return;

            const alloc = self.head_ctx.allocator;
            const io = self.head_ctx.io;
            const creds = self.head_ctx.credentials;
            const endpoint = try alloc.dupe(u8, self.head_ctx.endpoint);
            errdefer alloc.free(endpoint);
            const virtual_hosted = self.head_ctx.virtual_hosted;

            self.head_ctx.thread.join();
            alloc.free(self.head_ctx.endpoint);
            if (self.head_ctx.content_type) |s| alloc.free(s);
            if (self.head_ctx.sse) |s| alloc.free(s);
            if (self.head_ctx.lock_mode) |s| alloc.free(s);
            if (self.head_ctx.legal_hold) |s| alloc.free(s);
            if (self.head_ctx.checksum_value) |s| alloc.free(s);
            alloc.destroy(self.head_ctx);

            const new_ctx = try alloc.create(HeadCtx);
            errdefer alloc.destroy(new_ctx);
            new_ctx.* = .{
                .allocator = alloc,
                .io = io,
                .credentials = creds,
                .endpoint = endpoint,
                .virtual_hosted = virtual_hosted,
                .region = self.region,
                .bucket = self.bucket,
                .key = self.key,
                .thread = undefined,
                .done = std.atomic.Value(bool).init(false),
            };
            new_ctx.thread = try std.Thread.spawn(.{}, headFn, .{new_ctx});
            self.head_ctx = new_ctx;
        }

        const view_size_limit: u64 = 5 * 1024 * 1024;

        fn effectiveMime(self: *Self) ?[]const u8 {
            if (mime_mod.fromExtension(self.key)) |m| return m;
            if (self.mime_type) |m| if (m.len > 0) return m;
            if (self.head_ctx.done.load(.acquire)) {
                if (self.head_ctx.content_type) |ct| if (ct.len > 0) return ct;
            }
            return null;
        }

        fn isViewable(self: *Self) bool {
            if (self.size >= view_size_limit) return false;
            const ct = self.effectiveMime() orelse return false;
            return isTextMimeType(ct);
        }

        pub fn handleEvent(self: *Self, event: Event, ctx: ViewContext) !Action {
            switch (event) {
                .key => |k| switch (k) {
                    .ctrl_c => return .quit,
                    .char => |c| switch (c) {
                        'q' => return .{ .push = .{ .confirm = ConfirmView.init(self.fg_color, self.bg_color) } },
                        'r' => self.refresh() catch {},
                        'j' => self.scroll += 1,
                        'k' => if (self.scroll > 0) {
                            self.scroll -= 1;
                        },
                        'h' => if (self.action_idx > 0) {
                            self.action_idx -= 1;
                        },
                        'l' => if (self.action_idx < 1) {
                            self.action_idx += 1;
                        },
                        'g' => {
                            if (self.pending_g) {
                                self.scroll = 0;
                                self.pending_g = false;
                            } else {
                                self.pending_g = true;
                            }
                        },
                        'G' => {
                            self.pending_g = false;
                            self.scroll = std.math.maxInt(usize) / 2;
                        },
                        else => {
                            self.pending_g = false;
                        },
                    },
                    .down => self.scroll += 1,
                    .up => if (self.scroll > 0) {
                        self.scroll -= 1;
                    },
                    .left => if (self.action_idx > 0) {
                        self.action_idx -= 1;
                    },
                    .right => if (self.action_idx < 1) {
                        self.action_idx += 1;
                    },
                    .enter => {
                        const creds = self.head_ctx.credentials;
                        if (self.action_idx == 0 and self.isViewable()) {
                            const v = try S3ObjectContentView.init(
                                ctx.allocator,
                                ctx.io,
                                creds,
                                self.head_ctx.endpoint,
                                self.head_ctx.virtual_hosted,
                                self.bucket,
                                self.region,
                                self.key,
                                ctx.color_support,
                            );
                            return .{ .push = .{ .s3_object_content = v } };
                        } else if (self.action_idx == 1) {
                            const v = try S3DownloadView.init(
                                ctx.allocator,
                                ctx.io,
                                creds,
                                self.head_ctx.endpoint,
                                self.head_ctx.virtual_hosted,
                                self.bucket,
                                self.region,
                                self.key,
                                ctx.color_support,
                            );
                            return .{ .push = .{ .s3_download = v } };
                        }
                    },
                    .escape => return .pop,
                    else => {},
                },
                else => {},
            }
            return .none;
        }

        pub fn render(self: *Self, writer: *std.Io.Writer, size: Coord) !void {
            if (size.x < 10 or size.y < 2) return;
            const w: usize = @intCast(size.x);
            const h: usize = @intCast(size.y);

            const head_done = self.head_ctx.done.load(.acquire);
            const loading = constants.ELLIPSES;
            const none_str = "None";
            const dash = "-";

            const content_type: []const u8 = if (self.effectiveMime()) |m|
                m
            else if (head_done)
                dash
            else
                loading;

            const sse = if (head_done) self.head_ctx.sse orelse none_str else loading;
            const lock_mode = if (head_done) self.head_ctx.lock_mode orelse "Disabled" else loading;
            const legal_hold = if (head_done) self.head_ctx.legal_hold orelse "Disabled" else loading;
            const checksum_value = if (head_done) self.head_ctx.checksum_value orelse dash else loading;

            var size_buf: [20]u8 = undefined;
            const size_str = format_mod.size(&size_buf, self.size);

            var prop_buf: [20]props_mod.Prop = undefined;
            var n: usize = 0;
            prop_buf[n] = .{ .label = "Key", .value = self.key };
            n += 1;
            prop_buf[n] = .{ .label = "Bucket", .value = self.bucket };
            n += 1;
            prop_buf[n] = .{ .label = "S3 URI", .value = self.s3_uri };
            n += 1;
            prop_buf[n] = .{ .label = "ARN", .value = self.arn };
            n += 1;
            prop_buf[n] = .{ .label = "Object URL", .value = self.object_url };
            n += 1;
            prop_buf[n] = .{ .label = "Region", .value = self.region };
            n += 1;
            prop_buf[n] = .{ .label = "Owner", .value = self.owner_str };
            n += 1;
            prop_buf[n] = .{ .label = "Last Modified", .value = self.last_modified };
            n += 1;
            prop_buf[n] = .{ .label = "Size", .value = size_str };
            n += 1;
            prop_buf[n] = .{ .label = "MIME Type", .value = content_type };
            n += 1;
            prop_buf[n] = .{ .label = "ETag", .value = self.etag };
            n += 1;
            prop_buf[n] = .{ .label = "Storage Class", .value = self.storage_class_str };
            n += 1;
            prop_buf[n] = .{ .label = "SSE", .value = sse };
            n += 1;
            prop_buf[n] = .{ .label = "Checksum Algorithm", .value = self.checksum_algo_str };
            n += 1;
            prop_buf[n] = .{ .label = "Checksum Type", .value = self.checksum_type_str };
            n += 1;
            prop_buf[n] = .{ .label = "Checksum Value", .value = checksum_value };
            n += 1;
            prop_buf[n] = .{ .label = "Object Lock Mode", .value = lock_mode };
            n += 1;
            prop_buf[n] = .{ .label = "Legal Hold", .value = legal_hold };
            n += 1;

            const total = n;
            const data_rows = if (h >= 1) h - 1 else 0;
            if (data_rows > 0 and self.scroll + data_rows > total) {
                self.scroll = if (total > data_rows) total - data_rows else 0;
            }

            const props_h = if (h >= 2) h - 1 else h;
            try props_mod.render(writer, prop_buf[0..n], self.scroll, w, props_h, self.fg_color);

            if (h >= 2) {
                try writer.writeAll("\r\n");
                try renderActionBar(self, writer, w);
            }
        }

        fn renderActionBar(self: *Self, writer: *std.Io.Writer, w: usize) !void {
            const view_disabled = !self.isViewable();

            if (view_disabled) {
                try writer.writeAll(terminal.DIM);
                try writer.writeAll(self.fg_color);
            } else if (self.action_idx == 0) {
                try writer.writeAll(self.bg_color);
                try writer.writeAll(terminal.FG_BLACK);
            } else {
                try writer.writeAll(self.fg_color);
            }
            const view_btn = " [ View ] ";
            try writer.writeAll(view_btn);
            try writer.writeAll(terminal.RESET);

            if (self.action_idx == 1) {
                try writer.writeAll(self.bg_color);
                try writer.writeAll(terminal.FG_BLACK);
            } else {
                try writer.writeAll(self.fg_color);
            }
            const dl_btn = " [ Download ] ";
            try writer.writeAll(dl_btn);
            try writer.writeAll(terminal.RESET);

            const used = view_btn.len + dl_btn.len;
            if (w > used) {
                for (0..w - used) |_| try writer.writeByte(' ');
            }
        }
    };
}

pub const S3ObjectView = S3ObjectViewGeneric(headThread);

// ============================================================================
// Tests
// ============================================================================

test "formatSize bytes" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("512 B", format_mod.size(&buf, 512));
}

test "formatSize kilobytes" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("1.0 KB", format_mod.size(&buf, 1024));
}

test "formatSize megabytes" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("1.0 MB", format_mod.size(&buf, 1024 * 1024));
}

test "isTextMimeType text prefix" {
    try std.testing.expect(isTextMimeType("text/plain"));
    try std.testing.expect(isTextMimeType("text/html"));
    try std.testing.expect(isTextMimeType("text/css"));
}

test "isTextMimeType application types" {
    try std.testing.expect(isTextMimeType("application/json"));
    try std.testing.expect(isTextMimeType("application/xml"));
    try std.testing.expect(isTextMimeType("application/yaml"));
}

test "isTextMimeType rejects binary" {
    try std.testing.expect(!isTextMimeType("image/png"));
    try std.testing.expect(!isTextMimeType("application/octet-stream"));
}

test "isTextMimeType strips params" {
    try std.testing.expect(isTextMimeType("application/json; charset=utf-8"));
}
