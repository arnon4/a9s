const std = @import("std");
const colors_mod = @import("../../../ui/colors.zig");
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
const MessageView = @import("../../../ui/message.zig");
const ConfirmView = @import("../../../ui/confirm.zig");

const S3DownloadView = @This();
pub const name: []const u8 = "Download";

const DownloadCtx = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    io: std.Io,
    virtual_hosted: bool,
    endpoint: []const u8,
    region: []const u8,
    credentials: Credentials,
    bucket: []const u8,
    key: []const u8,
    thread: std.Thread,
    result_path: ?[]u8 = null,
    err: ?anyerror = null,
    done: std.atomic.Value(bool),
};

fn pathExists(io: std.Io, path: []const u8) bool {
    const f = std.Io.Dir.cwd().openFile(io, path, .{}) catch return false;
    f.close(io);
    return true;
}

fn findAvailableName(allocator: std.mem.Allocator, io: std.Io, filename: []const u8) ![]u8 {
    if (!pathExists(io, filename)) return allocator.dupe(u8, filename);

    const ext = std.fs.path.extension(filename);
    const stem = filename[0 .. filename.len - ext.len];

    var count: usize = 1;
    while (count < 1000) : (count += 1) {
        const candidate = if (ext.len > 0)
            try std.fmt.allocPrint(allocator, "{s} ({d}){s}", .{ stem, count, ext })
        else
            try std.fmt.allocPrint(allocator, "{s} ({d})", .{ stem, count });
        if (!pathExists(io, candidate)) return candidate;
        allocator.free(candidate);
    }
    return error.TooManyFiles;
}

fn downloadThread(ctx: *DownloadCtx) void {
    defer {
        ctx.done.store(true, .release);
        input.notify();
    }

    const result = S3.getObjectWithIo(
        ctx.arena.allocator(),
        ctx.io,
        ctx.virtual_hosted,
        ctx.endpoint,
        ctx.region,
        ctx.credentials,
        .{ .bucket = ctx.bucket, .key = ctx.key },
    ) catch |e| {
        std.log.err("S3 download getObject {s}/{s}: {s}", .{ ctx.bucket, ctx.key, @errorName(e) });
        ctx.err = e;
        return;
    };

    const raw_basename = std.fs.path.basename(ctx.key);
    const basename = if (raw_basename.len > 0) raw_basename else ctx.key;

    const filename = findAvailableName(ctx.arena.allocator(), ctx.io, basename) catch |e| {
        std.log.err("S3 download findAvailableName {s}: {s}", .{ basename, @errorName(e) });
        ctx.err = e;
        return;
    };

    const file = std.Io.Dir.cwd().createFile(ctx.io, filename, .{}) catch |e| {
        std.log.err("S3 download createFile {s}: {s}", .{ filename, @errorName(e) });
        ctx.err = e;
        return;
    };
    defer file.close(ctx.io);

    var write_buf: [4096]u8 = undefined;
    var fw = file.writer(ctx.io, &write_buf);
    fw.interface.writeAll(result.body) catch |e| {
        std.log.err("S3 download write {s}: {s}", .{ filename, @errorName(e) });
        ctx.err = e;
        return;
    };
    fw.flush() catch |e| {
        std.log.err("S3 download flush {s}: {s}", .{ filename, @errorName(e) });
        ctx.err = e;
        return;
    };

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const cwd_len = std.process.currentPath(ctx.io, &path_buf) catch |e| {
        std.log.err("S3 download currentPath: {s}", .{@errorName(e)});
        ctx.err = e;
        return;
    };
    const cwd = path_buf[0..cwd_len];
    ctx.result_path = std.fs.path.join(ctx.allocator, &.{ cwd, filename }) catch |e| {
        std.log.err("S3 download path.join: {s}", .{@errorName(e)});
        ctx.err = e;
        return;
    };
}

const State = union(enum) {
    in_progress: *DownloadCtx,
    done: MessageView,
};

allocator: std.mem.Allocator,
fg_color: []const u8,
bg_color: []const u8,
state: State,
breadcrumb_buf: [256]u8 = undefined,
breadcrumb_len: usize = 0,

pub fn init(
    allocator: std.mem.Allocator,
    io: std.Io,
    credentials: Credentials,
    endpoint: []const u8,
    virtual_hosted: bool,
    bucket: []const u8,
    region: []const u8,
    key: []const u8,
    color_support: terminal.ColorSupport,
) !S3DownloadView {
    const colors = colors_mod.green(color_support);
    const fg_color = colors.fg;
    const bg_color = colors.bg;

    const ctx = try allocator.create(DownloadCtx);
    errdefer allocator.destroy(ctx);

    ctx.* = .{
        .allocator = allocator,
        .arena = std.heap.ArenaAllocator.init(allocator),
        .io = io,
        .virtual_hosted = virtual_hosted,
        .credentials = credentials,
        .endpoint = undefined,
        .region = undefined,
        .bucket = undefined,
        .key = undefined,
        .thread = undefined,
        .done = std.atomic.Value(bool).init(false),
    };
    errdefer ctx.arena.deinit();

    const a = ctx.arena.allocator();
    ctx.endpoint = try a.dupe(u8, endpoint);
    ctx.region = try a.dupe(u8, region);
    ctx.bucket = try a.dupe(u8, bucket);
    ctx.key = try a.dupe(u8, key);

    ctx.thread = try std.Thread.spawn(.{}, downloadThread, .{ctx});

    var bc_buf: [256]u8 = undefined;
    const bc = std.fmt.bufPrint(
        &bc_buf,
        "Buckets {s} {s} {s} Objects {s} {s} {s} Download",
        .{ constants.SEP_ARROW, bucket, constants.SEP_ARROW, constants.SEP_ARROW, key, constants.SEP_ARROW },
    ) catch bc_buf[0..0];

    return .{
        .allocator = allocator,
        .fg_color = fg_color,
        .bg_color = bg_color,
        .state = .{ .in_progress = ctx },
        .breadcrumb_buf = bc_buf,
        .breadcrumb_len = bc.len,
    };
}

pub fn breadcrumb(self: *S3DownloadView) []const u8 {
    return self.breadcrumb_buf[0..self.breadcrumb_len];
}

pub fn deinit(self: *S3DownloadView) void {
    switch (self.state) {
        .in_progress => |ctx| {
            ctx.thread.join();
            if (ctx.result_path) |p| ctx.allocator.free(p);
            ctx.arena.deinit();
            ctx.allocator.destroy(ctx);
        },
        .done => |*m| m.deinit(),
    }
}

pub fn handleEvent(self: *S3DownloadView, event: Event, ctx: ViewContext) !Action {
    // Intercept 'q' to push confirm dialog instead of quitting directly.
    switch (event) {
        .key => |k| switch (k) {
            .char => |c| if (c == 'q') {
                return .{ .push = .{ .confirm = ConfirmView.init(self.fg_color, self.bg_color) } };
            },
            else => {},
        },
        else => {},
    }
    switch (self.state) {
        .in_progress => return .none,
        .done => |*m| return m.handleEvent(event, ctx),
    }
}

fn transitionIfDone(self: *S3DownloadView) void {
    if (self.state != .in_progress) return;
    const ctx = self.state.in_progress;
    if (!ctx.done.load(.acquire)) return;

    ctx.thread.join();

    const body: []u8 = blk: {
        if (ctx.err) |e| {
            if (ctx.result_path) |p| ctx.allocator.free(p);
            break :blk std.fmt.allocPrint(ctx.allocator, "Error: {s}", .{@errorName(e)}) catch unreachable;
        }
        const path = ctx.result_path orelse (ctx.allocator.dupe(u8, "unknown path") catch unreachable);
        ctx.result_path = null;
        defer ctx.allocator.free(path);
        break :blk std.fmt.allocPrint(ctx.allocator, "Downloaded to:\n{s}", .{path}) catch unreachable;
    };
    const title = ctx.allocator.dupe(u8, "Download") catch unreachable;

    ctx.arena.deinit();
    ctx.allocator.destroy(ctx);

    self.state = .{ .done = MessageView.init(self.allocator, title, body, self.fg_color) };
}

pub fn render(self: *S3DownloadView, writer: *std.Io.Writer, size: Coord) !void {
    self.transitionIfDone();

    switch (self.state) {
        .in_progress => try renderProgress(self, writer, size),
        .done => |*m| try m.render(writer, size),
    }
}

fn renderProgress(self: *S3DownloadView, writer: *std.Io.Writer, size: Coord) !void {
    if (size.x < 4 or size.y < 2) return;
    const w: usize = @intCast(size.x);
    const h: usize = @intCast(size.y);
    const inner_w = w - 2;
    const data_rows = h - 1;

    const msg = "Downloading\xe2\x80\xa6";

    for (0..data_rows) |row| {
        try writer.writeAll(self.fg_color);
        try writer.writeAll(constants.VERTICAL);
        try writer.writeAll(terminal.RESET);
        if (row == 0) {
            const shown = msg[0..@min(msg.len, inner_w)];
            try writer.writeAll(shown);
            for (shown.len..inner_w) |_| try writer.writeByte(' ');
        } else {
            for (0..inner_w) |_| try writer.writeByte(' ');
        }
        try writer.writeAll(self.fg_color);
        try writer.writeAll(constants.VERTICAL);
        try writer.writeAll(terminal.RESET);
        try writer.writeAll("\r\n");
    }

    try writer.writeAll(self.fg_color);
    try writer.writeAll(constants.BOTTOM_LEFT);
    for (0..inner_w) |_| try writer.writeAll(constants.HORIZONTAL);
    try writer.writeAll(constants.BOTTOM_RIGHT);
    try writer.writeAll(terminal.RESET);
}
