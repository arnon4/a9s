const std = @import("std");

var log_file: ?std.Io.File = null;
var log_io: std.Io = undefined;
var log_mutex: std.atomic.Mutex = .unlocked;
var log_write_buf: [4096]u8 = undefined;
var log_writer: ?std.Io.File.Writer = null;

pub fn init(io: std.Io, path: []const u8) !void {
    log_file = try std.Io.Dir.cwd().createFile(io, path, .{ .truncate = true });
    log_io = io;
    log_writer = log_file.?.writer(io, &log_write_buf);
}

pub fn deinit(io: std.Io) void {
    if (log_writer) |*w| w.interface.flush() catch {};
    if (log_file) |f| f.close(io);
    log_file = null;
    log_writer = null;
}

fn lockMutex(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

pub fn logFn(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    lockMutex(&log_mutex);
    defer log_mutex.unlock();

    if (log_writer) |*w| {
        var fmt_buf: [4096]u8 = undefined;
        const msg = std.fmt.bufPrint(
            &fmt_buf,
            "[" ++ @tagName(level) ++ "][" ++ @tagName(scope) ++ "] " ++ format ++ "\n",
            args,
        ) catch return;
        w.interface.writeAll(msg) catch {};
        w.interface.flush() catch {};
    }
}
