const std = @import("std");
const builtin = @import("builtin");
const is_windows = builtin.os.tag == .windows;

const windows = if (is_windows) std.os.windows else void;
const posix = if (!is_windows) std.posix else void;

const event = @import("../event.zig");
const Event = event.Event;
const Key = event.Key;

const terminal = @import("terminal.zig");

var sigwinch_pipe: if (is_windows) void else [2]posix.fd_t = if (is_windows) {} else undefined;
var notify_pipe: if (is_windows) void else [2]posix.fd_t = if (is_windows) {} else undefined;
var stdin_handle_cache: if (is_windows) ?windows.HANDLE else void = if (is_windows) null else {};

const WriteConsoleInputW = if (is_windows) struct {
    pub extern "kernel32" fn WriteConsoleInputW(
        hConsoleInput: windows.HANDLE,
        lpBuffer: [*]const INPUT_RECORD,
        nLength: windows.DWORD,
        lpNumberOfEventsRead: *windows.DWORD,
    ) callconv(.winapi) windows.BOOL;
}.WriteConsoleInputW else {};

fn sigwinchHandler(_: std.os.linux.SIG) callconv(.c) void {
    if (comptime !is_windows) {
        if (comptime builtin.os.tag == .linux) {
            _ = std.os.linux.write(sigwinch_pipe[1], "\x01", 1);
        } else {
            _ = std.c.write(sigwinch_pipe[1], "\x01", 1);
        }
    }
}

/// Installs the SIGWINCH handler and creates the pipe used to deliver resize events into the event loop.
pub fn initSignals() !void {
    if (comptime !is_windows) {
        if (comptime builtin.os.tag == .linux) {
            const rc = std.os.linux.pipe2(@ptrCast(&sigwinch_pipe), .{});
            if (rc != 0) return error.PipeFailed;
        } else {
            var fds: [2]posix.fd_t = undefined;
            if (std.c.pipe(&fds) != 0) return error.PipeFailed;
            sigwinch_pipe = fds;
        }
        if (comptime builtin.os.tag == .linux) {
            const rc = std.os.linux.pipe2(@ptrCast(&notify_pipe), .{});
            if (rc != 0) return error.PipeFailed;
        } else {
            var fds: [2]posix.fd_t = undefined;
            if (std.c.pipe(&fds) != 0) return error.PipeFailed;
            notify_pipe = fds;
        }
        const action = posix.Sigaction{
            .handler = .{ .handler = sigwinchHandler },
            .mask = std.mem.zeroes(posix.sigset_t),
            .flags = 0,
        };
        posix.sigaction(posix.SIG.WINCH, &action, null);
        std.log.debug("initSignals: sigwinch_pipe=[{d},{d}] notify_pipe=[{d},{d}]", .{
            sigwinch_pipe[0], sigwinch_pipe[1],
            notify_pipe[0],   notify_pipe[1],
        });
    }
}

/// Wakes the event loop from a background thread, triggering a re-render.
pub fn notify() void {
    if (comptime is_windows) {
        if (@intFromPtr(stdin_handle_cache) == 0) return;
        var record: INPUT_RECORD = std.mem.zeroes(INPUT_RECORD);
        record.EventType = KEY_EVENT;
        // bKeyDown = FALSE (zeroed) — readEvent filters key-up events and returns null,
        // which app.zig uses to trigger renderFrame.
        var written: windows.DWORD = 0;
        _ = WriteConsoleInputW(stdin_handle_cache.?, @ptrCast(&record), 1, &written);
    } else {
        if (comptime builtin.os.tag == .linux) {
            _ = std.os.linux.write(notify_pipe[1], "\x01", 1);
        } else {
            _ = std.c.write(notify_pipe[1], "\x01", 1);
        }
    }
}

fn parse(bytes: []const u8) ?Event {
    if (bytes.len == 0) return null;

    if (bytes.len == 1) {
        return switch (bytes[0]) {
            '\r', '\n' => .{ .key = .enter },
            '\x1b' => .{ .key = .escape },
            '\x7f', '\x08' => .{ .key = .backspace },
            '\x03' => .{ .key = .ctrl_c },
            else => |c| .{ .key = .{ .char = c } },
        };
    }

    // on Windows arrow/escape keys never arrive as escape sequences
    if (!is_windows) {
        if (bytes[0] == '\x1b' and bytes.len >= 3 and bytes[1] == '[') {
            return switch (bytes[2]) {
                'A' => .{ .key = .up },
                'B' => .{ .key = .down },
                'C' => .{ .key = .right },
                'D' => .{ .key = .left },
                else => .{ .key = .escape },
            };
        }
    }

    return .{ .key = .{ .char = bytes[0] } };
}

const KEY_EVENT: u16 = if (is_windows) 0x0001 else 0;
const WINDOW_BUFFER_SIZE_EVENT: u16 = if (is_windows) 0x0004 else 0;
const WINDOW_BUFFER_SIZE_RECORD = if (is_windows) extern struct { dwSize: windows.COORD } else void;

const VK_LEFT: u16 = if (is_windows) 0x25 else 0;
const VK_UP: u16 = if (is_windows) 0x26 else 0;
const VK_RIGHT: u16 = if (is_windows) 0x27 else 0;
const VK_DOWN: u16 = if (is_windows) 0x28 else 0;

const KEY_EVENT_RECORD = if (is_windows) extern struct {
    bKeyDown: windows.BOOL,
    wRepeatCount: windows.WORD,
    wVirtualKeyCode: windows.WORD,
    wVirtualScanCode: windows.WORD,
    UnicodeChar: windows.WCHAR,
    dwControlKeyState: windows.DWORD,
} else void;

const INPUT_RECORD = if (is_windows) extern struct {
    EventType: windows.WORD,
    _pad: u16 = 0,
    Event: extern union {
        KeyEvent: KEY_EVENT_RECORD,
        WindowBufferSizeEvent: WINDOW_BUFFER_SIZE_RECORD,
        _padding: [16]u8,
    },
} else void;

const ReadConsoleInputW = if (is_windows) struct {
    pub extern "kernel32" fn ReadConsoleInputW(
        hConsoleInput: windows.HANDLE,
        lpBuffer: [*]INPUT_RECORD,
        nLength: windows.DWORD,
        lpNumberOfEventsRead: *windows.DWORD,
    ) callconv(.winapi) windows.BOOL;
}.ReadConsoleInputW else {};

/// Blocks until the next terminal event and returns it, or null for events that are ignored.
pub fn readEvent(stdin: std.Io.File) !?Event {
    if (builtin.os.tag == .windows) {
        stdin_handle_cache = stdin.handle;
        var record: INPUT_RECORD = undefined;
        var events_read: windows.DWORD = 0;
        if (ReadConsoleInputW(stdin.handle, @ptrCast(&record), 1, &events_read) == windows.BOOL.FALSE) {
            return error.ReadFailed;
        }
        if (events_read == 0) return null;

        switch (record.EventType) {
            KEY_EVENT => {
                if (record.Event.KeyEvent.bKeyDown == windows.BOOL.FALSE) return null;
                return switch (record.Event.KeyEvent.wVirtualKeyCode) {
                    VK_UP => .{ .key = .up },
                    VK_DOWN => .{ .key = .down },
                    VK_LEFT => .{ .key = .left },
                    VK_RIGHT => .{ .key = .right },
                    else => {
                        const ch: u8 = @truncate(record.Event.KeyEvent.UnicodeChar);
                        if (ch == 0) return null; // other special key, ignore
                        var buf = [1]u8{ch};
                        return parse(&buf);
                    },
                };
            },
            WINDOW_BUFFER_SIZE_EVENT => {
                const size = record.Event.WindowBufferSizeEvent.dwSize;
                return .{ .resize = .{
                    .x = size.X,
                    .y = size.Y,
                } };
            },
            else => return null,
        }
    } else {
        var fds = [3]posix.pollfd{
            .{ .fd = stdin.handle, .events = posix.POLL.IN, .revents = 0 },
            .{ .fd = sigwinch_pipe[0], .events = posix.POLL.IN, .revents = 0 },
            .{ .fd = notify_pipe[0], .events = posix.POLL.IN, .revents = 0 },
        };
        std.log.debug("readEvent: poll fds stdin={d} sigwinch={d} notify={d}", .{ stdin.handle, sigwinch_pipe[0], notify_pipe[0] });
        const poll_n = try posix.poll(&fds, -1);
        std.log.debug("readEvent: poll returned n={d} revents=[{d},{d},{d}]", .{ poll_n, fds[0].revents, fds[1].revents, fds[2].revents });

        if (fds[2].revents & posix.POLL.IN != 0) {
            var drain: [1]u8 = undefined;
            _ = posix.read(notify_pipe[0], &drain) catch {};
            return null; // triggers re-render in app.zig
        }

        if (fds[1].revents & posix.POLL.IN != 0) {
            var drain: [1]u8 = undefined;
            _ = posix.read(sigwinch_pipe[0], &drain) catch {};
            // ioctl inline here, avoids passing stdout through
            var ws: posix.winsize = undefined;
            const rc = posix.system.ioctl(posix.STDOUT_FILENO, posix.T.IOCGWINSZ, @intFromPtr(&ws));
            if (rc != 0) return null;
            return .{ .resize = .{ .x = @intCast(ws.col), .y = @intCast(ws.row) } };
        }

        if (fds[0].revents & posix.POLL.IN != 0) {
            var buf: [16]u8 = undefined;
            const n = try posix.read(stdin.handle, &buf);
            if (n == 0) return null;
            return parse(buf[0..n]);
        }

        return null;
    }
}
