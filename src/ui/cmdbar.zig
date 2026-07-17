const std = @import("std");
const builtin = @import("builtin");
const Event = @import("../event.zig").Event;
const terminal = @import("../terminal/terminal.zig");

pub const Mode = enum { inactive, command, search };

pub const SubmitResult = union(enum) {
    none,
    dismiss,
    submit: struct {
        mode: Mode,
        text: []const u8,
    },
};

const max_history: usize = 500;
const path_buf_size: usize = 4096;

pub const CommandBar = @This();

allocator: std.mem.Allocator,
io: std.Io,
home_dir: ?[]const u8,
mode: Mode = .inactive,
buf: [256]u8 = undefined,
len: usize = 0,
cursor: usize = 0,
scroll: usize = 0,
error_msg: ?[]const u8 = null,
error_buf: [128]u8 = undefined,
history: std.ArrayList([]u8) = .empty,
hist_idx: usize = 0,
saved_buf: [256]u8 = undefined,
saved_len: usize = 0,
saved_cursor: usize = 0,

pub fn init(allocator: std.mem.Allocator, io: std.Io, environ_map: *const std.process.Environ.Map) CommandBar {
    const home_var = if (builtin.os.tag == .windows) "USERPROFILE" else "HOME";
    const home = environ_map.get(home_var);
    var self = CommandBar{ .allocator = allocator, .io = io, .home_dir = home };
    self.loadHistory() catch {};
    self.hist_idx = self.history.items.len;
    return self;
}

pub fn deinit(self: *CommandBar) void {
    for (self.history.items) |s| self.allocator.free(s);
    self.history.deinit(self.allocator);
}

fn loadHistory(self: *CommandBar) !void {
    const home = self.home_dir orelse return;

    var hist_buf: [path_buf_size]u8 = undefined;
    const hist_path = try std.fmt.bufPrint(&hist_buf, "{s}/.at/.history", .{home});

    const content = std.Io.Dir.cwd().readFileAlloc(
        self.io,
        hist_path,
        self.allocator,
        std.Io.Limit.limited(4 * 1024 * 1024),
    ) catch return;
    defer self.allocator.free(content);

    var it = std.mem.splitScalar(u8, content, '\n');
    while (it.next()) |line| {
        const trimmed = std.mem.trimEnd(u8, line, "\r");
        if (trimmed.len == 0) continue;
        const owned = self.allocator.dupe(u8, trimmed) catch continue;
        self.history.append(self.allocator, owned) catch {
            self.allocator.free(owned);
            continue;
        };
    }

    if (self.history.items.len > max_history) {
        const excess = self.history.items.len - max_history;
        for (self.history.items[0..excess]) |s| self.allocator.free(s);
        std.mem.copyForwards([]u8, self.history.items[0..max_history], self.history.items[excess..]);
        self.history.shrinkRetainingCapacity(max_history);
        self.saveHistory();
    }
}

fn saveHistory(self: *CommandBar) void {
    const home = self.home_dir orelse return;

    var at_buf: [path_buf_size]u8 = undefined;
    const at_path = std.fmt.bufPrint(&at_buf, "{s}/.at", .{home}) catch return;
    std.Io.Dir.createDirAbsolute(self.io, at_path, .default_dir) catch |e| switch (e) {
        error.PathAlreadyExists => {},
        else => return,
    };

    var hist_buf: [path_buf_size]u8 = undefined;
    const hist_path = std.fmt.bufPrint(&hist_buf, "{s}/.at/.history", .{home}) catch return;
    const file = std.Io.Dir.cwd().createFile(self.io, hist_path, .{ .truncate = true }) catch return;
    defer file.close(self.io);

    var write_buf: [4096]u8 = undefined;
    var writer = file.writer(self.io, &write_buf);
    for (self.history.items) |entry| {
        writer.interface.writeAll(entry) catch return;
        writer.interface.writeAll("\n") catch return;
    }
    writer.interface.flush() catch {};
}

pub fn isActive(self: *const CommandBar) bool {
    return self.mode != .inactive;
}

pub fn activate(self: *CommandBar, mode: Mode) void {
    self.mode = mode;
    self.len = 0;
    self.cursor = 0;
    self.scroll = 0;
    self.hist_idx = self.history.items.len;
    self.error_msg = null;
}

pub fn setError(self: *CommandBar, msg: []const u8) void {
    self.error_msg = msg;
}

pub fn setErrorFmt(self: *CommandBar, comptime fmt: []const u8, args: anytype) void {
    const result = std.fmt.bufPrint(&self.error_buf, fmt, args) catch "error";
    self.error_msg = result;
}

pub fn clearError(self: *CommandBar) void {
    self.error_msg = null;
}

pub fn handleEvent(self: *CommandBar, event: Event) SubmitResult {
    if (self.mode == .inactive) return .none;
    switch (event) {
        .key => |k| switch (k) {
            .escape, .ctrl_c => {
                self.mode = .inactive;
                return .dismiss;
            },
            .enter => {
                const text = self.buf[0..self.len];
                if (text.len > 0) {
                    const is_dup = self.history.items.len > 0 and
                        std.mem.eql(u8, self.history.getLast(), text);
                    if (!is_dup) {
                        if (self.allocator.dupe(u8, text) catch null) |owned| {
                            if (self.history.items.len >= max_history) {
                                self.allocator.free(self.history.items[0]);
                                std.mem.copyForwards([]u8, self.history.items[0 .. self.history.items.len - 1], self.history.items[1..]);
                                self.history.shrinkRetainingCapacity(self.history.items.len - 1);
                            }
                            self.history.append(self.allocator, owned) catch self.allocator.free(owned);
                            self.saveHistory();
                        }
                    }
                }
                const result = SubmitResult{ .submit = .{ .mode = self.mode, .text = text } };
                self.mode = .inactive;
                self.hist_idx = self.history.items.len;
                return result;
            },
            .backspace => {
                if (self.cursor > 0) {
                    std.mem.copyForwards(u8, self.buf[self.cursor - 1 .. self.len - 1], self.buf[self.cursor..self.len]);
                    self.len -= 1;
                    self.cursor -= 1;
                    self.hist_idx = self.history.items.len;
                } else {
                    self.mode = .inactive;
                    return .dismiss;
                }
                return .none;
            },
            .left => {
                if (self.cursor > 0) self.cursor -= 1;
                return .none;
            },
            .right => {
                if (self.cursor < self.len) self.cursor += 1;
                return .none;
            },
            .up => {
                if (self.hist_idx == self.history.items.len) {
                    @memcpy(self.saved_buf[0..self.len], self.buf[0..self.len]);
                    self.saved_len = self.len;
                    self.saved_cursor = self.cursor;
                }
                if (self.hist_idx > 0) {
                    self.hist_idx -= 1;
                    const entry = self.history.items[self.hist_idx];
                    const n = @min(entry.len, self.buf.len);
                    @memcpy(self.buf[0..n], entry[0..n]);
                    self.len = n;
                    self.cursor = n;
                    self.scroll = 0;
                }
                return .none;
            },
            .down => {
                if (self.hist_idx < self.history.items.len) {
                    self.hist_idx += 1;
                    if (self.hist_idx == self.history.items.len) {
                        @memcpy(self.buf[0..self.saved_len], self.saved_buf[0..self.saved_len]);
                        self.len = self.saved_len;
                        self.cursor = self.saved_cursor;
                        self.scroll = 0;
                    } else {
                        const entry = self.history.items[self.hist_idx];
                        const n = @min(entry.len, self.buf.len);
                        @memcpy(self.buf[0..n], entry[0..n]);
                        self.len = n;
                        self.cursor = n;
                        self.scroll = 0;
                    }
                }
                return .none;
            },
            .char => |c| {
                if (std.ascii.isPrint(c) and self.len < self.buf.len) {
                    std.mem.copyBackwards(u8, self.buf[self.cursor + 1 .. self.len + 1], self.buf[self.cursor..self.len]);
                    self.buf[self.cursor] = c;
                    self.len += 1;
                    self.cursor += 1;
                    self.hist_idx = self.history.items.len;
                }
                return .none;
            },
        },
        else => return .none,
    }
}

pub fn render(self: *CommandBar, writer: *std.Io.Writer, width: usize) !void {
    if (self.error_msg) |msg| {
        try writer.writeAll(terminal.FG_RED);
        const shown = msg[0..@min(msg.len, width)];
        try writer.writeAll(shown);
        for (shown.len..width) |_| try writer.writeByte(' ');
        try writer.writeAll(terminal.RESET);
        return;
    }
    if (self.mode == .inactive) {
        for (0..width) |_| try writer.writeByte(' ');
        return;
    }
    const prefix: u8 = switch (self.mode) {
        .command => ':',
        .search => '/',
        .inactive => unreachable,
    };
    try writer.writeByte(prefix);
    const avail = if (width >= 1) width - 1 else 0;

    if (self.cursor < self.scroll) self.scroll = self.cursor;
    if (avail > 0 and self.cursor >= self.scroll + avail) self.scroll = self.cursor - avail + 1;

    for (0..avail) |col| {
        const buf_idx = self.scroll + col;
        if (buf_idx == self.cursor) {
            if (buf_idx < self.len) {
                try writer.writeAll(terminal.REVERSE);
                try writer.writeByte(self.buf[buf_idx]);
                try writer.writeAll(terminal.RESET);
            } else {
                try writer.writeAll(terminal.REVERSE);
                try writer.writeByte(' ');
                try writer.writeAll(terminal.RESET);
                for (col + 1..avail) |_| try writer.writeByte(' ');
                break;
            }
        } else if (buf_idx < self.len) {
            try writer.writeByte(self.buf[buf_idx]);
        } else {
            for (col..avail) |_| try writer.writeByte(' ');
            break;
        }
    }
}
