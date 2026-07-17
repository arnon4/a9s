const std = @import("std");
const terminal = @import("../terminal/terminal.zig");
const constants = @import("constants.zig");
const Event = @import("../event.zig").Event;
const view_mod = @import("view.zig");
const Action = view_mod.Action;
const ViewContext = view_mod.ViewContext;
const Coord = terminal.Coord;

pub const MessageView = @This();

allocator: std.mem.Allocator,
title: []u8,
body: []u8,
fg_color: []const u8,

/// Takes ownership of title and body (both must be allocator-owned).
pub fn init(
    allocator: std.mem.Allocator,
    title: []u8,
    body: []u8,
    fg_color: []const u8,
) MessageView {
    return .{
        .allocator = allocator,
        .title = title,
        .body = body,
        .fg_color = fg_color,
    };
}

pub fn breadcrumb(self: *MessageView) []const u8 {
    return self.title;
}

pub fn deinit(self: *MessageView) void {
    self.allocator.free(self.title);
    self.allocator.free(self.body);
}

pub fn handleEvent(_: *MessageView, event: Event, _: ViewContext) !Action {
    switch (event) {
        .key => |k| switch (k) {
            .ctrl_c => return .quit,
            .enter, .escape => return .pop,
            .char => |c| if (c == 'q') return .pop,
            else => {},
        },
        else => {},
    }
    return .none;
}

pub fn render(self: *MessageView, writer: *std.Io.Writer, size: Coord) !void {
    if (size.x < 4 or size.y < 2) return;
    const w: usize = @intCast(size.x);
    const h: usize = @intCast(size.y);
    const inner_w = w - 2;
    const data_rows = h - 1;

    // Split body on \n — cap at 8 lines.
    var lines_buf: [8][]const u8 = undefined;
    var n_lines: usize = 0;
    var it = std.mem.splitScalar(u8, self.body, '\n');
    while (it.next()) |line| {
        if (n_lines >= lines_buf.len) break;
        lines_buf[n_lines] = line;
        n_lines += 1;
    }
    const lines = lines_buf[0..n_lines];

    const hint = "Enter / Esc";

    for (0..data_rows) |row| {
        try writer.writeAll(self.fg_color);
        try writer.writeAll(constants.VERTICAL);
        try writer.writeAll(terminal.RESET);

        if (row < lines.len) {
            const line = lines[row];
            const shown = line[0..@min(line.len, if (inner_w > 2) inner_w - 2 else 0)];
            try writer.writeByte(' ');
            try writer.writeAll(shown);
            for (shown.len + 1..inner_w) |_| try writer.writeByte(' ');
        } else if (row == data_rows - 1 and hint.len + 2 <= inner_w) {
            const pad = (inner_w - hint.len) / 2;
            for (0..pad) |_| try writer.writeByte(' ');
            try writer.writeAll(terminal.DIM);
            try writer.writeAll(hint);
            try writer.writeAll(terminal.RESET);
            for (pad + hint.len..inner_w) |_| try writer.writeByte(' ');
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
