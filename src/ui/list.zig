const std = @import("std");

const terminal = @import("../terminal/terminal.zig");
const constants = @import("constants.zig");

pub const List = @This();

items: []const []const u8,
selected: usize = 0,
scroll_offset: usize = 0,
fg_color: []const u8,
bg_color: []const u8,

pub fn moveUp(self: *List) void {
    if (self.selected == 0) return;
    self.selected -= 1;
}

pub fn moveDown(self: *List) void {
    if (self.items.len == 0 or self.selected >= self.items.len - 1) return;
    self.selected += 1;
}

pub fn updateScroll(self: *List, visible: usize) void {
    if (self.selected < self.scroll_offset) {
        self.scroll_offset = self.selected;
    } else if (visible > 0 and self.selected >= self.scroll_offset + visible) {
        self.scroll_offset = self.selected - visible + 1;
    }
}

/// Renders one line of the list box without a trailing \r\n.
/// row 0 = top border, row height-1 = bottom border, rows 1..height-2 = content.
pub fn renderLine(self: *List, writer: *std.Io.Writer, row: usize, width: usize, height: usize) !void {
    if (row == 0) {
        try writer.writeAll(self.fg_color);
        try writer.writeAll(constants.TOP_LEFT);
        for (0..width - 2) |_| try writer.writeAll(constants.HORIZONTAL);
        try writer.writeAll(constants.TOP_RIGHT);
        try writer.writeAll(terminal.RESET);
        return;
    }
    if (row == height - 1) {
        try writer.writeAll(self.fg_color);
        try writer.writeAll(constants.BOTTOM_LEFT);
        for (0..width - 2) |_| try writer.writeAll(constants.HORIZONTAL);
        try writer.writeAll(constants.BOTTOM_RIGHT);
        try writer.writeAll(terminal.RESET);
        return;
    }

    const content_row = row - 1;
    const idx = self.scroll_offset + content_row;
    const is_selected = idx < self.items.len and idx == self.selected;

    if (is_selected) {
        try writer.writeAll(self.bg_color);
        try writer.writeAll(terminal.FG_BLACK);
    } else {
        try writer.writeAll(self.fg_color);
    }
    try writer.writeAll(constants.VERTICAL);
    if (!is_selected) try writer.writeAll(terminal.RESET);

    const inner = width - 2;
    if (idx >= self.items.len or inner < 2) {
        for (0..inner) |_| try writer.writeByte(' ');
    } else {
        const item = self.items[idx];
        const max_label = inner - 2;
        try writer.writeAll(if (is_selected) "▸ " else "  ");
        if (item.len > max_label) {
            if (max_label > 3) {
                try writer.writeAll(item[0 .. max_label - 3]);
                try writer.writeAll("...");
            } else {
                try writer.writeAll(item[0..max_label]);
            }
        } else {
            try writer.writeAll(item);
            for (0..max_label - item.len) |_| try writer.writeByte(' ');
        }
    }

    if (is_selected) {
        try writer.writeAll(self.bg_color);
        try writer.writeAll(terminal.FG_BLACK);
    } else {
        try writer.writeAll(self.fg_color);
    }
    try writer.writeAll(constants.VERTICAL);
    try writer.writeAll(terminal.RESET);
}
