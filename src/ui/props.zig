const std = @import("std");
const terminal = @import("../terminal/terminal.zig");
const constants = @import("constants.zig");

pub const Prop = struct {
    label: []const u8,
    value: []const u8,
};

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

/// Width of the label column including 1-space padding on each side.
pub const LABEL_W: usize = 22;

/// Render a scrollable key-value property list.
/// `h` includes the bottom separator row — data rows = h - 1.
/// No trailing \r\n after the bottom separator (matches other views).
pub fn render(
    writer: *std.Io.Writer,
    items: []const Prop,
    scroll: usize,
    w: usize,
    h: usize,
    fg_color: []const u8,
) !void {
    if (w < 4 or h < 1) return;
    const inner = w - 2;
    // val_w = inner - LABEL_W - 1 (the interior │)
    const val_w: usize = if (inner > LABEL_W + 1) inner - LABEL_W - 1 else 0;
    const data_rows = h - 1;

    for (0..data_rows) |row| {
        const idx = scroll + row;
        try writer.writeAll(fg_color);
        try writer.writeAll(constants.VERTICAL);
        try writer.writeAll(terminal.RESET);
        if (idx < items.len) {
            const label_cw = if (LABEL_W >= 2) LABEL_W - 2 else 0;
            try writer.writeByte(' ');
            const lend = utf8FitBytes(items[idx].label, label_cw);
            const lshown = items[idx].label[0..lend];
            try writer.writeAll(lshown);
            for (utf8Cols(lshown)..label_cw) |_| try writer.writeByte(' ');
            try writer.writeByte(' ');
            try writer.writeAll(fg_color);
            try writer.writeAll(constants.VERTICAL);
            try writer.writeAll(terminal.RESET);
            const val_cw = if (val_w >= 2) val_w - 2 else 0;
            try writer.writeByte(' ');
            const vend = utf8FitBytes(items[idx].value, val_cw);
            const vshown = items[idx].value[0..vend];
            try writer.writeAll(vshown);
            for (utf8Cols(vshown)..val_cw) |_| try writer.writeByte(' ');
            try writer.writeByte(' ');
        } else {
            for (0..LABEL_W) |_| try writer.writeByte(' ');
            try writer.writeAll(fg_color);
            try writer.writeAll(constants.VERTICAL);
            try writer.writeAll(terminal.RESET);
            for (0..val_w) |_| try writer.writeByte(' ');
        }
        try writer.writeAll(fg_color);
        try writer.writeAll(constants.VERTICAL);
        try writer.writeAll(terminal.RESET);
        try writer.writeAll("\r\n");
    }

    // Bottom separator — no trailing \r\n.
    try writer.writeAll(fg_color);
    try writer.writeAll(constants.BOTTOM_LEFT);
    for (0..LABEL_W) |_| try writer.writeAll(constants.HORIZONTAL);
    try writer.writeAll(constants.BOTTOM_T);
    for (0..val_w) |_| try writer.writeAll(constants.HORIZONTAL);
    try writer.writeAll(constants.BOTTOM_RIGHT);
    try writer.writeAll(terminal.RESET);
}
