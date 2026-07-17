const std = @import("std");

const terminal = @import("../terminal/terminal.zig");
const Coord = terminal.Coord;
const constants = @import("constants.zig");

pub const Header = @This();

fg_color: []const u8,

const Size = constants.Size;

const LOGO_WIDTH: usize = 27;

const logo = [_][]const u8{
    "  ______           ______",
    " /      \\         /      \\",
    "/$$$$$$  |       /$$$$$$  |",
    "$$ |__$$ |  ___  $$ \\__$$/",
    "$$    $$ | / _ \\ $$      \\",
    "$$$$$$$$ |( (_) | $$$$$$  |",
    "$$ |  $$ | \\__, |/  \\__$$ |",
    "$$ |  $$ |   / / $$    $$/",
    "$$/   $$/   /_/   $$$$$$/",
};

const RenderMode = enum {
    logo, // full logo — wide width, h >= logo.len+11 (6+ content rows)
    medium, // 3 info rows  — medium/wide width, h >= 12 (6+ content rows)
    compact, // 1 info row   — any width, h >= 5
    hidden, // terminal too small to show a useful header
};

fn modeFor(size: Coord) RenderMode {
    const h: usize = @intCast(@max(0, size.y));
    if (size.x >= @intFromEnum(Size.wide) and h >= logo.len + 11) return .logo;
    if (size.x >= @intFromEnum(Size.medium) and h >= 12) return .medium;
    if (h >= 5) return .compact;
    return .hidden;
}

/// Returns the number of terminal rows the header occupies.
pub fn height(size: Coord) i16 {
    return switch (modeFor(size)) {
        .logo => @intCast(logo.len + 2),
        .medium => 5,
        .compact => 3,
        .hidden => 0,
    };
}

pub fn render(self: *Header, writer: *std.Io.Writer, size: Coord, breadcrumb: []const u8, region: []const u8, credentials: []const u8) !void {
    const mode = modeFor(size);
    if (mode == .hidden) return;
    const w = size.x;
    try renderTopLine(writer, w, self.fg_color);
    switch (mode) {
        .logo => try renderWide(writer, @intCast(w), breadcrumb, region, credentials, self.fg_color),
        .medium => try renderMedium(writer, @intCast(w), breadcrumb, region, credentials, self.fg_color),
        .compact => try renderCompact(writer, @intCast(w), region, credentials, self.fg_color),
        .hidden => unreachable,
    }
    try renderBottomLine(writer, w, self.fg_color);
}

fn renderWide(writer: *std.Io.Writer, width: usize, breadcrumb: []const u8, region: []const u8, credentials: []const u8, border_color: []const u8) !void {
    const inner = width - 2;
    const info_width = inner - LOGO_WIDTH;
    for (logo, 0..) |logo_line, i| {
        try writer.writeAll(border_color);
        try writer.writeAll(constants.VERTICAL);
        try writer.writeAll(terminal.RESET);
        const info_len: usize = switch (i) {
            0 => try writeLabeled(writer, "Region", region, info_width),
            1 => try writeLabeled(writer, "Credentials", credentials, info_width),
            2 => blk: {
                const shown = truncateToColumns(breadcrumb, info_width);
                try writer.writeAll(shown);
                break :blk utf8DisplayLen(shown);
            },
            else => 0,
        };
        for (info_len..info_width) |_| try writer.writeByte(' ');
        try writer.writeAll(logo_line);
        for (logo_line.len..LOGO_WIDTH) |_| try writer.writeByte(' ');
        try writer.writeAll(border_color);
        try writer.writeAll(constants.VERTICAL);
        try writer.writeAll(terminal.RESET);
        try writer.writeAll("\r\n");
    }
}

fn renderMedium(writer: *std.Io.Writer, width: usize, breadcrumb: []const u8, region: []const u8, credentials: []const u8, border_color: []const u8) !void {
    const inner = width - 2;
    const rows = [_][2][]const u8{
        .{ "Region", region },
        .{ "Credentials", credentials },
        .{ "", breadcrumb },
    };
    for (rows) |row| {
        try writer.writeAll(border_color);
        try writer.writeAll(constants.VERTICAL);
        try writer.writeAll(terminal.RESET);
        const len = if (row[0].len > 0)
            try writeLabeled(writer, row[0], row[1], inner)
        else blk: {
            const shown = truncateToColumns(row[1], inner);
            try writer.writeAll(shown);
            break :blk utf8DisplayLen(shown);
        };
        for (len..inner) |_| try writer.writeByte(' ');
        try writer.writeAll(border_color);
        try writer.writeAll(constants.VERTICAL);
        try writer.writeAll(terminal.RESET);
        try writer.writeAll("\r\n");
    }
}

fn renderCompact(writer: *std.Io.Writer, width: usize, region: []const u8, credentials: []const u8, border_color: []const u8) !void {
    const inner = width - 2;
    try writer.writeAll(border_color);
    try writer.writeAll(constants.VERTICAL);
    try writer.writeAll(terminal.RESET);
    var written: usize = 0;
    const region_shown = region[0..@min(region.len, inner)];
    try writer.writeAll(region_shown);
    written += region_shown.len;
    if (written + 3 <= inner) {
        try writer.writeAll(" | ");
        written += 3;
        const creds_shown = credentials[0..@min(credentials.len, inner - written)];
        try writer.writeAll(creds_shown);
        written += creds_shown.len;
    }
    for (written..inner) |_| try writer.writeByte(' ');
    try writer.writeAll(border_color);
    try writer.writeAll(constants.VERTICAL);
    try writer.writeAll(terminal.RESET);
    try writer.writeAll("\r\n");
}

fn utf8DisplayLen(s: []const u8) usize {
    var n: usize = 0;
    var i: usize = 0;
    while (i < s.len) {
        const seq_len = std.unicode.utf8ByteSequenceLength(s[i]) catch 1;
        i += seq_len;
        n += 1;
    }
    return n;
}

fn truncateToColumns(s: []const u8, max_cols: usize) []const u8 {
    var n: usize = 0;
    var i: usize = 0;
    while (i < s.len and n < max_cols) {
        const seq_len = std.unicode.utf8ByteSequenceLength(s[i]) catch 1;
        i += seq_len;
        n += 1;
    }
    return s[0..i];
}

fn writeLabeled(writer: *std.Io.Writer, label: []const u8, value: []const u8, max: usize) !usize {
    const prefix = label.len + 2; // "label: "
    if (prefix >= max) {
        const shown = label[0..@min(label.len, max)];
        try writer.writeAll(shown);
        return shown.len;
    }
    const shown = value[0..@min(value.len, max - prefix)];
    try writer.writeAll(label);
    try writer.writeAll(": ");
    try writer.writeAll(shown);
    return prefix + shown.len;
}

fn renderTopLine(writer: *std.Io.Writer, size: i16, border_color: []const u8) !void {
    try writer.writeAll(border_color);
    try writer.writeAll(constants.TOP_LEFT);
    for (0..@as(usize, @intCast(size - 2))) |_| try writer.writeAll(constants.HORIZONTAL);
    try writer.writeAll(constants.TOP_RIGHT);
    try writer.writeAll(terminal.RESET);
    try writer.writeAll("\r\n");
}

// Bottom separator includes a dim "? help" hint on the left.
// Layout: ├─ ? help ──────────────────────────────────────────┤
fn renderBottomLine(writer: *std.Io.Writer, size: i16, border_color: []const u8) !void {
    const inner = @as(usize, @intCast(size - 2));
    const hint = "? help";
    // hint section: "─ " + hint + " " = 1 + 1 + hint.len + 1 = hint.len + 3
    const hint_section = hint.len + 3;

    try writer.writeAll(border_color);
    try writer.writeAll(constants.LEFT_T);

    if (inner > hint_section + 2) {
        try writer.writeAll(constants.HORIZONTAL);
        try writer.writeByte(' ');
        try writer.writeAll(terminal.DIM);
        try writer.writeAll(hint);
        try writer.writeAll(terminal.RESET);
        try writer.writeAll(border_color);
        try writer.writeByte(' ');
        for (0..inner - hint_section) |_| try writer.writeAll(constants.HORIZONTAL);
    } else {
        for (0..inner) |_| try writer.writeAll(constants.HORIZONTAL);
    }

    try writer.writeAll(constants.RIGHT_T);
    try writer.writeAll(terminal.RESET);
    try writer.writeAll("\r\n");
}
