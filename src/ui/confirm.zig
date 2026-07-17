const std = @import("std");
const terminal = @import("../terminal/terminal.zig");
const constants = @import("constants.zig");
const Event = @import("../event.zig").Event;
const view_mod = @import("view.zig");
const Action = view_mod.Action;
const ViewContext = view_mod.ViewContext;
const Coord = terminal.Coord;

pub const ConfirmView = @This();

fg_color: []const u8,
bg_color: []const u8,
action_idx: usize = 0,

pub fn init(fg_color: []const u8, bg_color: []const u8) ConfirmView {
    return .{
        .fg_color = fg_color,
        .bg_color = bg_color,
    };
}

pub fn breadcrumb(_: *ConfirmView) []const u8 {
    return "Quit?";
}

pub fn deinit(_: *ConfirmView) void {}

pub fn handleEvent(self: *ConfirmView, event: Event, _: ViewContext) !Action {
    switch (event) {
        .key => |k| switch (k) {
            .ctrl_c => return .quit,
            .escape => return .pop,
            .char => |c| switch (c) {
                'q', 'n' => return .pop,
                'y' => return .quit,
                'h' => if (self.action_idx > 0) {
                    self.action_idx -= 1;
                },
                'l' => if (self.action_idx < 1) {
                    self.action_idx += 1;
                },
                else => {},
            },
            .left => if (self.action_idx > 0) {
                self.action_idx -= 1;
            },
            .right => if (self.action_idx < 1) {
                self.action_idx += 1;
            },
            .enter => if (self.action_idx == 1) return .quit else return .pop,
            else => {},
        },
        else => {},
    }
    return .none;
}

pub fn render(self: *ConfirmView, writer: *std.Io.Writer, size: Coord) !void {
    if (size.x < 10 or size.y < 4) return;
    const w: usize = @intCast(size.x);
    const h: usize = @intCast(size.y);
    const inner_w = w - 2;
    // No top border: the header's own bottom line already serves as the
    // top edge of the body area (matches message.zig and the prop/list views).
    // data rows: h - 1 total (leaving 1 row for the bottom border)
    const data_rows: usize = if (h >= 1) h - 1 else 0;

    // Button text
    const no_btn = "[ No ]";
    const yes_btn = "[ Yes ]";
    // With spaces between: "[ No ]  [ Yes ]"
    const gap = "  ";
    const buttons_len = no_btn.len + gap.len + yes_btn.len;

    for (0..data_rows) |row| {
        try writer.writeAll(self.fg_color);
        try writer.writeAll(constants.VERTICAL);
        try writer.writeAll(terminal.RESET);

        if (row == 0) {
            // "Quit the application?"
            const msg = "Quit the application?";
            const shown = msg[0..@min(msg.len, inner_w)];
            try writer.writeByte(' ');
            try writer.writeAll(shown);
            const used: usize = 1 + shown.len;
            for (used..inner_w) |_| try writer.writeByte(' ');
        } else if (data_rows >= 2 and row == data_rows - 2) {
            // Buttons row (second-to-last data row)
            if (inner_w >= buttons_len) {
                const pad = (inner_w - buttons_len) / 2;
                for (0..pad) |_| try writer.writeByte(' ');

                // No button
                if (self.action_idx == 0) {
                    try writer.writeAll(self.bg_color);
                    try writer.writeAll(terminal.FG_BLACK);
                } else {
                    try writer.writeAll(self.fg_color);
                }
                try writer.writeAll(no_btn);
                try writer.writeAll(terminal.RESET);

                try writer.writeAll(gap);

                // Yes button
                if (self.action_idx == 1) {
                    try writer.writeAll(self.bg_color);
                    try writer.writeAll(terminal.FG_BLACK);
                } else {
                    try writer.writeAll(self.fg_color);
                }
                try writer.writeAll(yes_btn);
                try writer.writeAll(terminal.RESET);

                const used = pad + buttons_len;
                for (used..inner_w) |_| try writer.writeByte(' ');
            } else {
                for (0..inner_w) |_| try writer.writeByte(' ');
            }
        } else if (data_rows >= 1 and row == data_rows - 1) {
            // Last data row: dim hint
            const hint = "Enter  Esc";
            if (inner_w >= hint.len) {
                const pad = (inner_w - hint.len) / 2;
                for (0..pad) |_| try writer.writeByte(' ');
                try writer.writeAll(terminal.DIM);
                try writer.writeAll(hint);
                try writer.writeAll(terminal.RESET);
                for (pad + hint.len..inner_w) |_| try writer.writeByte(' ');
            } else {
                for (0..inner_w) |_| try writer.writeByte(' ');
            }
        } else {
            for (0..inner_w) |_| try writer.writeByte(' ');
        }

        try writer.writeAll(self.fg_color);
        try writer.writeAll(constants.VERTICAL);
        try writer.writeAll(terminal.RESET);
        try writer.writeAll("\r\n");
    }

    // Bottom border
    try writer.writeAll(self.fg_color);
    try writer.writeAll(constants.BOTTOM_LEFT);
    for (0..inner_w) |_| try writer.writeAll(constants.HORIZONTAL);
    try writer.writeAll(constants.BOTTOM_RIGHT);
    try writer.writeAll(terminal.RESET);
}
