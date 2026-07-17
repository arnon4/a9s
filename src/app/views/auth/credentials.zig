const std = @import("std");
const terminal = @import("../../../terminal/terminal.zig");
const Event = @import("../../../event.zig").Event;
const view_mod = @import("../../../ui/view.zig");
const Action = view_mod.Action;
const ViewContext = view_mod.ViewContext;
const Coord = terminal.Coord;
const constants = @import("../../../ui/constants.zig");
const fetcher = @import("../../../sdk/credentials/fetcher.zig");

const CredentialsView = @This();
pub const name: []const u8 = "Credentials";

const MAX_FIELD = 256;

pub const TextField = struct {
    buf: [MAX_FIELD]u8 = undefined,
    len: usize = 0,

    pub fn slice(self: *const TextField) []const u8 {
        return self.buf[0..self.len];
    }

    pub fn append(self: *TextField, c: u8) void {
        if (self.len < MAX_FIELD) {
            self.buf[self.len] = c;
            self.len += 1;
        }
    }

    pub fn backspace(self: *TextField) void {
        if (self.len > 0) self.len -= 1;
    }
};

fg_color: []const u8,
bg_color: []const u8,
fields: [3]TextField = .{ .{}, .{}, .{} },
active: usize = 0,

pub fn init(fg_color: []const u8, bg_color: []const u8) CredentialsView {
    return .{ .fg_color = fg_color, .bg_color = bg_color };
}

pub fn breadcrumb(_: *CredentialsView) []const u8 {
    return "Credentials";
}

pub fn deinit(_: *CredentialsView) void {}

pub fn handleEvent(self: *CredentialsView, event: Event, ctx: ViewContext) !Action {
    switch (event) {
        .key => |k| switch (k) {
            .ctrl_c => return .quit,
            .escape => return .pop,
            .up => if (self.active > 0) {
                self.active -= 1;
            },
            .down => if (self.active < 2) {
                self.active += 1;
            },
            .backspace => self.fields[self.active].backspace(),
            .enter => {
                if (self.active < 2) {
                    self.active += 1;
                } else {
                    // Submit
                    const ak = self.fields[0].slice();
                    const sk = self.fields[1].slice();
                    if (ak.len == 0 or sk.len == 0) return .none;

                    const access_key = try ctx.allocator.dupe(u8, ak);
                    errdefer ctx.allocator.free(access_key);
                    const secret_key = try ctx.allocator.dupe(u8, sk);
                    errdefer ctx.allocator.free(secret_key);
                    const st_raw = self.fields[2].slice();
                    const session_token: ?[]const u8 = if (st_raw.len > 0)
                        try ctx.allocator.dupe(u8, st_raw)
                    else
                        null;
                    errdefer if (session_token) |t| ctx.allocator.free(t);
                    const source = try ctx.allocator.dupe(u8, "Manual");
                    errdefer ctx.allocator.free(source);

                    if (ctx.credentials.credentials) |c| c.deinit(ctx.allocator);
                    ctx.credentials.credentials = .{
                        .access_key_id = access_key,
                        .secret_access_key = secret_key,
                        .session_token = session_token,
                        .source = source,
                    };
                    return .pop;
                }
            },
            .char => |c| if (c == '\t') {
                self.active = (self.active + 1) % 3;
            } else if (std.ascii.isPrint(c)) {
                self.fields[self.active].append(c);
            },
            else => {},
        },
        else => {},
    }
    return .none;
}

pub fn render(self: *CredentialsView, writer: *std.Io.Writer, size: Coord) !void {
    if (size.x < 10 or size.y < 6) return;
    const w: usize = @intCast(size.x);
    const h: usize = @intCast(size.y);
    const inner_w = w - 2;

    // Each field group layout (0-indexed content rows):
    //   0: blank
    //   1: label
    //   2: box top
    //   3: box content
    //   4: box bottom
    // field 0: rows 0-4, field 1: rows 5-9, field 2: rows 10-14
    // row 15: blank, row 16: hint, row 17+: blank
    const FIELD_ROW_BLANK = 0;
    const FIELD_ROW_LABEL = 1;
    const FIELD_ROW_BOX_TOP = 2;
    const FIELD_ROW_BOX_CONTENT = 3;
    const FIELD_ROW_BOX_BOTTOM = 4;
    const FIELD_ROWS = 5;

    // field box: 2 chars left margin + borders + 2 chars right margin = inner_w
    // field_box_w = inner_w - 4
    // field inner visible = field_box_w - 4  (│ space ... space │)
    const field_box_w: usize = if (inner_w >= 4) inner_w - 4 else 0;
    const field_vis: usize = if (field_box_w >= 4) field_box_w - 4 else 0;

    const labels = [3][]const u8{
        "Access Key ID",
        "Secret Access Key",
        "Session Token (optional)",
    };

    const data_rows = if (h >= 1) h - 1 else 0;

    for (0..data_rows) |row| {
        try writer.writeAll(self.fg_color);
        try writer.writeAll(constants.VERTICAL);
        try writer.writeAll(terminal.RESET);

        const fi = row / FIELD_ROWS; // field index
        const fr = row % FIELD_ROWS; // row within field group

        if (fi < 3) {
            const is_active = fi == self.active;
            switch (fr) {
                FIELD_ROW_BLANK => {
                    for (0..inner_w) |_| try writer.writeByte(' ');
                },
                FIELD_ROW_LABEL => {
                    try writer.writeAll("  ");
                    if (is_active) {
                        try writer.writeAll(self.fg_color);
                        try writer.writeAll(terminal.BOLD);
                    }
                    const lbl = labels[fi];
                    const shown = lbl[0..@min(lbl.len, inner_w -| 2)];
                    try writer.writeAll(shown);
                    try writer.writeAll(terminal.RESET);
                    for (shown.len + 2..inner_w) |_| try writer.writeByte(' ');
                },
                FIELD_ROW_BOX_TOP => {
                    try writer.writeAll("  ");
                    if (is_active) try writer.writeAll(self.fg_color);
                    try writer.writeAll(constants.TOP_LEFT);
                    for (0..field_box_w -| 2) |_| try writer.writeAll(constants.HORIZONTAL);
                    try writer.writeAll(constants.TOP_RIGHT);
                    if (is_active) try writer.writeAll(terminal.RESET);
                    try writer.writeAll("  ");
                },
                FIELD_ROW_BOX_CONTENT => {
                    const mask = fi == 1;
                    try writer.writeAll("  ");
                    if (is_active) try writer.writeAll(self.fg_color);
                    try writer.writeAll(constants.VERTICAL);
                    if (!is_active) try writer.writeAll(terminal.RESET);
                    try writer.writeAll(" ");
                    const field = &self.fields[fi];
                    const content_len = @min(field.len, field_vis);
                    if (mask) {
                        for (0..content_len) |_| try writer.writeByte('*');
                    } else {
                        try writer.writeAll(field.buf[0..content_len]);
                    }
                    if (is_active) {
                        // cursor
                        try writer.writeByte('_');
                        for (content_len + 1..field_vis) |_| try writer.writeByte(' ');
                    } else {
                        for (content_len..field_vis) |_| try writer.writeByte(' ');
                    }
                    try writer.writeByte(' ');
                    if (is_active) try writer.writeAll(self.fg_color);
                    try writer.writeAll(constants.VERTICAL);
                    if (is_active) try writer.writeAll(terminal.RESET);
                    try writer.writeAll("  ");
                },
                FIELD_ROW_BOX_BOTTOM => {
                    try writer.writeAll("  ");
                    if (is_active) try writer.writeAll(self.fg_color);
                    try writer.writeAll(constants.BOTTOM_LEFT);
                    for (0..field_box_w -| 2) |_| try writer.writeAll(constants.HORIZONTAL);
                    try writer.writeAll(constants.BOTTOM_RIGHT);
                    if (is_active) try writer.writeAll(terminal.RESET);
                    try writer.writeAll("  ");
                },
                else => unreachable,
            }
        } else {
            // rows after the 3 field groups
            const after = row - 3 * FIELD_ROWS;
            if (after == 1) {
                // hint row
                const hint = "↑↓/Tab navigate   Enter submit   Esc back";
                // ↑ and ↓ are 3 UTF-8 bytes each but 1 display column each
                const hint_display_w = hint.len - 4;
                if (inner_w >= hint_display_w) {
                    const pad = (inner_w - hint_display_w) / 2;
                    for (0..pad) |_| try writer.writeByte(' ');
                    try writer.writeAll(terminal.DIM);
                    try writer.writeAll(hint);
                    try writer.writeAll(terminal.RESET);
                    for (pad + hint_display_w..inner_w) |_| try writer.writeByte(' ');
                } else {
                    for (0..inner_w) |_| try writer.writeByte(' ');
                }
            } else {
                for (0..inner_w) |_| try writer.writeByte(' ');
            }
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

// ============================================================================
// Tests
// ============================================================================

test "TextField append and slice" {
    var f: TextField = .{};
    f.append('a');
    f.append('b');
    f.append('c');
    try std.testing.expectEqualStrings("abc", f.slice());
}

test "TextField backspace" {
    var f: TextField = .{};
    f.append('x');
    f.append('y');
    f.backspace();
    try std.testing.expectEqualStrings("x", f.slice());
}

test "TextField backspace empty" {
    var f: TextField = .{};
    f.backspace();
    try std.testing.expectEqual(@as(usize, 0), f.len);
}

test "TextField max capacity" {
    var f: TextField = .{};
    for (0..300) |i| f.append(@intCast(i % 128));
    try std.testing.expectEqual(@as(usize, MAX_FIELD), f.len);
}
