const std = @import("std");
const terminal = @import("../../terminal/terminal.zig");
const constants = @import("../../ui/constants.zig");
const Event = @import("../../event.zig").Event;
const view_mod = @import("../../ui/view.zig");
const Action = view_mod.Action;
const ViewContext = view_mod.ViewContext;
const Coord = terminal.Coord;
const ConfirmView = @import("../../ui/confirm.zig");

pub const HelpView = @This();

pub const Topic = enum { general, profile, filter, sort, region };

fg_color: []const u8,
bg_color: []const u8,
topic: Topic,
scroll: usize = 0,

pub fn init(fg_color: []const u8, bg_color: []const u8, topic: Topic) HelpView {
    return .{ .fg_color = fg_color, .bg_color = bg_color, .topic = topic };
}

pub fn breadcrumb(self: *HelpView) []const u8 {
    return switch (self.topic) {
        .general => "Help",
        .profile => "Help: profile",
        .filter => "Help: filter",
        .sort => "Help: sort",
        .region => "Help: region",
    };
}

pub fn deinit(_: *HelpView) void {}

pub fn handleEvent(self: *HelpView, event: Event, _: ViewContext) !Action {
    const lines = topicLines(self.topic);
    switch (event) {
        .key => |k| switch (k) {
            .ctrl_c => return .quit,
            .escape, .enter => return .pop,
            .char => |c| switch (c) {
                'q' => return .{ .push = .{ .confirm = ConfirmView.init(self.fg_color, self.bg_color) } },
                '?' => return .pop,
                'j' => if (self.scroll + 1 < lines.len) {
                    self.scroll += 1;
                },
                'k' => if (self.scroll > 0) {
                    self.scroll -= 1;
                },
                else => {},
            },
            .down => if (self.scroll + 1 < lines.len) {
                self.scroll += 1;
            },
            .up => if (self.scroll > 0) {
                self.scroll -= 1;
            },
            else => {},
        },
        else => {},
    }
    return .none;
}

// Lines with no leading space are rendered as bold section headings.
// Lines with leading spaces are rendered as normal body text.

const GENERAL_LINES = [_][]const u8{
    "Keybinds",
    "  j (↑) / k (↓)     move down / up",
    "  h (←) / l (→)     move left / right",
    "  gg                go to top",
    "  G                 go to bottom",
    "  r                 refresh (supported views)",
    "  Enter             select / open",
    "  Esc               go back",
    "  q                 quit",
    "  :                 open command mode",
    "  /                 search (supported views)",
    "  ?                 this help screen",
    "",
    "Commands",
    "  :filter <expr>    filter current list by field expression",
    "  :filter           clear active filter",
    "  :profile <sub>    manage AWS credential profiles",
    "  :sort [fields]    sort list ascending by field(s)",
    "  :sort-desc        sort list descending",
    "  :help [topic]     show help for a topic",
    "  :region <sub>     manage active AWS regions",
    "  :goto <view>      jump to a top-level view (s3, lambda, logs, iam)",
    "",
    "Help topics",
    "  :help filter      filter syntax and operators",
    "  :help profile     profile subcommands",
    "  :help sort        sort fields and usage",
    "  :help region      region subcommands",
};

const PROFILE_LINES = [_][]const u8{
    ":profile — manage AWS credential profiles",
    "",
    "Subcommands",
    "  add <name>       activate a named profile",
    "  use <name>       replace all active profiles",
    "  remove <name>    deactivate a profile",
    "  show             list currently active profiles",
    "  logout <name>    clear SSO token for a profile",
    "  logout-all       clear all SSO tokens",
    "",
    "Multiple profiles",
    "  :profile add staging prod",
    "  :profile use default staging",
};

const FILTER_LINES = [_][]const u8{
    ":filter <expr>   apply filter to current list",
    ":filter          clear filter",
    "",
    "Available fields depend on the current view.",
    "",
    "Operators",
    "  eq             equal",
    "  gt  gte        greater than (or equal)",
    "  lt  lte        less than (or equal)",
    "  contains       substring match",
    "  beginswith     prefix match",
    "  endswith       suffix match",
    "  in [a, b]      value in list",
    "",
    "Logic",
    "  and  or  not  (...)",
    "  field not <op> value   (inline negation)",
    "",
    "Size values: 1K  1M  1G  1T  (or KB/MB/GB/TB)",
    "",
    "Examples",
    "  name contains prod",
    "  size gt 1G",
    "  region eq us-east-1",
    "  region in [us-east-1, eu-west-1]",
    "  size gt 1G and name beginswith my",
    "  not (region eq us-east-1)",
};

const SORT_LINES = [_][]const u8{
    ":sort [field ...]        sort ascending",
    ":sort-desc [field ...]   sort descending",
    "",
    "Available fields depend on the current view.",
    "",
    "Multiple fields",
    "  :sort name region",
    "  :sort-desc size name",
};

const REGION_LINES = [_][]const u8{
    ":region — manage active AWS regions",
    "",
    "Subcommands",
    "  add <region> [...]     add regions to the active list",
    "  remove <region> [...]  remove regions from the active list",
    "  use <region> [...]     replace the active region list",
    "  show                   list currently active regions",
    "",
    "Examples",
    "  :region use us-east-1",
    "  :region add eu-west-1 ap-southeast-1",
    "  :region remove us-west-2",
    "",
    "Notes",
    "  S3 always uses the global endpoint (unaffected).",
    "  At least one region is always kept active.",
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

fn topicLines(topic: Topic) []const []const u8 {
    return switch (topic) {
        .general => &GENERAL_LINES,
        .profile => &PROFILE_LINES,
        .filter => &FILTER_LINES,
        .sort => &SORT_LINES,
        .region => &REGION_LINES,
    };
}

pub fn render(self: *HelpView, writer: *std.Io.Writer, size: Coord) !void {
    if (size.x < 4 or size.y < 2) return;
    const w: usize = @intCast(size.x);
    const h: usize = @intCast(size.y);
    const inner_w = w - 2;
    const data_rows = h - 1;

    const lines = topicLines(self.topic);

    // Clamp scroll so we never show blank space below last line.
    if (lines.len > 0 and self.scroll >= lines.len) self.scroll = lines.len - 1;

    const show_scroll_hint = lines.len > data_rows;

    var rendered: usize = 0;
    var src: usize = self.scroll;
    while (rendered < data_rows) : (rendered += 1) {
        try writer.writeAll(self.fg_color);
        try writer.writeAll(constants.VERTICAL);
        try writer.writeAll(terminal.RESET);

        if (src < lines.len) {
            const line = lines[src];
            src += 1;

            if (line.len == 0) {
                // blank line
                for (0..inner_w) |_| try writer.writeByte(' ');
            } else if (line[0] != ' ') {
                // section heading: bold + fg color
                const budget = if (inner_w > 0) inner_w else 0;
                const end = utf8FitBytes(line, budget);
                const shown = line[0..end];
                const shown_cols = utf8Cols(shown);
                try writer.writeAll(terminal.BOLD);
                try writer.writeAll(self.fg_color);
                try writer.writeAll(shown);
                try writer.writeAll(terminal.RESET);
                for (shown_cols..inner_w) |_| try writer.writeByte(' ');
            } else {
                // body line: dim leading spaces, normal rest
                const trimmed = std.mem.trimStart(u8, line, " ");
                const indent = line.len - trimmed.len;
                const budget = if (inner_w > 0) inner_w else 0;
                const shown_indent = @min(indent, budget);
                const body_end = utf8FitBytes(trimmed, if (budget > shown_indent) budget - shown_indent else 0);
                const shown_body = trimmed[0..body_end];
                const shown_body_cols = utf8Cols(shown_body);
                try writer.writeAll(terminal.DIM);
                for (0..shown_indent) |_| try writer.writeByte(' ');
                try writer.writeAll(terminal.RESET);
                try writer.writeAll(shown_body);
                const used = shown_indent + shown_body_cols;
                for (used..inner_w) |_| try writer.writeByte(' ');
            }
        } else if (show_scroll_hint and rendered == data_rows - 1) {
            // last row: scroll hint
            const hint = "j/k to scroll";
            const pad = if (inner_w > hint.len) (inner_w - hint.len) / 2 else 0;
            for (0..pad) |_| try writer.writeByte(' ');
            try writer.writeAll(terminal.DIM);
            try writer.writeAll(hint[0..@min(hint.len, inner_w)]);
            try writer.writeAll(terminal.RESET);
            const used = pad + @min(hint.len, inner_w);
            for (used..inner_w) |_| try writer.writeByte(' ');
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
