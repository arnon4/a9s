//! Bordered table over rows that are already in memory: header, selectable rows,
//! scrolling, columns that drop out on narrow terminals, and the same text filter,
//! `:filter` expression and `:sort` commands as the list views. The caller owns the
//! cell text and the table state; this module draws, filters, sorts and moves.
const std = @import("std");
const Allocator = std.mem.Allocator;
const terminal = @import("../terminal/terminal.zig");
const constants = @import("constants.zig");
const filter_mod = @import("../commands/filter.zig");
const Coord = terminal.Coord;

pub const Column = struct {
    title: []const u8,
    /// Name used by `:filter` expressions and `:sort`.
    key: []const u8,
    /// Optional second name for the same column.
    alias: []const u8 = "",
    /// Compare as a number (filter and sort). Text that is not a number sorts last.
    numeric: bool = false,
    /// Fixed width including one space of padding on each side. Ignored for the flex column.
    width: usize,
    /// The column is dropped when the terminal is narrower than this.
    min_term_width: i16 = 0,
};

pub const Spec = struct {
    columns: []const Column,
    /// Index of the column that takes the remaining width. Always shown.
    flex: usize,
};

/// Column index for a `:sort` / `:filter` name, or null.
pub fn columnIndex(spec: Spec, name: []const u8) ?usize {
    for (spec.columns, 0..) |c, i| {
        if (std.ascii.eqlIgnoreCase(c.key, name)) return i;
        if (c.alias.len > 0 and std.ascii.eqlIgnoreCase(c.alias, name)) return i;
    }
    return null;
}

fn numericValue(text: []const u8) u64 {
    return std.fmt.parseInt(u64, text, 10) catch std.math.maxInt(u64);
}

const Resolver = struct {
    spec: Spec,
    cells: []const []const u8,
    row: usize,

    pub fn resolve(self: Resolver, field: []const u8) filter_mod.FieldValue {
        const ci = columnIndex(self.spec, field) orelse return .unknown;
        const text = self.cells[self.row * self.spec.columns.len + ci];
        if (self.spec.columns[ci].numeric) return .{ .bytes = numericValue(text) };
        return .{ .string = text };
    }
};

const SortCtx = struct {
    spec: Spec,
    cells: []const []const u8,
    cols: []const usize,
    dir: constants.SortDir,

    fn lessThan(ctx: SortCtx, a: usize, b: usize) bool {
        const n = ctx.spec.columns.len;
        for (ctx.cols) |ci| {
            const x = ctx.cells[a * n + ci];
            const y = ctx.cells[b * n + ci];
            const ord = if (ctx.spec.columns[ci].numeric)
                std.math.order(numericValue(x), numericValue(y))
            else
                std.mem.order(u8, x, y);
            if (ord != .eq) return if (ctx.dir == .asc) ord == .lt else ord == .gt;
        }
        return a < b;
    }
};

pub const State = struct {
    alloc: Allocator,
    selected: usize = 0,
    scroll: usize = 0,
    pending_g: bool = false,
    /// Borrowed from the app while the user is typing a `/` filter.
    live_filter: []const u8 = "",
    committed_filter: ?[]u8 = null,
    filter_expr: ?filter_mod.ParseResult = null,
    sort_cols: [3]usize = .{ 0, 0, 0 },
    sort_len: usize = 0,
    sort_dir: constants.SortDir = .asc,
    /// Original row indices that pass the filter, in display order.
    order: []usize = &.{},
    dirty: bool = true,
    cached_total: usize = 0,

    pub fn init(alloc: Allocator) State {
        return .{ .alloc = alloc };
    }

    pub fn deinit(self: *State) void {
        if (self.committed_filter) |f| self.alloc.free(f);
        if (self.filter_expr) |*fe| fe.deinit();
        if (self.order.len > 0) self.alloc.free(self.order);
    }

    fn reset(self: *State) void {
        self.selected = 0;
        self.scroll = 0;
        self.dirty = true;
    }

    // ─── Filter ──────────────────────────────────────────────────────────────

    pub fn setLiveFilter(self: *State, text: []const u8) void {
        if (!std.mem.eql(u8, self.live_filter, text)) self.reset();
        self.live_filter = text;
    }

    pub fn commitFilter(self: *State, text: []const u8) void {
        if (self.committed_filter) |f| self.alloc.free(f);
        self.committed_filter = if (text.len == 0) null else self.alloc.dupe(u8, text) catch null;
        self.live_filter = "";
        self.reset();
    }

    pub fn setFilterExpr(self: *State, result: filter_mod.ParseResult) void {
        if (self.filter_expr) |*fe| fe.deinit();
        self.filter_expr = result;
        self.reset();
    }

    pub fn clearFilterExpr(self: *State) void {
        if (self.filter_expr) |*fe| fe.deinit();
        self.filter_expr = null;
        self.reset();
    }

    fn effectiveFilter(self: *const State) []const u8 {
        return if (self.live_filter.len > 0) self.live_filter else self.committed_filter orelse "";
    }

    // ─── Sort ────────────────────────────────────────────────────────────────

    /// Sorts by up to three column indices; ties keep the original order.
    pub fn setSort(self: *State, columns: []const usize, dir: constants.SortDir) void {
        const n = @min(columns.len, self.sort_cols.len);
        if (n == 0) return;
        @memcpy(self.sort_cols[0..n], columns[0..n]);
        self.sort_len = n;
        self.sort_dir = dir;
        self.reset();
    }

    pub fn clearSort(self: *State) void {
        self.sort_len = 0;
        self.sort_dir = .asc;
        self.reset();
    }

    /// Escape: drops the committed filter, then the expression, then the sort.
    /// Returns false when there was nothing to clear, so the caller can go back.
    pub fn clearOne(self: *State) bool {
        if (self.committed_filter) |f| {
            self.alloc.free(f);
            self.committed_filter = null;
            self.reset();
            return true;
        }
        if (self.filter_expr != null) {
            self.clearFilterExpr();
            return true;
        }
        if (self.sort_len > 0) {
            self.clearSort();
            return true;
        }
        return false;
    }

    // ─── Rows ────────────────────────────────────────────────────────────────

    fn rowMatches(self: *const State, spec: Spec, cells: []const []const u8, row: usize, text: []const u8) bool {
        const n = spec.columns.len;
        if (text.len > 0) {
            const any = for (cells[row * n ..][0..n]) |c| {
                if (filter_mod.matchesText(c, text)) break true;
            } else false;
            if (!any) return false;
        }
        if (self.filter_expr) |*fe| {
            if (!filter_mod.evalExpr(fe.expr, Resolver{ .spec = spec, .cells = cells, .row = row })) return false;
        }
        return true;
    }

    /// Original row indices to show, filtered and sorted. Valid until the next change.
    pub fn visible(self: *State, spec: Spec, cells: []const []const u8) []const usize {
        const n = spec.columns.len;
        const total = if (n > 0) cells.len / n else 0;
        if (!self.dirty and self.cached_total == total) return self.order;

        if (self.order.len > 0) self.alloc.free(self.order);
        self.order = &.{};
        self.dirty = false;
        self.cached_total = total;

        var rows: std.ArrayList(usize) = .empty;
        const text = self.effectiveFilter();
        for (0..total) |r| {
            if (!self.rowMatches(spec, cells, r, text)) continue;
            rows.append(self.alloc, r) catch {
                rows.deinit(self.alloc);
                return self.order;
            };
        }
        if (self.sort_len > 0) {
            std.mem.sortUnstable(usize, rows.items, SortCtx{
                .spec = spec,
                .cells = cells,
                .cols = self.sort_cols[0..self.sort_len],
                .dir = self.sort_dir,
            }, SortCtx.lessThan);
        }
        self.order = rows.toOwnedSlice(self.alloc) catch {
            rows.deinit(self.alloc);
            return self.order;
        };
        return self.order;
    }

    /// Original row index of the selected visible row.
    pub fn selectedRow(self: *State, spec: Spec, cells: []const []const u8) ?usize {
        const rows = self.visible(spec, cells);
        if (self.selected >= rows.len) return null;
        return rows[self.selected];
    }

    // ─── Movement ────────────────────────────────────────────────────────────

    pub fn moveDown(self: *State, rows: usize) void {
        self.pending_g = false;
        if (rows > 0 and self.selected < rows - 1) self.selected += 1;
    }

    pub fn moveUp(self: *State) void {
        self.pending_g = false;
        if (self.selected > 0) self.selected -= 1;
    }

    pub fn top(self: *State) void {
        self.pending_g = false;
        self.selected = 0;
        self.scroll = 0;
    }

    pub fn bottom(self: *State, rows: usize) void {
        self.pending_g = false;
        if (rows > 0) self.selected = rows - 1;
    }

    /// Handles j, k, g (twice for top) and G. Returns true when the key was consumed.
    pub fn handleChar(self: *State, c: u8, rows: usize) bool {
        switch (c) {
            'j' => self.moveDown(rows),
            'k' => self.moveUp(),
            'g' => {
                if (self.pending_g) self.top() else self.pending_g = true;
            },
            'G' => self.bottom(rows),
            else => {
                self.pending_g = false;
                return false;
            },
        }
        return true;
    }
};

// ─── Drawing ─────────────────────────────────────────────────────────────────

fn cpLen(b: u8) usize {
    return if (b < 0x80) 1 else if (b < 0xE0) 2 else if (b < 0xF0) 3 else 4;
}

fn cols(text: []const u8) usize {
    var n: usize = 0;
    var i: usize = 0;
    while (i < text.len) : (n += 1) i += cpLen(text[i]);
    return n;
}

/// Longest prefix of `text` that fits in `max` columns.
fn fit(text: []const u8, max: usize) []const u8 {
    var n: usize = 0;
    var i: usize = 0;
    while (i < text.len and n < max) : (n += 1) i = @min(i + cpLen(text[i]), text.len);
    return text[0..i];
}

const Layout = struct {
    /// Indices of the visible columns, in order.
    visible: [16]usize = undefined,
    count: usize = 0,
    widths: [16]usize = undefined,
};

fn layout(spec: Spec, term_w: i16, inner: usize) Layout {
    var l: Layout = .{};
    var fixed: usize = 0;
    for (spec.columns, 0..) |c, i| {
        if (l.count >= l.visible.len) break;
        if (i != spec.flex and term_w < c.min_term_width) continue;
        l.visible[l.count] = i;
        if (i != spec.flex) fixed += c.width;
        l.count += 1;
    }
    const separators = if (l.count > 0) l.count - 1 else 0;
    const flex_w = if (inner > fixed + separators + 4) inner - fixed - separators else 4;
    for (l.visible[0..l.count], 0..) |ci, k| {
        l.widths[k] = if (ci == spec.flex) flex_w else spec.columns[ci].width;
    }
    return l;
}

fn writePadded(writer: *std.Io.Writer, text: []const u8, width: usize, marker: []const u8) !void {
    const content_w = if (width >= 2) width - 2 else 0;
    try writer.writeByte(' ');
    var avail = content_w;
    if (marker.len > 0 and avail >= 2) {
        try writer.writeAll(marker);
        avail -= 2;
    }
    const shown = fit(text, avail);
    try writer.writeAll(shown);
    for (cols(shown)..avail) |_| try writer.writeByte(' ');
    try writer.writeByte(' ');
}

fn writeHeaderCell(writer: *std.Io.Writer, text: []const u8, width: usize, bg: []const u8) !void {
    const content_w = if (width >= 2) width - 2 else 0;
    const shown = fit(text, content_w);
    const pad = content_w - cols(shown);
    const left = pad / 2;
    try writer.writeByte(' ');
    try writer.writeAll(bg);
    try writer.writeAll(terminal.FG_BLACK);
    for (0..left) |_| try writer.writeByte(' ');
    try writer.writeAll(shown);
    for (0..pad - left) |_| try writer.writeByte(' ');
    try writer.writeAll(terminal.RESET);
    try writer.writeByte(' ');
}

fn writeSep(writer: *std.Io.Writer, l: Layout, fg: []const u8, bottom: bool) !void {
    const left = if (bottom) constants.BOTTOM_LEFT else constants.LEFT_T;
    const mid = if (bottom) constants.BOTTOM_T else constants.CROSS;
    const right = if (bottom) constants.BOTTOM_RIGHT else constants.RIGHT_T;
    try writer.writeAll(fg);
    try writer.writeAll(left);
    for (l.widths[0..l.count], 0..) |w, k| {
        if (k > 0) try writer.writeAll(mid);
        for (0..w) |_| try writer.writeAll(constants.HORIZONTAL);
    }
    try writer.writeAll(right);
    try writer.writeAll(terminal.RESET);
}

/// Draws the visible rows of `cells` (row-major, `spec.columns.len` per row). `size.y` includes
/// the bottom border row; no newline is written after it.
pub fn render(
    writer: *std.Io.Writer,
    size: Coord,
    fg: []const u8,
    bg: []const u8,
    spec: Spec,
    cells: []const []const u8,
    state: *State,
) !void {
    if (size.x < 10 or size.y < 4) return;
    const w: usize = @intCast(size.x);
    const h: usize = @intCast(size.y);
    const ncols = spec.columns.len;
    const rows = state.visible(spec, cells);
    const l = layout(spec, size.x, w - 2);
    const show_header = h >= 6;
    const data_rows = if (show_header) h - 3 else h - 1;

    if (show_header) {
        try writer.writeAll(fg);
        try writer.writeAll(constants.VERTICAL);
        try writer.writeAll(terminal.RESET);
        for (l.visible[0..l.count], 0..) |ci, k| {
            if (k > 0) {
                try writer.writeAll(fg);
                try writer.writeAll(constants.VERTICAL);
                try writer.writeAll(terminal.RESET);
            }
            try writeHeaderCell(writer, spec.columns[ci].title, l.widths[k], bg);
        }
        try writer.writeAll(fg);
        try writer.writeAll(constants.VERTICAL);
        try writer.writeAll(terminal.RESET);
        try writer.writeAll("\r\n");
        try writeSep(writer, l, fg, false);
        try writer.writeAll("\r\n");
    }

    if (rows.len > 0) {
        if (state.selected >= rows.len) state.selected = rows.len - 1;
        if (state.selected < state.scroll) state.scroll = state.selected;
        if (data_rows > 0 and state.selected >= state.scroll + data_rows) state.scroll = state.selected - data_rows + 1;
    } else {
        state.selected = 0;
        state.scroll = 0;
    }

    var rendered: usize = 0;
    var v = state.scroll;
    while (v < rows.len and rendered < data_rows) : (v += 1) {
        const r = rows[v];
        const sel = v == state.selected;
        if (sel) {
            try writer.writeAll(bg);
            try writer.writeAll(terminal.FG_BLACK);
        } else {
            try writer.writeAll(fg);
        }
        try writer.writeAll(constants.VERTICAL);
        if (!sel) try writer.writeAll(terminal.RESET);
        for (l.visible[0..l.count], 0..) |ci, k| {
            if (k > 0) {
                if (!sel) try writer.writeAll(fg);
                try writer.writeAll(constants.VERTICAL);
                if (!sel) try writer.writeAll(terminal.RESET);
            }
            const marker: []const u8 = if (k == 0 and sel) "▸ " else if (k == 0) "  " else "";
            try writePadded(writer, cells[r * ncols + ci], l.widths[k], marker);
        }
        if (!sel) try writer.writeAll(fg);
        try writer.writeAll(constants.VERTICAL);
        try writer.writeAll(terminal.RESET);
        try writer.writeAll("\r\n");
        rendered += 1;
    }
    for (rendered..data_rows) |_| {
        try writer.writeAll(fg);
        try writer.writeAll(constants.VERTICAL);
        try writer.writeAll(terminal.RESET);
        for (l.widths[0..l.count], 0..) |cw, k| {
            if (k > 0) {
                try writer.writeAll(fg);
                try writer.writeAll(constants.VERTICAL);
                try writer.writeAll(terminal.RESET);
            }
            for (0..cw) |_| try writer.writeByte(' ');
        }
        try writer.writeAll(fg);
        try writer.writeAll(constants.VERTICAL);
        try writer.writeAll(terminal.RESET);
        try writer.writeAll("\r\n");
    }

    try writeSep(writer, l, fg, true);
}

// ============================================================================
// Tests
// ============================================================================

const test_spec: Spec = .{
    .flex = 1,
    .columns = &.{
        .{ .title = "N", .key = "n", .numeric = true, .width = 6 },
        .{ .title = "Name", .key = "name", .alias = "label", .width = 0 },
        .{ .title = "Kind", .key = "kind", .width = 8, .min_term_width = 100 },
    },
};

// Rows: (10, "beta", "x"), (2, "alpha", "y"), (*, "gamma", "x")
const test_cells = [_][]const u8{ "10", "beta", "x", "2", "alpha", "y", "*", "gamma", "x" };

test "fit and cols count codepoints" {
    try std.testing.expectEqualStrings("ab", fit("abc", 2));
    try std.testing.expectEqualStrings("─✓", fit("─✓▶", 2));
    try std.testing.expectEqual(@as(usize, 3), cols("─✓▶"));
}

test "layout drops narrow columns and gives the rest to flex" {
    const narrow = layout(test_spec, 80, 78);
    try std.testing.expectEqual(@as(usize, 2), narrow.count);
    try std.testing.expectEqual(@as(usize, 78 - 6 - 1), narrow.widths[1]);

    const wide = layout(test_spec, 120, 118);
    try std.testing.expectEqual(@as(usize, 3), wide.count);
    try std.testing.expectEqual(@as(usize, 118 - 14 - 2), wide.widths[1]);
}

test "columnIndex matches key and alias case-insensitively" {
    try std.testing.expectEqual(@as(?usize, 1), columnIndex(test_spec, "NAME"));
    try std.testing.expectEqual(@as(?usize, 1), columnIndex(test_spec, "label"));
    try std.testing.expectEqual(@as(?usize, null), columnIndex(test_spec, "nope"));
}

test "state navigation clamps and g g goes to top" {
    var s: State = .init(std.testing.allocator);
    defer s.deinit();
    _ = s.handleChar('j', 3);
    _ = s.handleChar('j', 3);
    _ = s.handleChar('j', 3);
    try std.testing.expectEqual(@as(usize, 2), s.selected);
    _ = s.handleChar('g', 3);
    try std.testing.expect(s.pending_g);
    _ = s.handleChar('g', 3);
    try std.testing.expectEqual(@as(usize, 0), s.selected);
    _ = s.handleChar('G', 3);
    try std.testing.expectEqual(@as(usize, 2), s.selected);
    try std.testing.expect(!s.handleChar('x', 3));
}

test "text filter matches any cell" {
    var s: State = .init(std.testing.allocator);
    defer s.deinit();
    s.setLiveFilter("ALP");
    const rows = s.visible(test_spec, &test_cells);
    try std.testing.expectEqual(@as(usize, 1), rows.len);
    try std.testing.expectEqual(@as(usize, 1), rows[0]);

    s.setLiveFilter("x");
    try std.testing.expectEqual(@as(usize, 2), s.visible(test_spec, &test_cells).len);
}

test "numeric sort orders by value and puts non-numbers last" {
    var s: State = .init(std.testing.allocator);
    defer s.deinit();
    s.setSort(&.{0}, .asc);
    var rows = s.visible(test_spec, &test_cells);
    try std.testing.expectEqualSlices(usize, &.{ 1, 0, 2 }, rows);

    s.setSort(&.{0}, .desc);
    rows = s.visible(test_spec, &test_cells);
    try std.testing.expectEqualSlices(usize, &.{ 2, 0, 1 }, rows);
}

test "text sort and selectedRow map to original rows" {
    var s: State = .init(std.testing.allocator);
    defer s.deinit();
    s.setSort(&.{1}, .asc);
    try std.testing.expectEqual(@as(?usize, 1), s.selectedRow(test_spec, &test_cells));
    s.moveDown(3);
    try std.testing.expectEqual(@as(?usize, 0), s.selectedRow(test_spec, &test_cells));
}

test "filter expression uses column keys" {
    var s: State = .init(std.testing.allocator);
    defer s.deinit();
    const parsed = try filter_mod.parse(std.testing.allocator, "kind eq y");
    s.setFilterExpr(parsed);
    const rows = s.visible(test_spec, &test_cells);
    try std.testing.expectEqual(@as(usize, 1), rows.len);
    try std.testing.expectEqual(@as(usize, 1), rows[0]);
}

test "numeric filter compares values" {
    var s: State = .init(std.testing.allocator);
    defer s.deinit();
    const parsed = try filter_mod.parse(std.testing.allocator, "n gt 5");
    s.setFilterExpr(parsed);
    // 10 passes; the non-numeric "*" counts as largest and passes too; 2 does not.
    try std.testing.expectEqual(@as(usize, 2), s.visible(test_spec, &test_cells).len);
}

test "clearOne drops filter, then expression, then sort" {
    var s: State = .init(std.testing.allocator);
    defer s.deinit();
    s.commitFilter("a");
    s.setSort(&.{0}, .asc);
    try std.testing.expect(s.clearOne());
    try std.testing.expect(s.committed_filter == null);
    try std.testing.expectEqual(@as(usize, 1), s.sort_len);
    try std.testing.expect(s.clearOne());
    try std.testing.expectEqual(@as(usize, 0), s.sort_len);
    try std.testing.expect(!s.clearOne());
}
