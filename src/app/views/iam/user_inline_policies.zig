const std = @import("std");
const terminal = @import("../../../terminal/terminal.zig");
const Event = @import("../../../event.zig").Event;
const view_mod = @import("../../../ui/view.zig");
const Action = view_mod.Action;
const ViewContext = view_mod.ViewContext;
const Coord = terminal.Coord;
const List = @import("../../../ui/list.zig");
const constants = @import("../../../ui/constants.zig");
const ConfirmView = @import("../../../ui/confirm.zig");
const IamUserInlinePolicyDocumentView = @import("user_inline_policy_document.zig");
const fetcher = @import("../../../sdk/credentials/fetcher.zig");
const Credentials = fetcher.Credentials;

const IamUserInlinePoliciesView = @This();
pub const name: []const u8 = "IAM User Inline Policies";

// ─── View fields ─────────────────────────────────────────────────────────────

fg_color: []const u8,
bg_color: []const u8,
list: List,
pending_g: bool = false,
user_name: []u8,
/// Owned deep copies of the inline policy names (parallel to `list.items`).
names: [][]u8,
io: std.Io,
credentials: Credentials,
alloc: std.mem.Allocator,
breadcrumb_buf: [320]u8 = undefined,
breadcrumb_len: usize = 0,

// ─── Init / deinit ───────────────────────────────────────────────────────────

pub fn init(
    allocator: std.mem.Allocator,
    io: std.Io,
    credentials: Credentials,
    user_name: []const u8,
    policy_names: []const []u8,
    fg_color: []const u8,
    bg_color: []const u8,
    parent_breadcrumb: []const u8,
) !IamUserInlinePoliciesView {
    const user_name_owned = try allocator.dupe(u8, user_name);
    errdefer allocator.free(user_name_owned);

    const names = try allocator.alloc([]u8, policy_names.len);
    errdefer allocator.free(names);
    var copied_names: usize = 0;
    errdefer for (names[0..copied_names]) |n| allocator.free(n);
    for (policy_names, 0..) |n, i| {
        names[i] = try allocator.dupe(u8, n);
        copied_names += 1;
    }

    const display = try allocator.alloc([]const u8, names.len);
    for (names, 0..) |n, i| display[i] = n;

    var view = IamUserInlinePoliciesView{
        .fg_color = fg_color,
        .bg_color = bg_color,
        .list = .{
            .items = display,
            .fg_color = fg_color,
            .bg_color = bg_color,
        },
        .user_name = user_name_owned,
        .names = names,
        .io = io,
        .credentials = credentials,
        .alloc = allocator,
    };
    const bc = std.fmt.bufPrint(&view.breadcrumb_buf, "{s} {s} Inline Policies", .{ parent_breadcrumb, constants.SEP_ARROW }) catch view.breadcrumb_buf[0..0];
    view.breadcrumb_len = bc.len;
    return view;
}

pub fn breadcrumb(self: *IamUserInlinePoliciesView) []const u8 {
    return self.breadcrumb_buf[0..self.breadcrumb_len];
}

pub fn deinit(self: *IamUserInlinePoliciesView) void {
    self.alloc.free(self.list.items);
    for (self.names) |n| self.alloc.free(n);
    self.alloc.free(self.names);
    self.alloc.free(self.user_name);
}

// ─── Event handling ───────────────────────────────────────────────────────────

pub fn handleEvent(self: *IamUserInlinePoliciesView, event: Event, vctx: ViewContext) !Action {
    switch (event) {
        .key => |k| switch (k) {
            .ctrl_c => return .quit,
            .char => |c| switch (c) {
                'q' => return .{ .push = .{ .confirm = ConfirmView.init(self.fg_color, self.bg_color) } },
                'j' => self.list.moveDown(),
                'k' => self.list.moveUp(),
                'g' => {
                    if (self.pending_g) {
                        self.list.selected = 0;
                        self.list.scroll_offset = 0;
                        self.pending_g = false;
                    } else {
                        self.pending_g = true;
                    }
                },
                'G' => {
                    self.pending_g = false;
                    if (self.list.items.len > 0) self.list.selected = self.list.items.len - 1;
                },
                else => self.pending_g = false,
            },
            .down => self.list.moveDown(),
            .up => self.list.moveUp(),
            .enter => {
                if (self.list.items.len == 0) return .none;
                const view = try IamUserInlinePolicyDocumentView.init(
                    vctx.allocator,
                    self.io,
                    self.credentials,
                    self.user_name,
                    self.names[self.list.selected],
                    self.fg_color,
                    self.bg_color,
                    self.breadcrumb(),
                );
                return .{ .push = .{ .iam_user_inline_policy_document = view } };
            },
            .escape => return .pop,
            else => {},
        },
        else => {},
    }
    return .none;
}

// ─── Rendering ───────────────────────────────────────────────────────────────

pub fn render(self: *IamUserInlinePoliciesView, writer: *std.Io.Writer, size: Coord) !void {
    if (size.x < 4 or size.y < 3) return;
    const w: usize = @intCast(size.x);
    const h: usize = @intCast(size.y);

    self.list.updateScroll(if (h >= 1) h - 1 else 0);

    for (0..h) |row| {
        try self.list.renderLine(writer, row + 1, w, h + 1);
        if (row + 1 < h) try writer.writeAll("\r\n");
    }
}
