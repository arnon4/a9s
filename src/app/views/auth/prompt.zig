const std = @import("std");
const terminal = @import("../../../terminal/terminal.zig");
const colors_mod = @import("../../../ui/colors.zig");
const Event = @import("../../../event.zig").Event;
const view_mod = @import("../../../ui/view.zig");
const Action = view_mod.Action;
const ViewContext = view_mod.ViewContext;
const Coord = terminal.Coord;
const ConfirmView = @import("../../../ui/confirm.zig");
const List = @import("../../../ui/list.zig");
const SSOProfileView = @import("sso_profile.zig");
const CredentialsView = @import("credentials.zig");

const AuthPromptView = @This();
pub const name: []const u8 = "Authenticate";

const items = [_][]const u8{ "SSO Profile", "Inline Credentials" };

fg_color: []const u8,
bg_color: []const u8,
list: List,

pub fn init(color_support: terminal.ColorSupport) AuthPromptView {
    const colors = colors_mod.orange(color_support);
    const fg_color = colors.fg;
    const bg_color = colors.bg;
    return .{
        .fg_color = fg_color,
        .bg_color = bg_color,
        .list = .{
            .items = &items,
            .fg_color = fg_color,
            .bg_color = bg_color,
        },
    };
}

pub fn breadcrumb(_: *AuthPromptView) []const u8 {
    return "Authenticate";
}

pub fn deinit(_: *AuthPromptView) void {}

pub fn handleEvent(self: *AuthPromptView, event: Event, ctx: ViewContext) !Action {
    // Auto-dismiss once credentials are available (user just finished auth)
    if (ctx.credentials.credentials != null) return .pop;

    switch (event) {
        .key => |k| switch (k) {
            .ctrl_c => return .quit,
            .escape => return .pop,
            .char => |c| switch (c) {
                'q' => return .{ .push = .{ .confirm = ConfirmView.init(self.fg_color, self.bg_color) } },
                'j' => self.list.moveDown(),
                'k' => self.list.moveUp(),
                else => {},
            },
            .down => self.list.moveDown(),
            .up => self.list.moveUp(),
            .enter => switch (self.list.selected) {
                0 => {
                    const v = try SSOProfileView.init(
                        ctx.allocator,
                        ctx.io,
                        ctx.credentials.env,
                        ctx.color_support,
                    );
                    return .{ .push = .{ .sso_profile = v } };
                },
                1 => {
                    return .{ .push = .{ .manual_credentials = CredentialsView.init(
                        self.fg_color,
                        self.bg_color,
                    ) } };
                },
                else => {},
            },
            else => {},
        },
        else => {},
    }
    return .none;
}

pub fn render(self: *AuthPromptView, writer: *std.Io.Writer, size: Coord) !void {
    if (size.x < 4 or size.y < 3) return;
    const w: usize = @intCast(size.x);
    const h: usize = @intCast(size.y);

    self.list.updateScroll(if (h >= 1) h - 1 else 0);
    for (0..h) |row| {
        try self.list.renderLine(writer, row + 1, w, h + 1);
        if (row + 1 < h) try writer.writeAll("\r\n");
    }
}
