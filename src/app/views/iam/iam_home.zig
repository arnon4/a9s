const std = @import("std");
const terminal = @import("../../../terminal/terminal.zig");
const colors_mod = @import("../../../ui/colors.zig");
const Event = @import("../../../event.zig").Event;
const view_mod = @import("../../../ui/view.zig");
const Action = view_mod.Action;
const ViewContext = view_mod.ViewContext;
const Coord = terminal.Coord;
const List = @import("../../../ui/list.zig");
const ProfileSet = @import("../../profile_set.zig").ProfileSet;
const ConfirmView = @import("../../../ui/confirm.zig");
const IamRolesView = @import("roles.zig");
const IamPoliciesView = @import("policies.zig");
const IamUsersView = @import("users.zig");
const IamGroupsView = @import("groups.zig");
const IamIdentityProvidersView = @import("identity_providers.zig");

const IamHomeView = @This();
pub const name: []const u8 = "IAM";

const MENU_ITEMS = [_][]const u8{
    "Users",
    "Roles",
    "Policies",
    "Groups",
    "Identity Providers",
};

fg_color: []const u8,
bg_color: []const u8,
list: List,
pending_g: bool = false,

pub fn init(color_support: terminal.ColorSupport) IamHomeView {
    const colors = colors_mod.iam(color_support);
    return .{
        .fg_color = colors.fg,
        .bg_color = colors.bg,
        .list = .{
            .items = &MENU_ITEMS,
            .fg_color = colors.fg,
            .bg_color = colors.bg,
        },
    };
}

pub fn breadcrumb(_: *IamHomeView) []const u8 {
    return "IAM";
}

pub fn deinit(_: *IamHomeView) void {}

pub fn handleEvent(self: *IamHomeView, event: Event, ctx: ViewContext) !Action {
    switch (event) {
        .key => |k| switch (k) {
            .ctrl_c => return .quit,
            .escape => return .pop,
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
            .enter => switch (self.list.selected) {
                0 => { // Users
                    const v = try IamUsersView.init(ctx.allocator, ctx.io, ctx.profile_set, ctx.color_support, self.breadcrumb());
                    return .{ .push = .{ .iam_users = v } };
                },
                1 => { // Roles
                    const v = try IamRolesView.init(ctx.allocator, ctx.io, ctx.profile_set, ctx.color_support, self.breadcrumb());
                    return .{ .push = .{ .iam_roles = v } };
                },
                2 => { // Policies
                    const v = try IamPoliciesView.init(ctx.allocator, ctx.io, ctx.profile_set, ctx.color_support, self.breadcrumb());
                    return .{ .push = .{ .iam_policies = v } };
                },
                3 => { // Groups
                    const v = try IamGroupsView.init(ctx.allocator, ctx.io, ctx.profile_set, ctx.color_support, self.breadcrumb());
                    return .{ .push = .{ .iam_groups = v } };
                },
                4 => { // Identity Providers
                    const v = try IamIdentityProvidersView.init(ctx.allocator, ctx.io, ctx.profile_set, ctx.color_support, self.breadcrumb());
                    return .{ .push = .{ .iam_identity_providers = v } };
                },
                else => {},
            },
            else => {},
        },
        else => {},
    }
    return .none;
}

pub fn render(self: *IamHomeView, writer: *std.Io.Writer, size: Coord) !void {
    if (size.x < 4 or size.y < 3) return;
    const w: usize = @intCast(size.x);
    const h: usize = @intCast(size.y);

    self.list.updateScroll(if (h >= 1) h - 1 else 0);

    for (0..h) |row| {
        try self.list.renderLine(writer, row + 1, w, h + 1);
        if (row + 1 < h) try writer.writeAll("\r\n");
    }
}
