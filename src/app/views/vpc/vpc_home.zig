const std = @import("std");
const terminal = @import("../../../terminal/terminal.zig");
const colors_mod = @import("../../../ui/colors.zig");
const Event = @import("../../../event.zig").Event;
const view_mod = @import("../../../ui/view.zig");
const Action = view_mod.Action;
const ViewContext = view_mod.ViewContext;
const Coord = terminal.Coord;
const List = @import("../../../ui/list.zig");
const ConfirmView = @import("../../../ui/confirm.zig");
const VpcsView = @import("vpcs.zig");
const SubnetsView = @import("subnets.zig");
const RouteTablesView = @import("route_tables.zig");
const InternetGatewaysView = @import("internet_gateways.zig");

const VpcHomeView = @This();
pub const name: []const u8 = "VPC";

const MENU_ITEMS = [_][]const u8{
    "VPCs",
    "Subnets",
    "Route Tables",
    "Internet Gateways",
};

fg_color: []const u8,
bg_color: []const u8,
list: List,
pending_g: bool = false,

pub fn init(color_support: terminal.ColorSupport) VpcHomeView {
    const colors = colors_mod.purple(color_support);
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

pub fn breadcrumb(_: *VpcHomeView) []const u8 {
    return "VPC";
}

pub fn deinit(_: *VpcHomeView) void {}

pub fn handleEvent(self: *VpcHomeView, event: Event, ctx: ViewContext) !Action {
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
                0 => { // VPCs
                    const v = try VpcsView.init(ctx.allocator, ctx.io, ctx.profile_set, ctx.regions, ctx.color_support);
                    return .{ .push = .{ .vpc_vpcs = v } };
                },
                1 => { // Subnets
                    const v = try SubnetsView.init(ctx.allocator, ctx.io, ctx.profile_set, ctx.regions, ctx.color_support);
                    return .{ .push = .{ .vpc_subnets = v } };
                },
                2 => { // Route Tables
                    const v = try RouteTablesView.init(ctx.allocator, ctx.io, ctx.profile_set, ctx.regions, ctx.color_support);
                    return .{ .push = .{ .vpc_route_tables = v } };
                },
                3 => { // Internet Gateways
                    const v = try InternetGatewaysView.init(ctx.allocator, ctx.io, ctx.profile_set, ctx.regions, ctx.color_support);
                    return .{ .push = .{ .vpc_internet_gateways = v } };
                },
                else => {},
            },
            else => {},
        },
        else => {},
    }
    return .none;
}

pub fn render(self: *VpcHomeView, writer: *std.Io.Writer, size: Coord) !void {
    if (size.x < 4 or size.y < 3) return;
    const w: usize = @intCast(size.x);
    const h: usize = @intCast(size.y);

    self.list.updateScroll(if (h >= 1) h - 1 else 0);

    for (0..h) |row| {
        try self.list.renderLine(writer, row + 1, w, h + 1);
        if (row + 1 < h) try writer.writeAll("\r\n");
    }
}
