const std = @import("std");
const terminal = @import("../../terminal/terminal.zig");
const colors_mod = @import("../../ui/colors.zig");
const Event = @import("../../event.zig").Event;
const view_mod = @import("../../ui/view.zig");
const Action = view_mod.Action;
const ViewContext = view_mod.ViewContext;
const Coord = terminal.Coord;
const List = @import("../../ui/list.zig");
const S3BucketsView = @import("s3/buckets.zig").S3BucketsView;
const LambdasView = @import("lambda/lambdas.zig");
const LogGroupsView = @import("logs/log_groups.zig");
const IamHomeView = @import("iam/iam_home.zig");
const SecretsView = @import("secretsmanager/secrets.zig");
const ConfirmView = @import("../../ui/confirm.zig");

const BaseView = @This();
pub const name: []const u8 = "Home";

fg_color: []const u8,
bg_color: []const u8,
list: List,
pending_g: bool = false,

pub fn init(environ_map: *const std.process.Environ.Map) BaseView {
    const colorSupport = terminal.getColorSupport(environ_map);
    const colors = colors_mod.orange(colorSupport);
    const fg_color = colors.fg;
    const bg_color = colors.bg;

    return .{
        .fg_color = fg_color,
        .bg_color = bg_color,
        .list = .{
            .items = &[_][]const u8{
                "S3",
                "Lambda",
                "CloudWatch Logs",
                "IAM",
                "Secrets Manager",
            },
            .fg_color = fg_color,
            .bg_color = bg_color,
        },
    };
}

pub fn breadcrumb(_: *BaseView) []const u8 {
    return "Home";
}

pub fn deinit(_: *BaseView) void {}

pub fn handleEvent(self: *BaseView, event: Event, ctx: ViewContext) !Action {
    switch (event) {
        .key => |k| switch (k) {
            .ctrl_c => return .quit,
            .escape => return .{ .push = .{ .confirm = ConfirmView.init(self.fg_color, self.bg_color) } },
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
                else => {
                    self.pending_g = false;
                },
            },
            .down => self.list.moveDown(),
            .up => self.list.moveUp(),
            .enter => return switch (self.list.selected) {
                0 => blk: {
                    const v = try S3BucketsView.init(ctx.allocator, ctx.io, ctx.profile_set, ctx.region, ctx.color_support);
                    break :blk .{ .push = .{ .s3_buckets = v } };
                },
                1 => blk: {
                    const v = try LambdasView.init(ctx.allocator, ctx.io, ctx.profile_set, ctx.regions, ctx.color_support);
                    break :blk .{ .push = .{ .lambda_functions = v } };
                },
                2 => blk: {
                    const v = try LogGroupsView.init(ctx.allocator, ctx.io, ctx.profile_set, ctx.regions, ctx.color_support);
                    break :blk .{ .push = .{ .logs_log_groups = v } };
                },
                3 => blk: {
                    const v = IamHomeView.init(ctx.color_support);
                    break :blk .{ .push = .{ .iam_home = v } };
                },
                4 => blk: {
                    const v = try SecretsView.init(ctx.allocator, ctx.io, ctx.profile_set, ctx.regions, ctx.color_support);
                    break :blk .{ .push = .{ .secretsmanager_secrets = v } };
                },
                else => .none,
            },
            else => {},
        },
        else => {},
    }
    return .none;
}

pub fn render(self: *BaseView, writer: *std.Io.Writer, size: Coord) !void {
    if (size.x < 4 or size.y < 3) return;
    const w: usize = @intCast(size.x);
    const h: usize = @intCast(size.y);

    self.list.updateScroll(if (h >= 1) h - 1 else 0);

    for (0..h) |row| {
        try self.list.renderLine(writer, row + 1, w, h + 1);
        if (row + 1 < h) try writer.writeAll("\r\n");
    }
}
