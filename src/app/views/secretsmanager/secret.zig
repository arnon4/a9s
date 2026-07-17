const std = @import("std");
const colors_mod = @import("../../../ui/colors.zig");
const fetcher = @import("../../../sdk/credentials/fetcher.zig");
const Credentials = fetcher.Credentials;
const terminal = @import("../../../terminal/terminal.zig");
const Event = @import("../../../event.zig").Event;
const view_mod = @import("../../../ui/view.zig");
const Action = view_mod.Action;
const ViewContext = view_mod.ViewContext;
const Coord = terminal.Coord;
const props_mod = @import("../../../ui/props.zig");
const constants = @import("../../../ui/constants.zig");
const ConfirmView = @import("../../../ui/confirm.zig");
const SecretValueView = @import("secret_value.zig");
const ResourcePolicyView = @import("resource_policy.zig");

const SecretView = @This();
pub const name: []const u8 = "Secret";

fg_color: []const u8,
bg_color: []const u8,
scroll: usize = 0,
action_idx: usize = 0,
pending_g: bool = false,
breadcrumb_buf: [256]u8 = undefined,
breadcrumb_len: usize = 0,

name_: []u8,
arn: []u8,
account_id: []u8,
region: []u8,
description: []u8,
created_date: ?f64,
last_accessed_date: ?f64,
credentials: Credentials,
alloc: std.mem.Allocator,
io: std.Io,

pub fn init(
    allocator: std.mem.Allocator,
    io: std.Io,
    credentials: Credentials,
    secret_name: []const u8,
    arn: []const u8,
    account_id: []const u8,
    region: []const u8,
    description: []const u8,
    created_date: ?f64,
    last_accessed_date: ?f64,
    color_support: terminal.ColorSupport,
) !SecretView {
    const colors = colors_mod.iam(color_support);

    const name_owned = try allocator.dupe(u8, secret_name);
    errdefer allocator.free(name_owned);
    const arn_owned = try allocator.dupe(u8, arn);
    errdefer allocator.free(arn_owned);
    const account_owned = try allocator.dupe(u8, account_id);
    errdefer allocator.free(account_owned);
    const region_owned = try allocator.dupe(u8, region);
    errdefer allocator.free(region_owned);
    const description_owned = try allocator.dupe(u8, description);
    errdefer allocator.free(description_owned);

    var view = SecretView{
        .fg_color = colors.fg,
        .bg_color = colors.bg,
        .name_ = name_owned,
        .arn = arn_owned,
        .account_id = account_owned,
        .region = region_owned,
        .description = description_owned,
        .created_date = created_date,
        .last_accessed_date = last_accessed_date,
        .credentials = credentials,
        .alloc = allocator,
        .io = io,
    };
    const bc = std.fmt.bufPrint(&view.breadcrumb_buf, "Secrets {s} {s}", .{ constants.SEP_ARROW, secret_name }) catch view.breadcrumb_buf[0..0];
    view.breadcrumb_len = bc.len;
    return view;
}

pub fn breadcrumb(self: *SecretView) []const u8 {
    return self.breadcrumb_buf[0..self.breadcrumb_len];
}

pub fn deinit(self: *SecretView) void {
    self.alloc.free(self.name_);
    self.alloc.free(self.arn);
    self.alloc.free(self.account_id);
    self.alloc.free(self.region);
    self.alloc.free(self.description);
}

fn formatEpochSeconds(buf: []u8, secs_f: ?f64) []u8 {
    const secs_val = secs_f orelse return std.fmt.bufPrint(buf, "-", .{}) catch buf[0..0];
    if (secs_val <= 0) return std.fmt.bufPrint(buf, "-", .{}) catch buf[0..0];
    const secs: u64 = @intFromFloat(secs_val);
    const epoch_secs = std.time.epoch.EpochSeconds{ .secs = secs };
    const epoch_day = epoch_secs.getEpochDay();
    const day_secs = epoch_secs.getDaySeconds();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}", .{
        year_day.year,
        month_day.month.numeric(),
        month_day.day_index + 1,
        day_secs.getHoursIntoDay(),
        day_secs.getMinutesIntoHour(),
    }) catch buf[0..0];
}

pub fn buildProps(
    buf: []props_mod.Prop,
    created_buf: []u8,
    accessed_buf: []u8,
    secret_name: []const u8,
    arn: []const u8,
    account_id: []const u8,
    region: []const u8,
    description: []const u8,
    created_date: ?f64,
    last_accessed_date: ?f64,
) []props_mod.Prop {
    const dash = "-";
    var n: usize = 0;

    buf[n] = .{ .label = "Name", .value = secret_name };
    n += 1;
    buf[n] = .{ .label = "ARN", .value = arn };
    n += 1;
    buf[n] = .{ .label = "Account", .value = account_id };
    n += 1;
    buf[n] = .{ .label = "Region", .value = region };
    n += 1;
    buf[n] = .{ .label = "Description", .value = if (description.len > 0) description else dash };
    n += 1;
    buf[n] = .{ .label = "Created", .value = formatEpochSeconds(created_buf, created_date) };
    n += 1;
    buf[n] = .{ .label = "Last Accessed", .value = formatEpochSeconds(accessed_buf, last_accessed_date) };
    n += 1;

    return buf[0..n];
}

pub fn handleEvent(self: *SecretView, event: Event, ctx: ViewContext) !Action {
    switch (event) {
        .key => |k| switch (k) {
            .ctrl_c => return .quit,
            .char => |c| switch (c) {
                'q' => return .{ .push = .{ .confirm = ConfirmView.init(self.fg_color, self.bg_color) } },
                'j' => self.scroll += 1,
                'k' => if (self.scroll > 0) {
                    self.scroll -= 1;
                },
                'h' => if (self.action_idx > 0) {
                    self.action_idx -= 1;
                },
                'l' => if (self.action_idx < 1) {
                    self.action_idx += 1;
                },
                'g' => {
                    if (self.pending_g) {
                        self.scroll = 0;
                        self.pending_g = false;
                    } else {
                        self.pending_g = true;
                    }
                },
                'G' => {
                    self.pending_g = false;
                    self.scroll = std.math.maxInt(usize) / 2;
                },
                else => {
                    self.pending_g = false;
                },
            },
            .down => self.scroll += 1,
            .up => if (self.scroll > 0) {
                self.scroll -= 1;
            },
            .left => if (self.action_idx > 0) {
                self.action_idx -= 1;
            },
            .right => if (self.action_idx < 1) {
                self.action_idx += 1;
            },
            .enter => {
                if (self.action_idx == 0) {
                    const v = try SecretValueView.init(
                        ctx.allocator,
                        ctx.io,
                        self.credentials,
                        self.name_,
                        self.region,
                        ctx.color_support,
                        self.breadcrumb(),
                    );
                    return .{ .push = .{ .secretsmanager_secret_value = v } };
                } else {
                    const v = try ResourcePolicyView.init(
                        ctx.allocator,
                        ctx.io,
                        self.credentials,
                        self.name_,
                        self.region,
                        ctx.color_support,
                        self.breadcrumb(),
                    );
                    return .{ .push = .{ .secretsmanager_resource_policy = v } };
                }
            },
            .escape => return .pop,
            else => {},
        },
        else => {},
    }
    return .none;
}

pub fn render(self: *SecretView, writer: *std.Io.Writer, size: Coord) !void {
    if (size.x < 10 or size.y < 2) return;
    const w: usize = @intCast(size.x);
    const h: usize = @intCast(size.y);

    var prop_buf: [8]props_mod.Prop = undefined;
    var created_buf: [20]u8 = undefined;
    var accessed_buf: [20]u8 = undefined;
    const props = buildProps(
        &prop_buf,
        &created_buf,
        &accessed_buf,
        self.name_,
        self.arn,
        self.account_id,
        self.region,
        self.description,
        self.created_date,
        self.last_accessed_date,
    );

    const total = props.len;
    const data_rows = if (h >= 1) h - 1 else 0;
    if (data_rows > 0 and self.scroll + data_rows > total) {
        self.scroll = if (total > data_rows) total - data_rows else 0;
    }

    const props_h = if (h >= 2) h - 1 else h;
    try props_mod.render(writer, props, self.scroll, w, props_h, self.fg_color);

    if (h >= 2) {
        try writer.writeAll("\r\n");
        try self.renderActionBar(writer, w);
    }
}

fn renderActionBar(self: *SecretView, writer: *std.Io.Writer, w: usize) !void {
    if (self.action_idx == 0) {
        try writer.writeAll(self.bg_color);
        try writer.writeAll(terminal.FG_BLACK);
    } else {
        try writer.writeAll(self.fg_color);
    }
    const value_btn = " [ View Secret Value ] ";
    try writer.writeAll(value_btn);
    try writer.writeAll(terminal.RESET);

    if (self.action_idx == 1) {
        try writer.writeAll(self.bg_color);
        try writer.writeAll(terminal.FG_BLACK);
    } else {
        try writer.writeAll(self.fg_color);
    }
    const policy_btn = " [ View Resource Policy ] ";
    try writer.writeAll(policy_btn);
    try writer.writeAll(terminal.RESET);

    const used = value_btn.len + policy_btn.len;
    if (w > used) {
        for (0..w - used) |_| try writer.writeByte(' ');
    }
}

// ============================================================================
// Tests
// ============================================================================

test "buildProps basic" {
    var prop_buf: [8]props_mod.Prop = undefined;
    var created_buf: [20]u8 = undefined;
    var accessed_buf: [20]u8 = undefined;
    const props = buildProps(&prop_buf, &created_buf, &accessed_buf, "my-secret", "arn:aws:secretsmanager:::secret:my-secret", "123456789012", "us-east-1", "", null, null);

    try std.testing.expectEqual(@as(usize, 7), props.len);
    try std.testing.expectEqualStrings("Name", props[0].label);
    try std.testing.expectEqualStrings("my-secret", props[0].value);
    try std.testing.expectEqualStrings("Account", props[2].label);
    try std.testing.expectEqualStrings("123456789012", props[2].value);
    try std.testing.expectEqualStrings("Description", props[4].label);
    try std.testing.expectEqualStrings("-", props[4].value);
    try std.testing.expectEqualStrings("Created", props[5].label);
    try std.testing.expectEqualStrings("-", props[5].value);
}
