const std = @import("std");
const colors_mod = @import("../../../ui/colors.zig");
const format_mod = @import("../../../ui/format.zig");
const fetcher = @import("../../../sdk/credentials/fetcher.zig");
const Credentials = fetcher.Credentials;
const terminal = @import("../../../terminal/terminal.zig");
const input = @import("../../../terminal/input.zig");
const Event = @import("../../../event.zig").Event;
const view_mod = @import("../../../ui/view.zig");
const Action = view_mod.Action;
const ViewContext = view_mod.ViewContext;
const Coord = terminal.Coord;
const Lambda = @import("../../../sdk/clients/lambda/client.zig");
const props_mod = @import("../../../ui/props.zig");
const LambdaContentView = @import("lambda_content.zig").LambdaContentView;
const constants = @import("../../../ui/constants.zig");
const ConfirmView = @import("../../../ui/confirm.zig");
const LogStreamsView = @import("../logs/log_streams.zig");
const IamRoleView = @import("../iam/role.zig");

const view_size_limit: i64 = 10 * 1024 * 1024;

pub const FetchCtx = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    credentials: Credentials,
    region: []const u8,
    function_name: []const u8,
    thread: std.Thread,
    result: ?Lambda.FunctionConfiguration = null,
    err: ?anyerror = null,
    done: std.atomic.Value(bool),
};

fn fetchThread(ctx: *FetchCtx) void {
    defer {
        ctx.done.store(true, .release);
        input.notify();
    }
    var client = Lambda.Client.init(ctx.allocator, .{
        .region = ctx.region,
        .io = ctx.io,
        .credentials = ctx.credentials,
    }) catch |e| {
        ctx.err = e;
        return;
    };
    defer client.deinit();
    ctx.result = client.getFunctionConfiguration(.{
        .function_name = ctx.function_name,
    }) catch |e| {
        ctx.err = e;
        return;
    };
}

pub const PropScratch = struct {
    size: [24]u8 = undefined,
    timeout: [20]u8 = undefined,
    mem: [20]u8 = undefined,
    eph: [20]u8 = undefined,
    err_msg: [64]u8 = undefined,
};

pub fn buildProps(
    buf: []props_mod.Prop,
    scratch: *PropScratch,
    function_name: []const u8,
    function_arn: []const u8,
    region: []const u8,
    done: bool,
    result: ?*const Lambda.FunctionConfiguration,
    err: ?anyerror,
) []props_mod.Prop {
    const dash = "-";
    var n: usize = 0;

    buf[n] = .{ .label = "Function Name", .value = function_name };
    n += 1;
    buf[n] = .{ .label = "ARN", .value = function_arn };
    n += 1;
    buf[n] = .{ .label = "Region", .value = region };
    n += 1;

    if (done) {
        if (err) |e| {
            const err_str = std.fmt.bufPrint(&scratch.err_msg, "Error: {s}", .{@errorName(e)}) catch "Error";
            buf[n] = .{ .label = "Status", .value = err_str };
            n += 1;
        } else if (result) |r| {
            buf[n] = .{ .label = "Runtime", .value = if (r.runtime.len > 0) r.runtime else dash };
            n += 1;
            buf[n] = .{ .label = "Handler", .value = if (r.handler.len > 0) r.handler else dash };
            n += 1;
            buf[n] = .{ .label = "Role", .value = r.role };
            n += 1;
            buf[n] = .{ .label = "Description", .value = if (r.description.len > 0) r.description else dash };
            n += 1;
            buf[n] = .{ .label = "Version", .value = r.version };
            n += 1;
            buf[n] = .{ .label = "Package Type", .value = r.package_type };
            n += 1;
            buf[n] = .{ .label = "State", .value = if (r.state.len > 0) r.state else dash };
            n += 1;
            buf[n] = .{ .label = "State Reason", .value = if (r.state_reason.len > 0) r.state_reason else dash };
            n += 1;
            buf[n] = .{ .label = "Last Modified", .value = r.last_modified };
            n += 1;
            buf[n] = .{ .label = "Last Update Status", .value = if (r.last_update_status.len > 0) r.last_update_status else dash };
            n += 1;
            buf[n] = .{ .label = "Tracing Mode", .value = if (r.tracing_mode.len > 0) r.tracing_mode else dash };
            n += 1;
            if (r.kms_key_arn.len > 0) {
                buf[n] = .{ .label = "KMS Key ARN", .value = r.kms_key_arn };
                n += 1;
            }
            if (r.master_arn.len > 0) {
                buf[n] = .{ .label = "Master ARN", .value = r.master_arn };
                n += 1;
            }
            buf[n] = .{ .label = "Revision ID", .value = r.revision_id };
            n += 1;
            buf[n] = .{ .label = "Code SHA256", .value = r.code_sha256 };
            n += 1;
            const code_bytes: u64 = if (r.code_size > 0) @intCast(r.code_size) else 0;
            buf[n] = .{ .label = "Code Size", .value = format_mod.size(&scratch.size, code_bytes) };
            n += 1;
            buf[n] = .{ .label = "Timeout", .value = std.fmt.bufPrint(&scratch.timeout, "{d}s", .{r.timeout}) catch dash };
            n += 1;
            buf[n] = .{ .label = "Memory Size", .value = std.fmt.bufPrint(&scratch.mem, "{d} MB", .{r.memory_size}) catch dash };
            n += 1;
            buf[n] = .{ .label = "Ephemeral Storage", .value = std.fmt.bufPrint(&scratch.eph, "{d} MB", .{r.ephemeral_storage_size}) catch dash };
            n += 1;
            if (r.dead_letter_target_arn.len > 0) {
                buf[n] = .{ .label = "Dead Letter Target", .value = r.dead_letter_target_arn };
                n += 1;
            }
            if (r.vpc_config) |vc| {
                buf[n] = .{ .label = "VPC ID", .value = if (vc.vpc_id.len > 0) vc.vpc_id else dash };
                n += 1;
            }
            if (r.logging_config) |lc| {
                buf[n] = .{ .label = "Log Format", .value = lc.log_format };
                n += 1;
                buf[n] = .{ .label = "Log Group", .value = if (lc.log_group.len > 0) lc.log_group else dash };
                n += 1;
            }
        }
    } else {
        buf[n] = .{ .label = "Runtime", .value = constants.ELLIPSES };
        n += 1;
        buf[n] = .{ .label = "Handler", .value = constants.ELLIPSES };
        n += 1;
        buf[n] = .{ .label = "State", .value = constants.ELLIPSES };
        n += 1;
    }

    return buf[0..n];
}

pub fn LambdaViewGeneric(comptime fetchFn: fn (*FetchCtx) void) type {
    return struct {
        const Self = @This();
        pub const name: []const u8 = "Function";

        fg_color: []const u8,
        bg_color: []const u8,
        scroll: usize = 0,
        action_idx: usize = 0,
        pending_g: bool = false,
        breadcrumb_buf: [256]u8 = undefined,
        breadcrumb_len: usize = 0,

        function_name: []u8,
        function_arn: []u8,
        region: []u8,
        code_size: i64,
        fetch_ctx: *FetchCtx,
        alloc: std.mem.Allocator,
        io: std.Io,

        pub fn init(
            allocator: std.mem.Allocator,
            io: std.Io,
            credentials: Credentials,
            function_name: []const u8,
            function_arn: []const u8,
            region: []const u8,
            code_size: i64,
            color_support: terminal.ColorSupport,
        ) !Self {
            const colors = colors_mod.orange(color_support);
            const fg_color = colors.fg;
            const bg_color = colors.bg;

            const name_owned = try allocator.dupe(u8, function_name);
            errdefer allocator.free(name_owned);
            const arn_owned = try allocator.dupe(u8, function_arn);
            errdefer allocator.free(arn_owned);
            const region_owned = try allocator.dupe(u8, region);
            errdefer allocator.free(region_owned);

            const ctx = try allocator.create(FetchCtx);
            errdefer allocator.destroy(ctx);
            ctx.* = .{
                .allocator = allocator,
                .io = io,
                .credentials = credentials,
                .region = region_owned,
                .function_name = name_owned,
                .thread = undefined,
                .done = std.atomic.Value(bool).init(false),
            };
            ctx.thread = try std.Thread.spawn(.{}, fetchFn, .{ctx});
            errdefer ctx.thread.join(); // only reachable on errors after a successful spawn

            var bc_buf: [256]u8 = undefined;
            const bc = std.fmt.bufPrint(&bc_buf, "Functions {s} {s}", .{ constants.SEP_ARROW, function_name }) catch bc_buf[0..0];

            return Self{
                .fg_color = fg_color,
                .bg_color = bg_color,
                .breadcrumb_buf = bc_buf,
                .breadcrumb_len = bc.len,
                .function_name = name_owned,
                .function_arn = arn_owned,
                .region = region_owned,
                .code_size = code_size,
                .fetch_ctx = ctx,
                .alloc = allocator,
                .io = io,
            };
        }

        pub fn breadcrumb(self: *Self) []const u8 {
            return self.breadcrumb_buf[0..self.breadcrumb_len];
        }

        pub fn deinit(self: *Self) void {
            const alloc = self.fetch_ctx.allocator;
            self.fetch_ctx.thread.join();
            if (self.fetch_ctx.result) |*r| r.deinit();
            alloc.destroy(self.fetch_ctx);
            alloc.free(self.function_name);
            alloc.free(self.function_arn);
            alloc.free(self.region);
        }

        fn refresh(self: *Self) !void {
            if (!self.fetch_ctx.done.load(.acquire)) return;

            const alloc = self.fetch_ctx.allocator;
            const io = self.fetch_ctx.io;
            const creds = self.fetch_ctx.credentials;

            self.fetch_ctx.thread.join();
            if (self.fetch_ctx.result) |*r| r.deinit();
            alloc.destroy(self.fetch_ctx);

            const new_ctx = try alloc.create(FetchCtx);
            errdefer alloc.destroy(new_ctx);
            new_ctx.* = .{
                .allocator = alloc,
                .io = io,
                .credentials = creds,
                .region = self.region,
                .function_name = self.function_name,
                .thread = undefined,
                .done = std.atomic.Value(bool).init(false),
            };
            new_ctx.thread = try std.Thread.spawn(.{}, fetchFn, .{new_ctx});
            self.fetch_ctx = new_ctx;
        }

        fn canViewCode(self: *Self) bool {
            return self.code_size > 0 and self.code_size <= view_size_limit;
        }

        pub fn handleEvent(self: *Self, event: Event, ctx: ViewContext) !Action {
            switch (event) {
                .key => |k| switch (k) {
                    .ctrl_c => return .quit,
                    .char => |c| switch (c) {
                        'q' => return .{ .push = .{ .confirm = ConfirmView.init(self.fg_color, self.bg_color) } },
                        'r' => self.refresh() catch {},
                        'j' => self.scroll += 1,
                        'k' => if (self.scroll > 0) {
                            self.scroll -= 1;
                        },
                        'h' => if (self.action_idx > 0) {
                            self.action_idx -= 1;
                        },
                        'l' => if (self.action_idx < 2) {
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
                    .right => if (self.action_idx < 2) {
                        self.action_idx += 1;
                    },
                    .enter => {
                        if (self.action_idx == 0) {
                            if (self.canViewCode()) {
                                const creds = self.fetch_ctx.credentials;
                                const v = try LambdaContentView.init(
                                    ctx.allocator,
                                    ctx.io,
                                    creds,
                                    self.function_name,
                                    self.region,
                                    ctx.color_support,
                                );
                                return .{ .push = .{ .lambda_function_content = v } };
                            }
                        } else if (self.action_idx == 1) {
                            const log_group: []u8 = blk: {
                                if (self.fetch_ctx.done.load(.acquire)) {
                                    if (self.fetch_ctx.result) |*r| {
                                        if (r.logging_config) |lc| {
                                            if (lc.log_group.len > 0) {
                                                break :blk try ctx.allocator.dupe(u8, lc.log_group);
                                            }
                                        }
                                    }
                                }
                                break :blk try std.fmt.allocPrint(ctx.allocator, "/aws/lambda/{s}", .{self.function_name});
                            };
                            defer ctx.allocator.free(log_group);
                            const v = try LogStreamsView.init(
                                ctx.allocator,
                                ctx.io,
                                self.fetch_ctx.credentials,
                                self.region,
                                log_group,
                                ctx.color_support,
                                self.breadcrumb(),
                            );
                            return .{ .push = .{ .logs_log_streams = v } };
                        } else if (self.action_idx == 2) {
                            if (!self.fetch_ctx.done.load(.acquire)) return .none;
                            const role_arn = if (self.fetch_ctx.result) |*r| r.role else return .none;
                            const role_name = if (std.mem.lastIndexOfScalar(u8, role_arn, '/')) |i|
                                role_arn[i + 1 ..]
                            else
                                role_arn;
                            const v = try IamRoleView.init(
                                ctx.allocator,
                                ctx.io,
                                self.fetch_ctx.credentials,
                                role_name,
                                role_arn,
                                "",
                                ctx.color_support,
                                self.breadcrumb(),
                            );
                            return .{ .push = .{ .iam_role = v } };
                        }
                    },
                    .escape => return .pop,
                    else => {},
                },
                else => {},
            }
            return .none;
        }

        pub fn render(self: *Self, writer: *std.Io.Writer, size: Coord) !void {
            if (size.x < 10 or size.y < 2) return;
            const w: usize = @intCast(size.x);
            const h: usize = @intCast(size.y);

            const done = self.fetch_ctx.done.load(.acquire);
            const result_ptr: ?*const Lambda.FunctionConfiguration = if (done)
                if (self.fetch_ctx.result) |*r| r else null
            else
                null;

            var prop_buf: [40]props_mod.Prop = undefined;
            var scratch: PropScratch = .{};
            const props = buildProps(
                &prop_buf,
                &scratch,
                self.function_name,
                self.function_arn,
                self.region,
                done,
                result_ptr,
                if (done) self.fetch_ctx.err else null,
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
                try renderActionBar(self, writer, w);
            }
        }

        fn renderActionBar(self: *Self, writer: *std.Io.Writer, w: usize) !void {
            const code_disabled = !self.canViewCode();

            if (code_disabled) {
                try writer.writeAll(terminal.DIM);
                try writer.writeAll(self.fg_color);
            } else if (self.action_idx == 0) {
                try writer.writeAll(self.bg_color);
                try writer.writeAll(terminal.FG_BLACK);
            } else {
                try writer.writeAll(self.fg_color);
            }
            const code_btn = " [ View Code ] ";
            try writer.writeAll(code_btn);
            try writer.writeAll(terminal.RESET);

            if (self.action_idx == 1) {
                try writer.writeAll(self.bg_color);
                try writer.writeAll(terminal.FG_BLACK);
            } else {
                try writer.writeAll(self.fg_color);
            }
            const logs_btn = " [ View Logs ] ";
            try writer.writeAll(logs_btn);
            try writer.writeAll(terminal.RESET);

            const role_disabled = !self.fetch_ctx.done.load(.acquire) or self.fetch_ctx.result == null;
            if (role_disabled) {
                try writer.writeAll(terminal.DIM);
                try writer.writeAll(self.fg_color);
            } else if (self.action_idx == 2) {
                try writer.writeAll(self.bg_color);
                try writer.writeAll(terminal.FG_BLACK);
            } else {
                try writer.writeAll(self.fg_color);
            }
            const role_btn = " [ View Role ] ";
            try writer.writeAll(role_btn);
            try writer.writeAll(terminal.RESET);

            const used = code_btn.len + logs_btn.len + role_btn.len;
            if (w > used) {
                for (0..w - used) |_| try writer.writeByte(' ');
            }
        }
    };
}

pub const LambdaView = LambdaViewGeneric(fetchThread);

// ============================================================================
// Tests
// ============================================================================

test "formatSize bytes" {
    var buf: [24]u8 = undefined;
    try std.testing.expectEqualStrings("512 B", format_mod.size(&buf, 512));
}

test "formatSize kilobytes" {
    var buf: [24]u8 = undefined;
    const s = format_mod.size(&buf, 2048);
    try std.testing.expectEqualStrings("2.0 KB", s);
}

test "formatSize megabytes" {
    var buf: [24]u8 = undefined;
    const s = format_mod.size(&buf, 3 * 1024 * 1024);
    try std.testing.expectEqualStrings("3.0 MB", s);
}

test "buildProps loading state" {
    var prop_buf: [40]props_mod.Prop = undefined;
    var scratch: PropScratch = .{};
    const props = buildProps(&prop_buf, &scratch, "my-fn", "arn:aws:lambda:::my-fn", "us-east-1", false, null, null);

    try std.testing.expectEqual(@as(usize, 6), props.len);
    try std.testing.expectEqualStrings("Function Name", props[0].label);
    try std.testing.expectEqualStrings("my-fn", props[0].value);
    try std.testing.expectEqualStrings("ARN", props[1].label);
    try std.testing.expectEqualStrings("Region", props[2].label);
    try std.testing.expectEqualStrings("us-east-1", props[2].value);
    try std.testing.expectEqualStrings("Runtime", props[3].label);
    try std.testing.expectEqualStrings(constants.ELLIPSES, props[3].value);
    try std.testing.expectEqualStrings("Handler", props[4].label);
    try std.testing.expectEqualStrings("State", props[5].label);
}

test "buildProps error state" {
    var prop_buf: [40]props_mod.Prop = undefined;
    var scratch: PropScratch = .{};
    const props = buildProps(&prop_buf, &scratch, "fn", "arn", "eu-west-1", true, null, error.AccessDenied);

    try std.testing.expectEqual(@as(usize, 4), props.len);
    try std.testing.expectEqualStrings("Status", props[3].label);
    try std.testing.expectEqualStrings("Error: AccessDenied", props[3].value);
}

test "buildProps result state" {
    const allocator = std.testing.allocator;

    var empty_map = std.StringHashMap([]u8).init(allocator);
    defer empty_map.deinit();

    var cfg = Lambda.FunctionConfiguration{
        .allocator = allocator,
        .function_name = @constCast("my-fn"),
        .function_arn = @constCast("arn"),
        .runtime = @constCast("python3.12"),
        .role = @constCast("arn:aws:iam::123:role/r"),
        .handler = @constCast("index.handler"),
        .code_size = 4096,
        .description = @constCast(""),
        .timeout = 30,
        .memory_size = 128,
        .last_modified = @constCast("2024-01-01T00:00:00Z"),
        .code_sha256 = @constCast("abc123"),
        .version = @constCast("$LATEST"),
        .package_type = @constCast("Zip"),
        .architectures = &.{},
        .state = @constCast("Active"),
        .state_reason = @constCast(""),
        .state_reason_code = @constCast(""),
        .last_update_status = @constCast("Successful"),
        .last_update_status_reason = @constCast(""),
        .last_update_status_reason_code = @constCast(""),
        .revision_id = @constCast("rev-1"),
        .kms_key_arn = @constCast(""),
        .master_arn = @constCast(""),
        .signing_job_arn = @constCast(""),
        .signing_profile_version_arn = @constCast(""),
        .ephemeral_storage_size = 512,
        .tracing_mode = @constCast("PassThrough"),
        .dead_letter_target_arn = @constCast(""),
        .runtime_version_arn = @constCast(""),
        .environment = null,
        .layers = &.{},
        .logging_config = null,
        .vpc_config = null,
        .image_config = null,
        .snap_start = null,
    };

    var prop_buf: [40]props_mod.Prop = undefined;
    var scratch: PropScratch = .{};
    const props = buildProps(&prop_buf, &scratch, "my-fn", "arn", "us-east-1", true, &cfg, null);

    // props order: FunctionName, ARN, Region, Runtime, Handler, Role, Description, Version, PackageType, State, ...
    try std.testing.expectEqualStrings("Runtime", props[3].label);
    try std.testing.expectEqualStrings("python3.12", props[3].value);
    try std.testing.expectEqualStrings("Handler", props[4].label);
    try std.testing.expectEqualStrings("index.handler", props[4].value);
    // empty description shows dash
    try std.testing.expectEqualStrings("Description", props[6].label);
    try std.testing.expectEqualStrings("-", props[6].value);
    try std.testing.expectEqualStrings("State", props[9].label);
    try std.testing.expectEqualStrings("Active", props[9].value);
    // numeric fields formatted
    const timeout_prop = for (props) |p| {
        if (std.mem.eql(u8, p.label, "Timeout")) break p;
    } else unreachable;
    try std.testing.expectEqualStrings("30s", timeout_prop.value);
}
