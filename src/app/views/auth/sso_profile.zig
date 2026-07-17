const std = @import("std");
const terminal = @import("../../../terminal/terminal.zig");
const colors_mod = @import("../../../ui/colors.zig");
const Event = @import("../../../event.zig").Event;
const view_mod = @import("../../../ui/view.zig");
const Action = view_mod.Action;
const ViewContext = view_mod.ViewContext;
const Coord = terminal.Coord;
const List = @import("../../../ui/list.zig");
const constants = @import("../../../ui/constants.zig");
const sso = @import("../../../auth/sso.zig");
const input = @import("../../../terminal/input.zig");
const ConfirmView = @import("../../../ui/confirm.zig");
const fetcher = @import("../../../sdk/credentials/fetcher.zig");

const SSOProfileView = @This();
pub const name: []const u8 = "SSO Login";

const State = enum { selecting, logging_in, done, failed };

fg_color: []const u8,
bg_color: []const u8,
allocator: std.mem.Allocator,
io: std.Io,
env: std.process.Environ,
profiles: []sso.SsoProfile,
names: [][]const u8,
list: List,
state: State = .selecting,
poll_ctx: ?*sso.PollCtx = null,
poll_thread: ?std.Thread = null,
login_url: []const u8 = "",
login_err: ?anyerror = null,

pub fn init(
    allocator: std.mem.Allocator,
    io: std.Io,
    env: std.process.Environ,
    color_support: terminal.ColorSupport,
) !SSOProfileView {
    const colors = colors_mod.orange(color_support);
    const fg_color = colors.fg;
    const bg_color = colors.bg;

    const profiles = try sso.readProfiles(allocator, io, env);
    errdefer {
        for (profiles) |p| p.deinit(allocator);
        allocator.free(profiles);
    }

    const names = try allocator.alloc([]const u8, profiles.len);
    errdefer allocator.free(names);
    for (profiles, names) |p, *n| n.* = p.name;

    return .{
        .fg_color = fg_color,
        .bg_color = bg_color,
        .allocator = allocator,
        .io = io,
        .env = env,
        .profiles = profiles,
        .names = names,
        .list = .{
            .items = names,
            .fg_color = fg_color,
            .bg_color = bg_color,
        },
    };
}

/// Like init but skips profile selection: immediately starts login for the named profile.
pub fn initForProfile(
    allocator: std.mem.Allocator,
    io: std.Io,
    env: std.process.Environ,
    profile_name: []const u8,
    color_support: terminal.ColorSupport,
) !SSOProfileView {
    const colors = colors_mod.orange(color_support);
    const fg_color = colors.fg;
    const bg_color = colors.bg;

    const name_copy = try allocator.dupe(u8, profile_name);
    const profiles = allocator.alloc(sso.SsoProfile, 1) catch {
        allocator.free(name_copy);
        return error.OutOfMemory;
    };
    profiles[0] = .{ .name = name_copy };
    const names = allocator.alloc([]const u8, 1) catch {
        profiles[0].deinit(allocator);
        allocator.free(profiles);
        return error.OutOfMemory;
    };
    names[0] = profiles[0].name;

    var v: SSOProfileView = .{
        .fg_color = fg_color,
        .bg_color = bg_color,
        .allocator = allocator,
        .io = io,
        .env = env,
        .profiles = profiles,
        .names = names,
        .list = .{
            .items = names,
            .fg_color = fg_color,
            .bg_color = bg_color,
        },
        .state = .logging_in,
    };

    const poll_ctx = allocator.create(sso.PollCtx) catch {
        v.login_err = error.OutOfMemory;
        v.state = .failed;
        return v;
    };
    poll_ctx.* = .{
        .allocator = allocator,
        .io = io,
        .arena = std.heap.ArenaAllocator.init(allocator),
        .done = std.atomic.Value(bool).init(false),
    };

    const url = sso.beginLogin(allocator, io, env, profile_name, poll_ctx) catch |e| {
        poll_ctx.deinit();
        allocator.destroy(poll_ctx);
        v.login_err = e;
        v.state = .failed;
        return v;
    };

    v.poll_ctx = poll_ctx;
    v.login_url = url;
    v.poll_thread = std.Thread.spawn(.{}, sso.pollToken, .{poll_ctx}) catch |e| {
        v.login_err = e;
        v.state = .failed;
        return v;
    };

    return v;
}

pub fn breadcrumb(_: *SSOProfileView) []const u8 {
    return "SSO Login";
}

pub fn deinit(self: *SSOProfileView) void {
    if (self.poll_thread) |t| t.join();
    if (self.poll_ctx) |ctx| {
        ctx.deinit();
        self.allocator.destroy(ctx);
    }
    for (self.profiles) |p| p.deinit(self.allocator);
    self.allocator.free(self.profiles);
    self.allocator.free(self.names);
}

pub fn handleEvent(self: *SSOProfileView, event: Event, ctx: ViewContext) !Action {
    // Check if login thread finished
    if (self.poll_ctx) |poll| {
        if (poll.done.load(.acquire) and self.state == .logging_in) {
            if (poll.err) |e| {
                self.login_err = e;
                self.state = .failed;
            } else {
                self.state = .done;
            }
        }
    }

    switch (self.state) {
        .done => {
            const auth_profile = self.profiles[self.list.selected].name;
            if (ctx.profile_set.indexOf(auth_profile)) |idx| {
                // Profile already in set (e.g. added via :profile add). Just refresh
                // its credentials from the SSO token file written by the poll thread.
                const entry = &ctx.profile_set.entries.items[idx];
                if (entry.store.credentials) |c| c.deinit(ctx.allocator);
                entry.store.credentials = null;
                _ = entry.store.getCredentials() catch {};
            } else {
                // Initial auth flow: replace the placeholder (e.g. "default") with the
                // authenticated profile so the primary store reads the correct SSO cache.
                ctx.profile_set.replaceWith(&[_][]const u8{auth_profile}) catch {};
                const store = ctx.profile_set.primaryStore();
                if (store.credentials) |c| c.deinit(ctx.allocator);
                store.credentials = null;
                _ = store.getCredentials() catch {};
            }
            input.notify();
            return .pop;
        },
        .failed => switch (event) {
            .key => |k| switch (k) {
                .ctrl_c => return .quit,
                else => return .pop,
            },
            else => {},
        },
        .logging_in => switch (event) {
            .key => |k| switch (k) {
                .ctrl_c => return .quit,
                .escape => {
                    if (self.poll_ctx) |poll| poll.cancel();
                    return .pop;
                },
                .char => |c| switch (c) {
                    'q' => {
                        if (self.poll_ctx) |poll| poll.cancel();
                        return .pop;
                    },
                    else => {},
                },
                else => {},
            },
            else => {},
        },
        .selecting => switch (event) {
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
                .enter => {
                    if (self.profiles.len == 0) return .none;
                    const selected = self.profiles[self.list.selected].name;

                    // Skip browser flow if the selected profile's credentials are still valid.
                    var selected_store = fetcher.CredentialsStore.init(self.allocator, self.io, self.env, .{
                        .profile_name = selected,
                    });
                    defer selected_store.deinit();
                    if (selected_store.getCredentials()) |_| {
                        self.state = .done;
                        return .none;
                    } else |_| {}

                    const poll_ctx = try self.allocator.create(sso.PollCtx);
                    errdefer self.allocator.destroy(poll_ctx);
                    poll_ctx.* = .{
                        .allocator = self.allocator,
                        .io = self.io,
                        .arena = std.heap.ArenaAllocator.init(self.allocator),
                        .done = std.atomic.Value(bool).init(false),
                    };

                    const url = sso.beginLogin(self.allocator, self.io, self.env, selected, poll_ctx) catch |e| {
                        poll_ctx.deinit();
                        self.allocator.destroy(poll_ctx);
                        self.login_err = e;
                        self.state = .failed;
                        return .none;
                    };

                    self.poll_ctx = poll_ctx;
                    self.login_url = url;
                    self.poll_thread = try std.Thread.spawn(.{}, sso.pollToken, .{poll_ctx});
                    self.state = .logging_in;
                },
                else => {},
            },
            else => {},
        },
    }
    return .none;
}

pub fn render(self: *SSOProfileView, writer: *std.Io.Writer, size: Coord) !void {
    if (size.x < 4 or size.y < 2) return;
    const w: usize = @intCast(size.x);
    const h: usize = @intCast(size.y);

    switch (self.state) {
        .selecting => {
            if (self.profiles.len == 0) {
                try renderMsg(self, writer, w, h, "No SSO profiles found in ~/.aws/config", "");
                return;
            }
            self.list.updateScroll(if (h >= 1) h - 1 else 0);
            for (0..h) |row| {
                try self.list.renderLine(writer, row + 1, w, h + 1);
                if (row + 1 < h) try writer.writeAll("\r\n");
            }
        },
        .logging_in => {
            try renderLoggingIn(self, writer, w, h);
        },
        .done => {
            try renderMsg(self, writer, w, h, "Login successful.", "");
        },
        .failed => {
            var buf: [128]u8 = undefined;
            const msg = if (self.login_err) |e|
                std.fmt.bufPrint(&buf, "Login failed: {s}", .{@errorName(e)}) catch "Login failed"
            else
                "Login failed";
            try renderMsg(self, writer, w, h, msg, "Press any key to dismiss");
        },
    }
}

fn renderMsg(self: *SSOProfileView, writer: *std.Io.Writer, w: usize, h: usize, line1: []const u8, line2: []const u8) !void {
    const inner_w = w - 2;
    const data_rows = if (h >= 2) h - 2 else 0;

    try writer.writeAll(self.fg_color);
    try writer.writeAll(constants.TOP_LEFT);
    for (0..inner_w) |_| try writer.writeAll(constants.HORIZONTAL);
    try writer.writeAll(constants.TOP_RIGHT);
    try writer.writeAll(terminal.RESET);
    try writer.writeAll("\r\n");

    for (0..data_rows) |row| {
        try writer.writeAll(self.fg_color);
        try writer.writeAll(constants.VERTICAL);
        try writer.writeAll(terminal.RESET);
        if (row == 0 and line1.len > 0) {
            const shown = line1[0..@min(line1.len, inner_w)];
            try writer.writeAll(shown);
            for (shown.len..inner_w) |_| try writer.writeByte(' ');
        } else if (row == 2 and line2.len > 0) {
            const shown = line2[0..@min(line2.len, inner_w)];
            try writer.writeAll(terminal.DIM);
            try writer.writeAll(shown);
            try writer.writeAll(terminal.RESET);
            for (shown.len..inner_w) |_| try writer.writeByte(' ');
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

fn renderLoggingIn(self: *SSOProfileView, writer: *std.Io.Writer, w: usize, h: usize) !void {
    const inner_w = w - 2;
    const data_rows = if (h >= 2) h - 2 else 0;

    const cancel_hint_row = 5; // index of "Esc / q: cancel" in lines below
    const lines = [_][]const u8{
        "Waiting for browser authorization...",
        "",
        "If your browser did not open, visit:",
        self.login_url,
        "",
        "Esc / q: cancel",
    };

    try writer.writeAll(self.fg_color);
    try writer.writeAll(constants.TOP_LEFT);
    for (0..inner_w) |_| try writer.writeAll(constants.HORIZONTAL);
    try writer.writeAll(constants.TOP_RIGHT);
    try writer.writeAll(terminal.RESET);
    try writer.writeAll("\r\n");

    for (0..data_rows) |row| {
        try writer.writeAll(self.fg_color);
        try writer.writeAll(constants.VERTICAL);
        try writer.writeAll(terminal.RESET);
        if (row < lines.len and lines[row].len > 0) {
            const shown = lines[row][0..@min(lines[row].len, inner_w)];
            if (row == cancel_hint_row) try writer.writeAll(terminal.DIM);
            try writer.writeAll(shown);
            if (row == cancel_hint_row) try writer.writeAll(terminal.RESET);
            for (shown.len..inner_w) |_| try writer.writeByte(' ');
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
