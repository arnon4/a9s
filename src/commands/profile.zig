const std = @import("std");
const Allocator = std.mem.Allocator;

pub const SubCmd = enum { add, use, remove, show, logout, logout_all };

pub const ProfileCommand = struct {
    arena: std.heap.ArenaAllocator,
    subcmd: SubCmd,
    profiles: []const []const u8,

    pub fn deinit(self: *ProfileCommand) void {
        self.arena.deinit();
    }
};

pub const ParseError = error{ UnknownSubcommand, OutOfMemory };

/// Parse text after "profile" (trimmed).
pub fn parse(allocator: Allocator, text: []const u8) ParseError!ProfileCommand {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();

    var it = std.mem.tokenizeScalar(u8, text, ' ');
    const subcmd_str = it.next() orelse return error.UnknownSubcommand;

    const subcmd: SubCmd = blk: {
        if (std.mem.eql(u8, subcmd_str, "add")) break :blk .add;
        if (std.mem.eql(u8, subcmd_str, "use")) break :blk .use;
        if (std.mem.eql(u8, subcmd_str, "remove")) break :blk .remove;
        if (std.mem.eql(u8, subcmd_str, "show")) break :blk .show;
        if (std.mem.eql(u8, subcmd_str, "logout")) break :blk .logout;
        if (std.mem.eql(u8, subcmd_str, "logout-all")) break :blk .logout_all;
        return error.UnknownSubcommand;
    };

    var profiles: std.ArrayList([]const u8) = .empty;
    while (it.next()) |tok| {
        try profiles.append(a, try a.dupe(u8, tok));
    }

    return .{
        .arena = arena,
        .subcmd = subcmd,
        .profiles = try profiles.toOwnedSlice(a),
    };
}

// ============================================================================
// Tests
// ============================================================================

test "parse use single" {
    var cmd = try parse(std.testing.allocator, "use my-profile");
    defer cmd.deinit();
    try std.testing.expect(cmd.subcmd == .use);
    try std.testing.expectEqual(@as(usize, 1), cmd.profiles.len);
    try std.testing.expectEqualStrings("my-profile", cmd.profiles[0]);
}

test "parse add multiple" {
    var cmd = try parse(std.testing.allocator, "add alpha beta gamma");
    defer cmd.deinit();
    try std.testing.expect(cmd.subcmd == .add);
    try std.testing.expectEqual(@as(usize, 3), cmd.profiles.len);
}

test "parse show no args" {
    var cmd = try parse(std.testing.allocator, "show");
    defer cmd.deinit();
    try std.testing.expect(cmd.subcmd == .show);
    try std.testing.expectEqual(@as(usize, 0), cmd.profiles.len);
}

test "parse logout-all" {
    var cmd = try parse(std.testing.allocator, "logout-all");
    defer cmd.deinit();
    try std.testing.expect(cmd.subcmd == .logout_all);
}

test "parse unknown subcmd" {
    const result = parse(std.testing.allocator, "frobnicate foo");
    try std.testing.expectError(error.UnknownSubcommand, result);
}
