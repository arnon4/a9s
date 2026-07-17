const std = @import("std");
const Allocator = std.mem.Allocator;

pub const SubCmd = enum { add, remove, use, show };

pub const RegionCommand = struct {
    arena: std.heap.ArenaAllocator,
    subcmd: SubCmd,
    regions: []const []const u8,

    pub fn deinit(self: *RegionCommand) void {
        self.arena.deinit();
    }
};

pub const ParseError = error{ UnknownSubcommand, OutOfMemory };

/// Parse text after "region" (trimmed).
pub fn parse(allocator: Allocator, text: []const u8) ParseError!RegionCommand {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();

    var it = std.mem.tokenizeScalar(u8, text, ' ');
    const subcmd_str = it.next() orelse return error.UnknownSubcommand;

    const subcmd: SubCmd = blk: {
        if (std.mem.eql(u8, subcmd_str, "add")) break :blk .add;
        if (std.mem.eql(u8, subcmd_str, "remove")) break :blk .remove;
        if (std.mem.eql(u8, subcmd_str, "use")) break :blk .use;
        if (std.mem.eql(u8, subcmd_str, "show")) break :blk .show;
        return error.UnknownSubcommand;
    };

    var regions: std.ArrayList([]const u8) = .empty;
    while (it.next()) |tok| {
        try regions.append(a, try a.dupe(u8, tok));
    }

    return .{
        .arena = arena,
        .subcmd = subcmd,
        .regions = try regions.toOwnedSlice(a),
    };
}

// ============================================================================
// Tests
// ============================================================================

test "parse use single" {
    var cmd = try parse(std.testing.allocator, "use us-east-1");
    defer cmd.deinit();
    try std.testing.expect(cmd.subcmd == .use);
    try std.testing.expectEqual(@as(usize, 1), cmd.regions.len);
    try std.testing.expectEqualStrings("us-east-1", cmd.regions[0]);
}

test "parse add multiple" {
    var cmd = try parse(std.testing.allocator, "add eu-west-1 ap-southeast-1");
    defer cmd.deinit();
    try std.testing.expect(cmd.subcmd == .add);
    try std.testing.expectEqual(@as(usize, 2), cmd.regions.len);
}

test "parse remove" {
    var cmd = try parse(std.testing.allocator, "remove us-west-2");
    defer cmd.deinit();
    try std.testing.expect(cmd.subcmd == .remove);
}

test "parse unknown subcmd" {
    const result = parse(std.testing.allocator, "list");
    try std.testing.expectError(error.UnknownSubcommand, result);
}
