//! Follows `NextToken` across the pages of an EC2 describe call.
const std = @import("std");
const Allocator = std.mem.Allocator;

/// Calls `fetch` until it stops returning a token and merges the pages into one result.
///
/// `Result` must have an `allocator`, a slice field named `items_field` of `Item`, and an optional
/// owned `next_token`; `params` must have an optional `next_token`. The merged result has no token.
/// Each item is moved into the merged slice, so only a page's container and token are released here.
pub fn collect(
    comptime Item: type,
    comptime Result: type,
    comptime items_field: []const u8,
    allocator: Allocator,
    comptime Ctx: type,
    ctx: Ctx,
    params: anytype,
    comptime fetch: fn (Ctx, @TypeOf(params)) anyerror!Result,
) !Result {
    var all: std.ArrayList(Item) = .empty;
    errdefer {
        for (all.items) |x| x.deinit();
        all.deinit(allocator);
    }

    var page_params = params;
    var token: ?[]u8 = null;
    defer if (token) |t| allocator.free(t);

    while (true) {
        page_params.next_token = token;
        const got = try fetch(ctx, page_params);
        all.appendSlice(allocator, @field(got, items_field)) catch |e| {
            got.deinit();
            return e;
        };
        allocator.free(@field(got, items_field));
        if (token) |t| allocator.free(t);
        token = got.next_token;
        if (token == null) break;
    }

    var merged: Result = undefined;
    merged.allocator = allocator;
    @field(merged, items_field) = try all.toOwnedSlice(allocator);
    merged.next_token = null;
    return merged;
}

// ============================================================================
// Tests
// ============================================================================

const TestItem = struct {
    allocator: Allocator,
    name: []u8,

    fn deinit(self: TestItem) void {
        self.allocator.free(self.name);
    }
};

const TestResult = struct {
    allocator: Allocator,
    things: []TestItem,
    next_token: ?[]u8,

    fn deinit(self: TestResult) void {
        for (self.things) |t| t.deinit();
        self.allocator.free(self.things);
        if (self.next_token) |t| self.allocator.free(t);
    }
};

const TestParams = struct {
    next_token: ?[]const u8 = null,
};

fn testPage(allocator: Allocator, name: []const u8, token: ?[]const u8) !TestResult {
    const things = try allocator.alloc(TestItem, 1);
    things[0] = .{ .allocator = allocator, .name = try allocator.dupe(u8, name) };
    return .{
        .allocator = allocator,
        .things = things,
        .next_token = if (token) |t| try allocator.dupe(u8, t) else null,
    };
}

const Pager = struct {
    calls: usize = 0,
    tokens_seen: [4]usize = @splat(0),

    fn fetch(self: *Pager, params: TestParams) anyerror!TestResult {
        // Record only the token's length: the slice is freed once the next page arrives.
        self.tokens_seen[self.calls] = if (params.next_token) |t| t.len else 0;
        defer self.calls += 1;
        return switch (self.calls) {
            0 => testPage(std.testing.allocator, "a", "T1"),
            1 => testPage(std.testing.allocator, "b", "T22"),
            else => testPage(std.testing.allocator, "c", null),
        };
    }
};

test "collect merges every page and passes each token to the next call" {
    var pager: Pager = .{};
    const result = try collect(TestItem, TestResult, "things", std.testing.allocator, *Pager, &pager, TestParams{}, Pager.fetch);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 3), pager.calls);
    try std.testing.expectEqual(@as(usize, 3), result.things.len);
    try std.testing.expectEqualStrings("a", result.things[0].name);
    try std.testing.expectEqualStrings("b", result.things[1].name);
    try std.testing.expectEqualStrings("c", result.things[2].name);
    try std.testing.expect(result.next_token == null);
    try std.testing.expectEqual(@as(usize, 0), pager.tokens_seen[0]);
    try std.testing.expectEqual(@as(usize, 2), pager.tokens_seen[1]);
    try std.testing.expectEqual(@as(usize, 3), pager.tokens_seen[2]);
}

test "collect returns a single page as is" {
    const Single = struct {
        fn fetch(_: void, _: TestParams) anyerror!TestResult {
            return testPage(std.testing.allocator, "only", null);
        }
    };
    const result = try collect(TestItem, TestResult, "things", std.testing.allocator, void, {}, TestParams{}, Single.fetch);
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 1), result.things.len);
    try std.testing.expectEqualStrings("only", result.things[0].name);
}

test "collect releases earlier pages when a later one fails" {
    const Failing = struct {
        calls: usize = 0,

        fn fetch(self: *@This(), _: TestParams) anyerror!TestResult {
            self.calls += 1;
            if (self.calls == 2) return error.RequestLimitExceeded;
            return testPage(std.testing.allocator, "a", "T1");
        }
    };
    var failing: Failing = .{};
    try std.testing.expectError(
        error.RequestLimitExceeded,
        collect(TestItem, TestResult, "things", std.testing.allocator, *Failing, &failing, TestParams{}, Failing.fetch),
    );
}
