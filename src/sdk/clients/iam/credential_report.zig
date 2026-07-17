const std = @import("std");
const Allocator = std.mem.Allocator;

/// Per-user fields parsed out of the IAM credential report CSV that have no
/// cheaper direct API equivalent (password_last_changed is not exposed by
/// GetUser/GetLoginProfile; mfa_active is included here too since it comes
/// for free once the report is already fetched).
pub const UserCredentialInfo = struct {
    password_enabled: bool,
    /// Owned. Null if the user has no password or the report used "not_supported"/"N/A".
    password_last_changed: ?[]u8,
    mfa_active: bool,
};

pub const CredentialReport = struct {
    allocator: Allocator,
    users: std.StringHashMap(UserCredentialInfo),

    pub fn deinit(self: *CredentialReport) void {
        var it = self.users.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            if (entry.value_ptr.password_last_changed) |d| self.allocator.free(d);
        }
        self.users.deinit();
    }

    pub fn get(self: *const CredentialReport, user_name: []const u8) ?UserCredentialInfo {
        return self.users.get(user_name);
    }
};

fn isMissing(s: []const u8) bool {
    return s.len == 0 or std.mem.eql(u8, s, "N/A") or std.mem.eql(u8, s, "not_supported") or std.mem.eql(u8, s, "no_information");
}

/// Finds the byte index of `name` in a header row already split on ','.
fn columnIndex(headers: []const []const u8, name: []const u8) ?usize {
    for (headers, 0..) |h, i| {
        if (std.mem.eql(u8, std.mem.trim(u8, h, " \r"), name)) return i;
    }
    return null;
}

/// Parses the raw CSV content returned by GetCredentialReport. Caller owns
/// the returned report and must call deinit.
pub fn parse(allocator: Allocator, csv: []const u8) !CredentialReport {
    var users = std.StringHashMap(UserCredentialInfo).init(allocator);
    errdefer {
        var it = users.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            if (entry.value_ptr.password_last_changed) |d| allocator.free(d);
        }
        users.deinit();
    }

    var lines = std.mem.splitScalar(u8, csv, '\n');
    const header_line = lines.next() orelse return .{ .allocator = allocator, .users = users };

    var header_cols: std.ArrayList([]const u8) = .empty;
    defer header_cols.deinit(allocator);
    var header_it = std.mem.splitScalar(u8, std.mem.trimEnd(u8, header_line, "\r"), ',');
    while (header_it.next()) |col| try header_cols.append(allocator, col);

    const user_idx = columnIndex(header_cols.items, "user") orelse return .{ .allocator = allocator, .users = users };
    const password_enabled_idx = columnIndex(header_cols.items, "password_enabled");
    const password_last_changed_idx = columnIndex(header_cols.items, "password_last_changed");
    const mfa_active_idx = columnIndex(header_cols.items, "mfa_active");

    while (lines.next()) |raw_line| {
        const line = std.mem.trimEnd(u8, raw_line, "\r");
        if (line.len == 0) continue;

        var cols: std.ArrayList([]const u8) = .empty;
        defer cols.deinit(allocator);
        var col_it = std.mem.splitScalar(u8, line, ',');
        while (col_it.next()) |col| try cols.append(allocator, col);

        if (user_idx >= cols.items.len) continue;
        const user_name = cols.items[user_idx];
        if (user_name.len == 0) continue;

        const password_enabled = if (password_enabled_idx) |i|
            (i < cols.items.len and std.mem.eql(u8, cols.items[i], "true"))
        else
            false;

        const password_last_changed: ?[]u8 = if (password_last_changed_idx) |i|
            if (i < cols.items.len and !isMissing(cols.items[i]))
                try allocator.dupe(u8, cols.items[i])
            else
                null
        else
            null;
        errdefer if (password_last_changed) |d| allocator.free(d);

        const mfa_active = if (mfa_active_idx) |i|
            (i < cols.items.len and std.mem.eql(u8, cols.items[i], "true"))
        else
            false;

        const key = try allocator.dupe(u8, user_name);
        errdefer allocator.free(key);
        try users.put(key, .{
            .password_enabled = password_enabled,
            .password_last_changed = password_last_changed,
            .mfa_active = mfa_active,
        });
    }

    return .{ .allocator = allocator, .users = users };
}

// ============================================================================
// Tests
// ============================================================================

test "parse basic report" {
    const csv =
        "user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active\n" ++
        "alice,arn:aws:iam::123:user/alice,2020-01-01T00:00:00Z,true,2024-01-01T00:00:00Z,2023-06-01T00:00:00Z,N/A,true,true\n" ++
        "bob,arn:aws:iam::123:user/bob,2020-01-01T00:00:00Z,false,N/A,N/A,N/A,false,false\n";

    var report = try parse(std.testing.allocator, csv);
    defer report.deinit();

    const alice = report.get("alice").?;
    try std.testing.expect(alice.password_enabled);
    try std.testing.expectEqualStrings("2023-06-01T00:00:00Z", alice.password_last_changed.?);
    try std.testing.expect(alice.mfa_active);

    const bob = report.get("bob").?;
    try std.testing.expect(!bob.password_enabled);
    try std.testing.expect(bob.password_last_changed == null);
    try std.testing.expect(!bob.mfa_active);

    try std.testing.expect(report.get("carol") == null);
}

test "parse empty report" {
    var report = try parse(std.testing.allocator, "");
    defer report.deinit();
    try std.testing.expect(report.get("alice") == null);
}

test "parse header only" {
    var report = try parse(std.testing.allocator, "user,arn\n");
    defer report.deinit();
    try std.testing.expect(report.get("alice") == null);
}
