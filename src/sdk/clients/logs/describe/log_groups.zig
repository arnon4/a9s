const std = @import("std");
const Allocator = std.mem.Allocator;

const sigv4 = @import("../../../sig/sigv4.zig");
const Credentials = @import("../../../credentials/fetcher.zig").Credentials;

pub const LogGroupClass = enum {
    standard,
    infrequent_access,
    delivery,
    unknown,

    fn parse(s: []const u8) LogGroupClass {
        if (std.mem.eql(u8, s, "STANDARD")) return .standard;
        if (std.mem.eql(u8, s, "INFREQUENT_ACCESS")) return .infrequent_access;
        if (std.mem.eql(u8, s, "DELIVERY")) return .delivery;
        return .unknown;
    }
};

pub const DataProtectionStatus = enum {
    activated,
    deleted,
    archived,
    disabled,
    unknown,

    fn parse(s: []const u8) DataProtectionStatus {
        if (std.mem.eql(u8, s, "ACTIVATED")) return .activated;
        if (std.mem.eql(u8, s, "DELETED")) return .deleted;
        if (std.mem.eql(u8, s, "ARCHIVED")) return .archived;
        if (std.mem.eql(u8, s, "DISABLED")) return .disabled;
        return .unknown;
    }
};

pub const LogGroup = struct {
    allocator: Allocator,
    log_group_name: []u8,
    log_group_arn: []u8,
    arn: []u8,
    creation_time: ?i64,
    retention_in_days: ?i32,
    metric_filter_count: i32,
    stored_bytes: i64,
    kms_key_id: []u8,
    log_group_class: LogGroupClass,
    data_protection_status: DataProtectionStatus,

    pub fn deinit(self: LogGroup) void {
        self.allocator.free(self.log_group_name);
        self.allocator.free(self.log_group_arn);
        self.allocator.free(self.arn);
        self.allocator.free(self.kms_key_id);
    }
};

pub const Options = struct {
    /// Filter by prefix.
    log_group_name_prefix: ?[]const u8 = null,
    /// Filter by substring (cannot combine with prefix).
    log_group_name_pattern: ?[]const u8 = null,
    next_token: ?[]const u8 = null,
    limit: ?u32 = null,
    log_group_class: ?LogGroupClass = null,
    include_linked_accounts: ?bool = null,
    account_identifiers: ?[]const []const u8 = null,
};

pub const Result = struct {
    allocator: Allocator,
    log_groups: []LogGroup,
    next_token: ?[]u8,

    pub fn deinit(self: Result) void {
        for (self.log_groups) |g| g.deinit();
        self.allocator.free(self.log_groups);
        if (self.next_token) |t| self.allocator.free(t);
    }
};

// ============================================================================
// Public API
// ============================================================================

pub fn describeLogGroups(client: anytype, options: Options) !Result {
    return describeLogGroupsWithIo(
        client.allocator,
        client.io,
        client.credentials,
        client.region,
        client.endpoint,
        options,
    );
}

pub fn describeLogGroupsWithIo(
    allocator: Allocator,
    io: std.Io,
    credentials: Credentials,
    region: []const u8,
    endpoint: []const u8,
    options: Options,
) !Result {
    const body = try buildBody(allocator, options);
    defer allocator.free(body);

    var extra_headers = std.StringHashMap([]const u8).init(allocator);
    defer extra_headers.deinit();
    try extra_headers.put("Content-Type", "application/x-amz-json-1.1");
    try extra_headers.put("X-Amz-Target", "Logs_20140328.DescribeLogGroups");
    if (credentials.session_token) |token| {
        try extra_headers.put("X-Amz-Security-Token", token);
    }

    var signed = try sigv4.sign(
        allocator,
        io,
        .{
            .access_key = credentials.access_key_id,
            .secret_key = credentials.secret_access_key,
            .region = region,
            .service = "logs",
        },
        .POST,
        endpoint,
        extra_headers,
        body,
        null,
    );
    defer signed.deinit();

    var header_list: std.ArrayList(std.http.Header) = .empty;
    defer header_list.deinit(allocator);
    var it = signed.headers.iterator();
    while (it.next()) |entry| {
        if (std.ascii.eqlIgnoreCase(entry.key_ptr.*, "host")) continue;
        try header_list.append(allocator, .{ .name = entry.key_ptr.*, .value = entry.value_ptr.* });
    }

    var http_client = std.http.Client{ .allocator = allocator, .io = io };
    defer http_client.deinit();

    var body_writer: std.Io.Writer.Allocating = .init(allocator);
    defer body_writer.deinit();

    const result = try http_client.fetch(.{
        .method = .POST,
        .location = .{ .url = endpoint },
        .extra_headers = header_list.items,
        .payload = body,
        .response_writer = &body_writer.writer,
    });

    const response_body = body_writer.writer.buffer[0..body_writer.writer.end];

    if (result.status != .ok) {
        std.log.err("CloudWatch Logs DescribeLogGroups failed: status={} body={s}", .{ result.status, response_body });
        return error.LogsRequestFailed;
    }

    return parseResponse(allocator, response_body);
}

// ============================================================================
// Request builder
// ============================================================================

fn buildBody(allocator: Allocator, options: Options) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    try buf.appendSlice(allocator, "{");

    var first = true;

    if (options.log_group_name_prefix) |v| {
        try writeJsonStringField(&buf, allocator, "logGroupNamePrefix", v, &first);
    }
    if (options.log_group_name_pattern) |v| {
        try writeJsonStringField(&buf, allocator, "logGroupNamePattern", v, &first);
    }
    if (options.next_token) |v| {
        try writeJsonStringField(&buf, allocator, "nextToken", v, &first);
    }
    if (options.limit) |v| {
        if (!first) try buf.appendSlice(allocator, ",");
        first = false;
        const s = try std.fmt.allocPrint(allocator, "\"limit\":{d}", .{v});
        defer allocator.free(s);
        try buf.appendSlice(allocator, s);
    }
    if (options.log_group_class) |v| {
        const wire = switch (v) {
            .standard => "STANDARD",
            .infrequent_access => "INFREQUENT_ACCESS",
            .delivery => "DELIVERY",
            .unknown => "STANDARD",
        };
        try writeJsonStringField(&buf, allocator, "logGroupClass", wire, &first);
    }
    if (options.include_linked_accounts) |v| {
        if (!first) try buf.appendSlice(allocator, ",");
        first = false;
        try buf.appendSlice(allocator, if (v) "\"includeLinkedAccounts\":true" else "\"includeLinkedAccounts\":false");
    }
    if (options.account_identifiers) |ids| {
        if (!first) try buf.appendSlice(allocator, ",");
        first = false;
        try buf.appendSlice(allocator, "\"accountIdentifiers\":[");
        for (ids, 0..) |id, i| {
            if (i > 0) try buf.appendSlice(allocator, ",");
            try buf.append(allocator, '"');
            try buf.appendSlice(allocator, id);
            try buf.append(allocator, '"');
        }
        try buf.appendSlice(allocator, "]");
    }

    try buf.appendSlice(allocator, "}");
    return buf.toOwnedSlice(allocator);
}

fn writeJsonStringField(
    buf: *std.ArrayList(u8),
    allocator: Allocator,
    key: []const u8,
    value: []const u8,
    first: *bool,
) !void {
    if (!first.*) try buf.appendSlice(allocator, ",");
    first.* = false;
    try buf.append(allocator, '"');
    try buf.appendSlice(allocator, key);
    try buf.appendSlice(allocator, "\":\"");
    try buf.appendSlice(allocator, value);
    try buf.append(allocator, '"');
}

fn jsonStr(obj: std.json.ObjectMap, key: []const u8) []const u8 {
    const v = obj.get(key) orelse return "";
    return switch (v) {
        .string => |s| s,
        else => "",
    };
}

fn jsonI64(obj: std.json.ObjectMap, key: []const u8) ?i64 {
    const v = obj.get(key) orelse return null;
    return switch (v) {
        .integer => |i| i,
        .float => |f| @intFromFloat(f),
        else => null,
    };
}

fn jsonI32(obj: std.json.ObjectMap, key: []const u8) ?i32 {
    const v = obj.get(key) orelse return null;
    return switch (v) {
        .integer => |i| @intCast(i),
        else => null,
    };
}

fn parseLogGroup(allocator: Allocator, obj: std.json.ObjectMap) !LogGroup {
    const log_group_name = try allocator.dupe(u8, jsonStr(obj, "logGroupName"));
    errdefer allocator.free(log_group_name);
    const log_group_arn = try allocator.dupe(u8, jsonStr(obj, "logGroupArn"));
    errdefer allocator.free(log_group_arn);
    const arn = try allocator.dupe(u8, jsonStr(obj, "arn"));
    errdefer allocator.free(arn);
    const kms_key_id = try allocator.dupe(u8, jsonStr(obj, "kmsKeyId"));
    errdefer allocator.free(kms_key_id);

    const lg_class = blk: {
        const v = obj.get("logGroupClass") orelse break :blk LogGroupClass.standard;
        break :blk switch (v) {
            .string => |s| LogGroupClass.parse(s),
            else => LogGroupClass.standard,
        };
    };

    const dp_status = blk: {
        const v = obj.get("dataProtectionStatus") orelse break :blk DataProtectionStatus.unknown;
        break :blk switch (v) {
            .string => |s| DataProtectionStatus.parse(s),
            else => DataProtectionStatus.unknown,
        };
    };

    return .{
        .allocator = allocator,
        .log_group_name = log_group_name,
        .log_group_arn = log_group_arn,
        .arn = arn,
        .creation_time = jsonI64(obj, "creationTime"),
        .retention_in_days = jsonI32(obj, "retentionInDays"),
        .metric_filter_count = @intCast(jsonI64(obj, "metricFilterCount") orelse 0),
        .stored_bytes = jsonI64(obj, "storedBytes") orelse 0,
        .kms_key_id = kms_key_id,
        .log_group_class = lg_class,
        .data_protection_status = dp_status,
    };
}

fn parseResponse(allocator: Allocator, body: []const u8) !Result {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    const root = switch (parsed.value) {
        .object => |o| o,
        else => return error.UnexpectedJsonType,
    };

    var groups: std.ArrayList(LogGroup) = .empty;
    errdefer {
        for (groups.items) |g| g.deinit();
        groups.deinit(allocator);
    }

    if (root.get("logGroups")) |val| {
        switch (val) {
            .array => |arr| {
                for (arr.items) |item| {
                    switch (item) {
                        .object => |obj| {
                            const g = try parseLogGroup(allocator, obj);
                            errdefer g.deinit();
                            try groups.append(allocator, g);
                        },
                        else => {},
                    }
                }
            },
            else => {},
        }
    }

    const next_token: ?[]u8 = blk: {
        const v = root.get("nextToken") orelse break :blk null;
        break :blk switch (v) {
            .string => |s| try allocator.dupe(u8, s),
            else => null,
        };
    };
    errdefer if (next_token) |t| allocator.free(t);

    return .{
        .allocator = allocator,
        .log_groups = try groups.toOwnedSlice(allocator),
        .next_token = next_token,
    };
}

test "buildBody empty options" {
    const allocator = std.testing.allocator;
    const body = try buildBody(allocator, .{});
    defer allocator.free(body);
    try std.testing.expectEqualStrings("{}", body);
}

test "buildBody with prefix and limit" {
    const allocator = std.testing.allocator;
    const body = try buildBody(allocator, .{
        .log_group_name_prefix = "/aws/lambda",
        .limit = 50,
    });
    defer allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"logGroupNamePrefix\":\"/aws/lambda\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"limit\":50") != null);
}

test "buildBody with next_token" {
    const allocator = std.testing.allocator;
    const body = try buildBody(allocator, .{ .next_token = "tok123" });
    defer allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"nextToken\":\"tok123\"") != null);
}

test "parseResponse basic" {
    const allocator = std.testing.allocator;
    const response =
        \\{
        \\  "logGroups": [
        \\    {
        \\      "logGroupName": "/aws/lambda/my-fn",
        \\      "logGroupArn": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/my-fn:*",
        \\      "arn": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/my-fn",
        \\      "creationTime": 1700000000000,
        \\      "retentionInDays": 30,
        \\      "metricFilterCount": 0,
        \\      "storedBytes": 2048,
        \\      "logGroupClass": "STANDARD"
        \\    }
        \\  ]
        \\}
    ;
    const result = try parseResponse(allocator, response);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.log_groups.len);
    const g = result.log_groups[0];
    try std.testing.expectEqualStrings("/aws/lambda/my-fn", g.log_group_name);
    try std.testing.expectEqual(@as(?i64, 1700000000000), g.creation_time);
    try std.testing.expectEqual(@as(?i32, 30), g.retention_in_days);
    try std.testing.expectEqual(@as(i64, 2048), g.stored_bytes);
    try std.testing.expectEqual(LogGroupClass.standard, g.log_group_class);
    try std.testing.expect(result.next_token == null);
}

test "parseResponse with nextToken" {
    const allocator = std.testing.allocator;
    const response =
        \\{"logGroups":[],"nextToken":"abc"}
    ;
    const result = try parseResponse(allocator, response);
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 0), result.log_groups.len);
    try std.testing.expectEqualStrings("abc", result.next_token.?);
}
