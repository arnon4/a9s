const std = @import("std");
const Allocator = std.mem.Allocator;

const sigv4 = @import("../../../sig/sigv4.zig");
const Credentials = @import("../../../credentials/fetcher.zig").Credentials;

pub const LogGroupField = struct {
    allocator: Allocator,
    name: []u8,
    /// Percentage of log events (0-100) containing this field.
    percent: i32,

    pub fn deinit(self: LogGroupField) void {
        self.allocator.free(self.name);
    }
};

pub const Options = struct {
    /// Required unless log_group_identifier is set.
    log_group_name: ?[]const u8 = null,
    log_group_identifier: ?[]const u8 = null,
    /// Epoch millis. Constrains the field search to a recent time window.
    time: ?i64 = null,
};

pub const Result = struct {
    allocator: Allocator,
    log_group_fields: []LogGroupField,

    pub fn deinit(self: Result) void {
        for (self.log_group_fields) |f| f.deinit();
        self.allocator.free(self.log_group_fields);
    }
};

pub fn getLogGroupFields(client: anytype, options: Options) !Result {
    return getLogGroupFieldsWithIo(
        client.allocator,
        client.io,
        client.credentials,
        client.region,
        client.endpoint,
        options,
    );
}

pub fn getLogGroupFieldsWithIo(
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
    try extra_headers.put("X-Amz-Target", "Logs_20140328.GetLogGroupFields");
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
        std.log.err("CloudWatch Logs GetLogGroupFields failed: status={} body={s}", .{ result.status, response_body });
        return error.LogsRequestFailed;
    }

    return parseResponse(allocator, response_body);
}

fn buildBody(allocator: Allocator, options: Options) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    try buf.appendSlice(allocator, "{");

    var first = true;

    if (options.log_group_name) |v| {
        try writeJsonStringField(&buf, allocator, "logGroupName", v, &first);
    }
    if (options.log_group_identifier) |v| {
        try writeJsonStringField(&buf, allocator, "logGroupIdentifier", v, &first);
    }
    if (options.time) |v| {
        if (!first) try buf.appendSlice(allocator, ",");
        first = false;
        const s = try std.fmt.allocPrint(allocator, "\"time\":{d}", .{v});
        defer allocator.free(s);
        try buf.appendSlice(allocator, s);
    }

    try buf.appendSlice(allocator, "}");
    return buf.toOwnedSlice(allocator);
}

fn writeJsonStringField(buf: *std.ArrayList(u8), allocator: Allocator, key: []const u8, value: []const u8, first: *bool) !void {
    if (!first.*) try buf.appendSlice(allocator, ",");
    first.* = false;
    try buf.append(allocator, '"');
    try buf.appendSlice(allocator, key);
    try buf.appendSlice(allocator, "\":\"");
    try buf.appendSlice(allocator, value);
    try buf.append(allocator, '"');
}

fn parseResponse(allocator: Allocator, body: []const u8) !Result {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    const root = switch (parsed.value) {
        .object => |o| o,
        else => return error.UnexpectedJsonType,
    };

    var fields: std.ArrayList(LogGroupField) = .empty;
    errdefer {
        for (fields.items) |f| f.deinit();
        fields.deinit(allocator);
    }

    if (root.get("logGroupFields")) |val| {
        switch (val) {
            .array => |arr| {
                for (arr.items) |item| {
                    switch (item) {
                        .object => |obj| {
                            const f = try parseField(allocator, obj);
                            errdefer f.deinit();
                            try fields.append(allocator, f);
                        },
                        else => {},
                    }
                }
            },
            else => {},
        }
    }

    return .{
        .allocator = allocator,
        .log_group_fields = try fields.toOwnedSlice(allocator),
    };
}

fn parseField(allocator: Allocator, obj: std.json.ObjectMap) !LogGroupField {
    const name_raw = obj.get("name") orelse return error.MissingField;
    const name = switch (name_raw) {
        .string => |s| try allocator.dupe(u8, s),
        else => return error.UnexpectedJsonType,
    };
    errdefer allocator.free(name);

    const percent: i32 = blk: {
        const v = obj.get("percent") orelse break :blk 0;
        break :blk switch (v) {
            .integer => |i| @intCast(i),
            else => 0,
        };
    };

    return .{
        .allocator = allocator,
        .name = name,
        .percent = percent,
    };
}

test "buildBody name only" {
    const allocator = std.testing.allocator;
    const body = try buildBody(allocator, .{ .log_group_name = "/aws/ecs/app" });
    defer allocator.free(body);
    try std.testing.expectEqualStrings("{\"logGroupName\":\"/aws/ecs/app\"}", body);
}

test "buildBody with time" {
    const allocator = std.testing.allocator;
    const body = try buildBody(allocator, .{
        .log_group_name = "/aws/ecs/app",
        .time = 1700000000000,
    });
    defer allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"time\":1700000000000") != null);
}

test "buildBody identifier only" {
    const allocator = std.testing.allocator;
    const body = try buildBody(allocator, .{
        .log_group_identifier = "arn:aws:logs:us-east-1:123456789012:log-group:/aws/ecs/app",
    });
    defer allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"logGroupIdentifier\"") != null);
}

test "parseResponse basic" {
    const allocator = std.testing.allocator;
    const response =
        \\{
        \\  "logGroupFields": [
        \\    {"name": "@timestamp", "percent": 100},
        \\    {"name": "@message",   "percent": 100},
        \\    {"name": "@requestId", "percent": 82},
        \\    {"name": "level",      "percent": 74}
        \\  ]
        \\}
    ;
    const result = try parseResponse(allocator, response);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 4), result.log_group_fields.len);
    try std.testing.expectEqualStrings("@timestamp", result.log_group_fields[0].name);
    try std.testing.expectEqual(@as(i32, 100), result.log_group_fields[0].percent);
    try std.testing.expectEqualStrings("@requestId", result.log_group_fields[2].name);
    try std.testing.expectEqual(@as(i32, 82), result.log_group_fields[2].percent);
}

test "parseResponse empty" {
    const allocator = std.testing.allocator;
    const result = try parseResponse(allocator, "{\"logGroupFields\":[]}");
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 0), result.log_group_fields.len);
}
