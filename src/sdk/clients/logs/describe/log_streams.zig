const std = @import("std");
const Allocator = std.mem.Allocator;

const sigv4 = @import("../../../sig/sigv4.zig");
const Credentials = @import("../../../credentials/fetcher.zig").Credentials;

pub const OrderBy = enum {
    log_stream_name,
    last_event_time,

    fn wireValue(self: OrderBy) []const u8 {
        return switch (self) {
            .log_stream_name => "LogStreamName",
            .last_event_time => "LastEventTime",
        };
    }
};

pub const LogStream = struct {
    allocator: Allocator,
    log_stream_name: []u8,
    arn: []u8,
    creation_time: ?i64,
    first_event_timestamp: ?i64,
    last_event_timestamp: ?i64,
    last_ingestion_time: ?i64,
    upload_sequence_token: []u8,
    stored_bytes: i64,

    pub fn deinit(self: LogStream) void {
        self.allocator.free(self.log_stream_name);
        self.allocator.free(self.arn);
        self.allocator.free(self.upload_sequence_token);
    }
};

pub const Options = struct {
    /// Log group name. Required if log_group_identifier is not set.
    log_group_name: ?[]const u8 = null,
    /// Log group ARN or name with account prefix. Alternative to log_group_name.
    log_group_identifier: ?[]const u8 = null,
    log_stream_name_prefix: ?[]const u8 = null,
    order_by: ?OrderBy = null,
    descending: ?bool = null,
    next_token: ?[]const u8 = null,
    limit: ?u32 = null,
};

pub const Result = struct {
    allocator: Allocator,
    log_streams: []LogStream,
    next_token: ?[]u8,

    pub fn deinit(self: Result) void {
        for (self.log_streams) |s| s.deinit();
        self.allocator.free(self.log_streams);
        if (self.next_token) |t| self.allocator.free(t);
    }
};

// ============================================================================
// Public API
// ============================================================================

pub fn describeLogStreams(client: anytype, options: Options) !Result {
    return describeLogStreamsWithIo(
        client.allocator,
        client.io,
        client.credentials,
        client.region,
        client.endpoint,
        options,
    );
}

pub fn describeLogStreamsWithIo(
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
    try extra_headers.put("X-Amz-Target", "Logs_20140328.DescribeLogStreams");
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
        std.log.err("CloudWatch Logs DescribeLogStreams failed: status={} body={s}", .{ result.status, response_body });
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

    if (options.log_group_name) |v| {
        try writeJsonStringField(&buf, allocator, "logGroupName", v, &first);
    }
    if (options.log_group_identifier) |v| {
        try writeJsonStringField(&buf, allocator, "logGroupIdentifier", v, &first);
    }
    if (options.log_stream_name_prefix) |v| {
        try writeJsonStringField(&buf, allocator, "logStreamNamePrefix", v, &first);
    }
    if (options.order_by) |v| {
        try writeJsonStringField(&buf, allocator, "orderBy", v.wireValue(), &first);
    }
    if (options.descending) |v| {
        if (!first) try buf.appendSlice(allocator, ",");
        first = false;
        try buf.appendSlice(allocator, if (v) "\"descending\":true" else "\"descending\":false");
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

fn parseLogStream(allocator: Allocator, obj: std.json.ObjectMap) !LogStream {
    const log_stream_name = try allocator.dupe(u8, jsonStr(obj, "logStreamName"));
    errdefer allocator.free(log_stream_name);
    const arn = try allocator.dupe(u8, jsonStr(obj, "arn"));
    errdefer allocator.free(arn);
    const upload_sequence_token = try allocator.dupe(u8, jsonStr(obj, "uploadSequenceToken"));
    errdefer allocator.free(upload_sequence_token);

    return .{
        .allocator = allocator,
        .log_stream_name = log_stream_name,
        .arn = arn,
        .creation_time = jsonI64(obj, "creationTime"),
        .first_event_timestamp = jsonI64(obj, "firstEventTimestamp"),
        .last_event_timestamp = jsonI64(obj, "lastEventTimestamp"),
        .last_ingestion_time = jsonI64(obj, "lastIngestionTime"),
        .upload_sequence_token = upload_sequence_token,
        .stored_bytes = jsonI64(obj, "storedBytes") orelse 0,
    };
}

fn parseResponse(allocator: Allocator, body: []const u8) !Result {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    const root = switch (parsed.value) {
        .object => |o| o,
        else => return error.UnexpectedJsonType,
    };

    var streams: std.ArrayList(LogStream) = .empty;
    errdefer {
        for (streams.items) |s| s.deinit();
        streams.deinit(allocator);
    }

    if (root.get("logStreams")) |val| {
        switch (val) {
            .array => |arr| {
                for (arr.items) |item| {
                    switch (item) {
                        .object => |obj| {
                            const s = try parseLogStream(allocator, obj);
                            errdefer s.deinit();
                            try streams.append(allocator, s);
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
        .log_streams = try streams.toOwnedSlice(allocator),
        .next_token = next_token,
    };
}

test "buildBody log_group_name only" {
    const allocator = std.testing.allocator;
    const body = try buildBody(allocator, .{ .log_group_name = "/aws/lambda/my-fn" });
    defer allocator.free(body);
    try std.testing.expectEqualStrings("{\"logGroupName\":\"/aws/lambda/my-fn\"}", body);
}

test "buildBody with order_by descending and limit" {
    const allocator = std.testing.allocator;
    const body = try buildBody(allocator, .{
        .log_group_name = "/aws/ecs/app",
        .order_by = .last_event_time,
        .descending = true,
        .limit = 25,
    });
    defer allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"orderBy\":\"LastEventTime\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"descending\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"limit\":25") != null);
}

test "buildBody with prefix and next_token" {
    const allocator = std.testing.allocator;
    const body = try buildBody(allocator, .{
        .log_group_name = "/aws/lambda/my-fn",
        .log_stream_name_prefix = "2024",
        .next_token = "tok456",
    });
    defer allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"logStreamNamePrefix\":\"2024\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"nextToken\":\"tok456\"") != null);
}

test "parseResponse basic" {
    const allocator = std.testing.allocator;
    const response =
        \\{
        \\  "logStreams": [
        \\    {
        \\      "logStreamName": "2024/01/15/[$LATEST]abc123",
        \\      "arn": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/fn:log-stream:2024/01/15/[$LATEST]abc123",
        \\      "creationTime": 1705312200000,
        \\      "firstEventTimestamp": 1705312210000,
        \\      "lastEventTimestamp": 1705312250000,
        \\      "lastIngestionTime": 1705312260000,
        \\      "uploadSequenceToken": "seq-1",
        \\      "storedBytes": 0
        \\    }
        \\  ]
        \\}
    ;
    const result = try parseResponse(allocator, response);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.log_streams.len);
    const s = result.log_streams[0];
    try std.testing.expectEqualStrings("2024/01/15/[$LATEST]abc123", s.log_stream_name);
    try std.testing.expectEqual(@as(?i64, 1705312200000), s.creation_time);
    try std.testing.expectEqual(@as(?i64, 1705312210000), s.first_event_timestamp);
    try std.testing.expectEqual(@as(?i64, 1705312250000), s.last_event_timestamp);
    try std.testing.expectEqualStrings("seq-1", s.upload_sequence_token);
    try std.testing.expect(result.next_token == null);
}

test "parseResponse with nextToken" {
    const allocator = std.testing.allocator;
    const response =
        \\{"logStreams":[],"nextToken":"next-page"}
    ;
    const result = try parseResponse(allocator, response);
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 0), result.log_streams.len);
    try std.testing.expectEqualStrings("next-page", result.next_token.?);
}
