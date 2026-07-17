const std = @import("std");
const Allocator = std.mem.Allocator;

const sigv4 = @import("../../../sig/sigv4.zig");
const Credentials = @import("../../../credentials/fetcher.zig").Credentials;

pub const OutputLogEvent = struct {
    allocator: Allocator,
    message: []u8,
    timestamp: i64,
    ingestion_time: ?i64,

    pub fn deinit(self: OutputLogEvent) void {
        self.allocator.free(self.message);
    }
};

pub const Options = struct {
    /// Required unless log_group_identifier is set.
    log_group_name: ?[]const u8 = null,
    log_group_identifier: ?[]const u8 = null,
    /// Required.
    log_stream_name: []const u8,
    start_time: ?i64 = null,
    end_time: ?i64 = null,
    next_token: ?[]const u8 = null,
    /// Max 10000.
    limit: ?u32 = null,
    /// If true, reads oldest events first. Default false (newest first).
    start_from_head: ?bool = null,
    /// Unmask sensitive log data protected by data protection policy.
    unmask: ?bool = null,
};

pub const Result = struct {
    allocator: Allocator,
    events: []OutputLogEvent,
    next_forward_token: ?[]u8,
    next_backward_token: ?[]u8,

    pub fn deinit(self: Result) void {
        for (self.events) |e| e.deinit();
        self.allocator.free(self.events);
        if (self.next_forward_token) |t| self.allocator.free(t);
        if (self.next_backward_token) |t| self.allocator.free(t);
    }
};

// ============================================================================
// Public API
// ============================================================================

pub fn getLogEvents(client: anytype, options: Options) !Result {
    return getLogEventsWithIo(
        client.allocator,
        client.io,
        client.credentials,
        client.region,
        client.endpoint,
        options,
    );
}

pub fn getLogEventsWithIo(
    allocator: Allocator,
    io: std.Io,
    credentials: Credentials,
    region: []const u8,
    endpoint: []const u8,
    options: Options,
) !Result {
    const body = try buildBody(allocator, options);
    defer allocator.free(body);

    std.log.debug("GetLogEvents request: body={s}", .{body});

    var extra_headers = std.StringHashMap([]const u8).init(allocator);
    defer extra_headers.deinit();
    try extra_headers.put("Content-Type", "application/x-amz-json-1.1");
    try extra_headers.put("X-Amz-Target", "Logs_20140328.GetLogEvents");
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

    std.log.debug("GetLogEvents response: status={} body_len={d}", .{ result.status, response_body.len });
    if (response_body.len < 512) {
        std.log.debug("GetLogEvents body={s}", .{response_body});
    }

    if (result.status != .ok) {
        std.log.err("CloudWatch Logs GetLogEvents failed: status={} body={s}", .{ result.status, response_body });
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
    try writeJsonStringField(&buf, allocator, "logStreamName", options.log_stream_name, &first);

    if (options.start_time) |v| {
        try writeJsonI64Field(&buf, allocator, "startTime", v, &first);
    }
    if (options.end_time) |v| {
        try writeJsonI64Field(&buf, allocator, "endTime", v, &first);
    }
    if (options.next_token) |v| {
        try writeJsonStringField(&buf, allocator, "nextToken", v, &first);
    }
    if (options.limit) |v| {
        try writeJsonU32Field(&buf, allocator, "limit", v, &first);
    }
    if (options.start_from_head) |v| {
        try writeJsonBoolField(&buf, allocator, "startFromHead", v, &first);
    }
    if (options.unmask) |v| {
        try writeJsonBoolField(&buf, allocator, "unmask", v, &first);
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

fn writeJsonI64Field(buf: *std.ArrayList(u8), allocator: Allocator, key: []const u8, value: i64, first: *bool) !void {
    if (!first.*) try buf.appendSlice(allocator, ",");
    first.* = false;
    const s = try std.fmt.allocPrint(allocator, "\"{s}\":{d}", .{ key, value });
    defer allocator.free(s);
    try buf.appendSlice(allocator, s);
}

fn writeJsonU32Field(buf: *std.ArrayList(u8), allocator: Allocator, key: []const u8, value: u32, first: *bool) !void {
    if (!first.*) try buf.appendSlice(allocator, ",");
    first.* = false;
    const s = try std.fmt.allocPrint(allocator, "\"{s}\":{d}", .{ key, value });
    defer allocator.free(s);
    try buf.appendSlice(allocator, s);
}

fn writeJsonBoolField(buf: *std.ArrayList(u8), allocator: Allocator, key: []const u8, value: bool, first: *bool) !void {
    if (!first.*) try buf.appendSlice(allocator, ",");
    first.* = false;
    const s = try std.fmt.allocPrint(allocator, "\"{s}\":{s}", .{ key, if (value) "true" else "false" });
    defer allocator.free(s);
    try buf.appendSlice(allocator, s);
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

fn parseLogEvent(allocator: Allocator, obj: std.json.ObjectMap) !OutputLogEvent {
    const message = try allocator.dupe(u8, jsonStr(obj, "message"));
    errdefer allocator.free(message);

    return .{
        .allocator = allocator,
        .message = message,
        .timestamp = jsonI64(obj, "timestamp") orelse 0,
        .ingestion_time = jsonI64(obj, "ingestionTime"),
    };
}

fn parseResponse(allocator: Allocator, body: []const u8) !Result {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    const root = switch (parsed.value) {
        .object => |o| o,
        else => return error.UnexpectedJsonType,
    };

    var events: std.ArrayList(OutputLogEvent) = .empty;
    errdefer {
        for (events.items) |e| e.deinit();
        events.deinit(allocator);
    }

    if (root.get("events")) |val| {
        switch (val) {
            .array => |arr| {
                for (arr.items) |item| {
                    switch (item) {
                        .object => |obj| {
                            const e = try parseLogEvent(allocator, obj);
                            errdefer e.deinit();
                            try events.append(allocator, e);
                        },
                        else => {},
                    }
                }
            },
            else => {},
        }
    }

    const next_forward_token: ?[]u8 = blk: {
        const v = root.get("nextForwardToken") orelse break :blk null;
        break :blk switch (v) {
            .string => |s| try allocator.dupe(u8, s),
            else => null,
        };
    };
    errdefer if (next_forward_token) |t| allocator.free(t);

    const next_backward_token: ?[]u8 = blk: {
        const v = root.get("nextBackwardToken") orelse break :blk null;
        break :blk switch (v) {
            .string => |s| try allocator.dupe(u8, s),
            else => null,
        };
    };
    errdefer if (next_backward_token) |t| allocator.free(t);

    return .{
        .allocator = allocator,
        .events = try events.toOwnedSlice(allocator),
        .next_forward_token = next_forward_token,
        .next_backward_token = next_backward_token,
    };
}

test "buildBody required field only" {
    const allocator = std.testing.allocator;
    const body = try buildBody(allocator, .{
        .log_group_name = "/aws/lambda/fn",
        .log_stream_name = "2024/01/15/stream",
    });
    defer allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"logGroupName\":\"/aws/lambda/fn\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"logStreamName\":\"2024/01/15/stream\"") != null);
}

test "buildBody with time range and limit" {
    const allocator = std.testing.allocator;
    const body = try buildBody(allocator, .{
        .log_group_name = "/aws/lambda/fn",
        .log_stream_name = "stream",
        .start_time = 1700000000000,
        .end_time = 1700003600000,
        .limit = 100,
        .start_from_head = true,
    });
    defer allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"startTime\":1700000000000") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"endTime\":1700003600000") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"limit\":100") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"startFromHead\":true") != null);
}

test "parseResponse basic" {
    const allocator = std.testing.allocator;
    const response =
        \\{
        \\  "events": [
        \\    {
        \\      "timestamp": 1705312210000,
        \\      "message": "START RequestId: abc-123 Version: $LATEST\n",
        \\      "ingestionTime": 1705312215000
        \\    },
        \\    {
        \\      "timestamp": 1705312211000,
        \\      "message": "END RequestId: abc-123\n",
        \\      "ingestionTime": 1705312215000
        \\    }
        \\  ],
        \\  "nextForwardToken": "f/fwd-tok",
        \\  "nextBackwardToken": "b/bwd-tok"
        \\}
    ;
    const result = try parseResponse(allocator, response);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 2), result.events.len);
    try std.testing.expectEqual(@as(i64, 1705312210000), result.events[0].timestamp);
    try std.testing.expect(std.mem.startsWith(u8, result.events[0].message, "START"));
    try std.testing.expectEqual(@as(?i64, 1705312215000), result.events[0].ingestion_time);
    try std.testing.expectEqualStrings("f/fwd-tok", result.next_forward_token.?);
    try std.testing.expectEqualStrings("b/bwd-tok", result.next_backward_token.?);
}

test "parseResponse empty events" {
    const allocator = std.testing.allocator;
    const response =
        \\{"events":[],"nextForwardToken":"f/tok","nextBackwardToken":"b/tok"}
    ;
    const result = try parseResponse(allocator, response);
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 0), result.events.len);
}
