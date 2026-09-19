const std = @import("std");
const Allocator = std.mem.Allocator;

const sigv4 = @import("../../../sig/sigv4.zig");
const aws_errors = @import("../../aws_errors.zig");
const Credentials = @import("../../../credentials/fetcher.zig").Credentials;

pub const GetTrailStatusError = error{ TrailNotFoundException, InvalidTrailNameException };

pub const Options = struct {
    /// Trail name or ARN. Required.
    name: []const u8,
};

pub const Result = struct {
    allocator: Allocator,
    is_logging: bool,
    latest_delivery_error: []u8,
    latest_notification_error: []u8,
    latest_delivery_time: ?f64,
    latest_notification_time: ?f64,
    start_logging_time: ?f64,
    stop_logging_time: ?f64,
    latest_cloud_watch_logs_delivery_error: []u8,
    latest_cloud_watch_logs_delivery_time: ?f64,

    pub fn deinit(self: Result) void {
        self.allocator.free(self.latest_delivery_error);
        self.allocator.free(self.latest_notification_error);
        self.allocator.free(self.latest_cloud_watch_logs_delivery_error);
    }
};

// ============================================================================
// Public API
// ============================================================================

pub fn getTrailStatus(client: anytype, options: Options) !Result {
    return getTrailStatusWithIo(
        client.allocator,
        client.io,
        client.credentials,
        client.region,
        client.endpoint,
        options,
    );
}

pub fn getTrailStatusWithIo(
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
    try extra_headers.put("X-Amz-Target", "CloudTrail_20131101.GetTrailStatus");
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
            .service = "cloudtrail",
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
        const code_str = extractJsonString(allocator, response_body, "__type") catch null;
        defer if (code_str) |c| allocator.free(c);
        if (code_str) |full_code| {
            const code = if (std.mem.lastIndexOfScalar(u8, full_code, '#')) |idx|
                full_code[idx + 1 ..]
            else
                full_code;
            std.log.err("CloudTrail GetTrailStatus error: {s} (status {d})", .{ code, @intFromEnum(result.status) });
            inline for (@typeInfo(GetTrailStatusError).error_set.?) |entry| {
                if (std.mem.eql(u8, entry.name, code)) return @field(GetTrailStatusError, entry.name);
            }
            return aws_errors.fromCode(code) orelse aws_errors.fromStatus(result.status);
        }
        std.log.err("CloudTrail GetTrailStatus error: status {d} body={s}", .{ @intFromEnum(result.status), response_body });
        return aws_errors.fromStatus(result.status);
    }

    return parseResponse(allocator, response_body);
}

// ============================================================================
// Request builder
// ============================================================================

fn buildBody(allocator: Allocator, options: Options) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    try buf.appendSlice(allocator, "{\"Name\":\"");
    try buf.appendSlice(allocator, options.name);
    try buf.appendSlice(allocator, "\"}");
    return buf.toOwnedSlice(allocator);
}

// ============================================================================
// Response parser
// ============================================================================

fn extractJsonString(allocator: Allocator, json: []const u8, key: []const u8) ![]u8 {
    const needle = try std.fmt.allocPrint(allocator, "\"{s}\"", .{key});
    defer allocator.free(needle);

    const pos = std.mem.indexOf(u8, json, needle) orelse return error.KeyNotFound;
    const after_key = json[pos + needle.len ..];
    const colon = std.mem.indexOfScalar(u8, after_key, ':') orelse return error.KeyNotFound;
    const after_colon = std.mem.trimStart(u8, after_key[colon + 1 ..], " \t\r\n");
    if (after_colon.len == 0 or after_colon[0] != '"') return error.KeyNotFound;
    const content = after_colon[1..];
    const end = std.mem.indexOfScalar(u8, content, '"') orelse return error.KeyNotFound;
    return allocator.dupe(u8, content[0..end]);
}

fn jsonStr(obj: std.json.ObjectMap, key: []const u8) []const u8 {
    const v = obj.get(key) orelse return "";
    return switch (v) {
        .string => |s| s,
        else => "",
    };
}

fn jsonBool(obj: std.json.ObjectMap, key: []const u8) bool {
    const v = obj.get(key) orelse return false;
    return switch (v) {
        .bool => |b| b,
        else => false,
    };
}

fn jsonF64(obj: std.json.ObjectMap, key: []const u8) ?f64 {
    const v = obj.get(key) orelse return null;
    return switch (v) {
        .float => |f| f,
        .integer => |i| @floatFromInt(i),
        else => null,
    };
}

fn parseResponse(allocator: Allocator, body: []const u8) !Result {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    const root = switch (parsed.value) {
        .object => |o| o,
        else => return error.UnexpectedJsonType,
    };

    const latest_delivery_error = try allocator.dupe(u8, jsonStr(root, "LatestDeliveryError"));
    errdefer allocator.free(latest_delivery_error);
    const latest_notification_error = try allocator.dupe(u8, jsonStr(root, "LatestNotificationError"));
    errdefer allocator.free(latest_notification_error);
    const latest_cw_error = try allocator.dupe(u8, jsonStr(root, "LatestCloudWatchLogsDeliveryError"));
    errdefer allocator.free(latest_cw_error);

    return .{
        .allocator = allocator,
        .is_logging = jsonBool(root, "IsLogging"),
        .latest_delivery_error = latest_delivery_error,
        .latest_notification_error = latest_notification_error,
        .latest_delivery_time = jsonF64(root, "LatestDeliveryTime"),
        .latest_notification_time = jsonF64(root, "LatestNotificationTime"),
        .start_logging_time = jsonF64(root, "StartLoggingTime"),
        .stop_logging_time = jsonF64(root, "StopLoggingTime"),
        .latest_cloud_watch_logs_delivery_error = latest_cw_error,
        .latest_cloud_watch_logs_delivery_time = jsonF64(root, "LatestCloudWatchLogsDeliveryTime"),
    };
}

// ============================================================================
// Tests
// ============================================================================

test "buildBody" {
    const allocator = std.testing.allocator;
    const body = try buildBody(allocator, .{ .name = "my-trail" });
    defer allocator.free(body);
    try std.testing.expectEqualStrings("{\"Name\":\"my-trail\"}", body);
}

test "parseResponse basic" {
    const allocator = std.testing.allocator;
    const response =
        \\{
        \\  "IsLogging": true,
        \\  "LatestDeliveryTime": 1700000000.123,
        \\  "StartLoggingTime": 1699000000.0,
        \\  "LatestDeliveryError": ""
        \\}
    ;
    const result = try parseResponse(allocator, response);
    defer result.deinit();

    try std.testing.expect(result.is_logging);
    try std.testing.expectEqual(@as(?f64, 1700000000.123), result.latest_delivery_time);
    try std.testing.expectEqual(@as(?f64, 1699000000.0), result.start_logging_time);
    try std.testing.expect(result.stop_logging_time == null);
    try std.testing.expectEqualStrings("", result.latest_delivery_error);
}

test "parseResponse logging disabled with errors" {
    const allocator = std.testing.allocator;
    const response =
        \\{
        \\  "IsLogging": false,
        \\  "LatestDeliveryError": "InsufficientS3BucketPolicyException",
        \\  "StopLoggingTime": 1700100000.0
        \\}
    ;
    const result = try parseResponse(allocator, response);
    defer result.deinit();

    try std.testing.expect(!result.is_logging);
    try std.testing.expectEqualStrings("InsufficientS3BucketPolicyException", result.latest_delivery_error);
    try std.testing.expectEqual(@as(?f64, 1700100000.0), result.stop_logging_time);
}
