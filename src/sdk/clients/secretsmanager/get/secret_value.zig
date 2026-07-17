const std = @import("std");
const Allocator = std.mem.Allocator;

const sigv4 = @import("../../../sig/sigv4.zig");
const aws_errors = @import("../../aws_errors.zig");
const Credentials = @import("../../../credentials/fetcher.zig").Credentials;

pub const GetSecretValueError = error{
    ResourceNotFoundException,
    InvalidParameterException,
    InvalidRequestException,
    DecryptionFailure,
    InternalServiceError,
};

pub const Options = struct {
    secret_id: []const u8,
    version_id: ?[]const u8 = null,
    version_stage: ?[]const u8 = null,
};

pub const Result = struct {
    allocator: Allocator,
    arn: []u8,
    name: []u8,
    version_id: []u8,
    secret_string: ?[]u8,
    secret_binary: ?[]u8,
    version_stages: [][]u8,
    created_date: ?f64,

    pub fn deinit(self: Result) void {
        self.allocator.free(self.arn);
        self.allocator.free(self.name);
        self.allocator.free(self.version_id);
        if (self.secret_string) |s| self.allocator.free(s);
        if (self.secret_binary) |s| self.allocator.free(s);
        for (self.version_stages) |s| self.allocator.free(s);
        self.allocator.free(self.version_stages);
    }
};

// ============================================================================
// Public API
// ============================================================================

pub fn getSecretValue(client: anytype, options: Options) !Result {
    return getSecretValueWithIo(
        client.allocator,
        client.io,
        client.credentials,
        client.region,
        client.endpoint,
        options,
    );
}

pub fn getSecretValueWithIo(
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
    try extra_headers.put("X-Amz-Target", "secretsmanager.GetSecretValue");
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
            .service = "secretsmanager",
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
            std.log.err("Secrets Manager GetSecretValue error: {s} (status {d})", .{ code, @intFromEnum(result.status) });
            inline for (@typeInfo(GetSecretValueError).error_set.?) |entry| {
                if (std.mem.eql(u8, entry.name, code)) return @field(GetSecretValueError, entry.name);
            }
            return aws_errors.fromCode(code) orelse aws_errors.fromStatus(result.status);
        }
        std.log.err("Secrets Manager GetSecretValue error: status {d} body={s}", .{ @intFromEnum(result.status), response_body });
        return aws_errors.fromStatus(result.status);
    }

    return parseResponse(allocator, response_body);
}

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

// ============================================================================
// Request builder
// ============================================================================

fn buildBody(allocator: Allocator, options: Options) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    try buf.appendSlice(allocator, "{\"SecretId\":\"");
    try buf.appendSlice(allocator, options.secret_id);
    try buf.appendSlice(allocator, "\"");

    if (options.version_id) |v| {
        try buf.appendSlice(allocator, ",\"VersionId\":\"");
        try buf.appendSlice(allocator, v);
        try buf.appendSlice(allocator, "\"");
    }
    if (options.version_stage) |v| {
        try buf.appendSlice(allocator, ",\"VersionStage\":\"");
        try buf.appendSlice(allocator, v);
        try buf.appendSlice(allocator, "\"");
    }

    try buf.appendSlice(allocator, "}");
    return buf.toOwnedSlice(allocator);
}

// ============================================================================
// Response parser
// ============================================================================

fn jsonStr(obj: std.json.ObjectMap, key: []const u8) []const u8 {
    const v = obj.get(key) orelse return "";
    return switch (v) {
        .string => |s| s,
        else => "",
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

    const arn = try allocator.dupe(u8, jsonStr(root, "ARN"));
    errdefer allocator.free(arn);
    const name = try allocator.dupe(u8, jsonStr(root, "Name"));
    errdefer allocator.free(name);
    const version_id = try allocator.dupe(u8, jsonStr(root, "VersionId"));
    errdefer allocator.free(version_id);

    const secret_string: ?[]u8 = blk: {
        const v = root.get("SecretString") orelse break :blk null;
        break :blk switch (v) {
            .string => |s| try allocator.dupe(u8, s),
            else => null,
        };
    };
    errdefer if (secret_string) |s| allocator.free(s);

    const secret_binary: ?[]u8 = blk: {
        const v = root.get("SecretBinary") orelse break :blk null;
        break :blk switch (v) {
            .string => |s| try allocator.dupe(u8, s),
            else => null,
        };
    };
    errdefer if (secret_binary) |s| allocator.free(s);

    var stages: std.ArrayList([]u8) = .empty;
    errdefer {
        for (stages.items) |s| allocator.free(s);
        stages.deinit(allocator);
    }
    if (root.get("VersionStages")) |val| {
        switch (val) {
            .array => |arr| {
                for (arr.items) |item| {
                    switch (item) {
                        .string => |s| try stages.append(allocator, try allocator.dupe(u8, s)),
                        else => {},
                    }
                }
            },
            else => {},
        }
    }

    return .{
        .allocator = allocator,
        .arn = arn,
        .name = name,
        .version_id = version_id,
        .secret_string = secret_string,
        .secret_binary = secret_binary,
        .version_stages = try stages.toOwnedSlice(allocator),
        .created_date = jsonF64(root, "CreatedDate"),
    };
}

// ============================================================================
// Tests
// ============================================================================

test "buildBody secret id only" {
    const allocator = std.testing.allocator;
    const body = try buildBody(allocator, .{ .secret_id = "my-secret" });
    defer allocator.free(body);
    try std.testing.expectEqualStrings("{\"SecretId\":\"my-secret\"}", body);
}

test "buildBody with version stage" {
    const allocator = std.testing.allocator;
    const body = try buildBody(allocator, .{ .secret_id = "my-secret", .version_stage = "AWSCURRENT" });
    defer allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"VersionStage\":\"AWSCURRENT\"") != null);
}

test "parseResponse basic" {
    const allocator = std.testing.allocator;
    const response =
        \\{
        \\  "ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:my-secret-AbCdEf",
        \\  "Name": "my-secret",
        \\  "VersionId": "v1",
        \\  "SecretString": "{\"user\":\"admin\"}",
        \\  "VersionStages": ["AWSCURRENT"],
        \\  "CreatedDate": 1700000000.5
        \\}
    ;
    const result = try parseResponse(allocator, response);
    defer result.deinit();

    try std.testing.expectEqualStrings("my-secret", result.name);
    try std.testing.expectEqualStrings("v1", result.version_id);
    try std.testing.expectEqualStrings("{\"user\":\"admin\"}", result.secret_string.?);
    try std.testing.expect(result.secret_binary == null);
    try std.testing.expectEqual(@as(usize, 1), result.version_stages.len);
    try std.testing.expectEqualStrings("AWSCURRENT", result.version_stages[0]);
    try std.testing.expectEqual(@as(?f64, 1700000000.5), result.created_date);
}
