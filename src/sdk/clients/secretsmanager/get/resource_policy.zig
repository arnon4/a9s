const std = @import("std");
const Allocator = std.mem.Allocator;

const sigv4 = @import("../../../sig/sigv4.zig");
const aws_errors = @import("../../aws_errors.zig");
const Credentials = @import("../../../credentials/fetcher.zig").Credentials;

pub const GetResourcePolicyError = error{
    ResourceNotFoundException,
    InvalidParameterException,
    InvalidRequestException,
    InternalServiceError,
};

pub const Options = struct {
    secret_id: []const u8,
};

pub const Result = struct {
    allocator: Allocator,
    arn: []u8,
    name: []u8,
    resource_policy: ?[]u8,

    pub fn deinit(self: Result) void {
        self.allocator.free(self.arn);
        self.allocator.free(self.name);
        if (self.resource_policy) |p| self.allocator.free(p);
    }
};

// ============================================================================
// Public API
// ============================================================================

pub fn getResourcePolicy(client: anytype, options: Options) !Result {
    return getResourcePolicyWithIo(
        client.allocator,
        client.io,
        client.credentials,
        client.region,
        client.endpoint,
        options,
    );
}

pub fn getResourcePolicyWithIo(
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
    try extra_headers.put("X-Amz-Target", "secretsmanager.GetResourcePolicy");
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
            std.log.err("Secrets Manager GetResourcePolicy error: {s} (status {d})", .{ code, @intFromEnum(result.status) });
            inline for (@typeInfo(GetResourcePolicyError).error_set.?) |entry| {
                if (std.mem.eql(u8, entry.name, code)) return @field(GetResourcePolicyError, entry.name);
            }
            return aws_errors.fromCode(code) orelse aws_errors.fromStatus(result.status);
        }
        std.log.err("Secrets Manager GetResourcePolicy error: status {d} body={s}", .{ @intFromEnum(result.status), response_body });
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
    try buf.appendSlice(allocator, "\"}");

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

    const resource_policy: ?[]u8 = blk: {
        const v = root.get("ResourcePolicy") orelse break :blk null;
        break :blk switch (v) {
            .string => |s| try allocator.dupe(u8, s),
            else => null,
        };
    };
    errdefer if (resource_policy) |p| allocator.free(p);

    return .{
        .allocator = allocator,
        .arn = arn,
        .name = name,
        .resource_policy = resource_policy,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "buildBody" {
    const allocator = std.testing.allocator;
    const body = try buildBody(allocator, .{ .secret_id = "my-secret" });
    defer allocator.free(body);
    try std.testing.expectEqualStrings("{\"SecretId\":\"my-secret\"}", body);
}

test "parseResponse with policy" {
    const allocator = std.testing.allocator;
    const response =
        \\{
        \\  "ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:my-secret-AbCdEf",
        \\  "Name": "my-secret",
        \\  "ResourcePolicy": "{\"Version\":\"2012-10-17\"}"
        \\}
    ;
    const result = try parseResponse(allocator, response);
    defer result.deinit();

    try std.testing.expectEqualStrings("my-secret", result.name);
    try std.testing.expectEqualStrings("{\"Version\":\"2012-10-17\"}", result.resource_policy.?);
}

test "parseResponse without policy" {
    const allocator = std.testing.allocator;
    const response =
        \\{"ARN":"arn:aws:secretsmanager:us-east-1:123:secret:s","Name":"s"}
    ;
    const result = try parseResponse(allocator, response);
    defer result.deinit();
    try std.testing.expect(result.resource_policy == null);
}
