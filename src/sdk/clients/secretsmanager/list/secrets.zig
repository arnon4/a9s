const std = @import("std");
const Allocator = std.mem.Allocator;

const sigv4 = @import("../../../sig/sigv4.zig");
const aws_errors = @import("../../aws_errors.zig");
const Credentials = @import("../../../credentials/fetcher.zig").Credentials;

pub const ListSecretsError = error{
    InvalidNextTokenException,
    InvalidParameterException,
};

pub const Filter = struct {
    key: []const u8,
    values: []const []const u8,
};

pub const Options = struct {
    filters: ?[]const Filter = null,
    include_planned_deletion: ?bool = null,
    max_results: ?u32 = null,
    next_token: ?[]const u8 = null,
    sort_order: ?[]const u8 = null,
};

pub const Tag = struct {
    allocator: Allocator,
    key: []u8,
    value: []u8,

    pub fn deinit(self: Tag) void {
        self.allocator.free(self.key);
        self.allocator.free(self.value);
    }
};

pub const SecretEntry = struct {
    allocator: Allocator,
    arn: []u8,
    name: []u8,
    description: []u8,
    kms_key_id: []u8,
    rotation_enabled: bool,
    rotation_lambda_arn: []u8,
    last_rotated_date: ?f64,
    last_changed_date: ?f64,
    last_accessed_date: ?f64,
    deleted_date: ?f64,
    next_rotation_date: ?f64,
    created_date: ?f64,
    primary_region: []u8,
    owning_service: []u8,
    tags: []Tag,

    pub fn deinit(self: SecretEntry) void {
        self.allocator.free(self.arn);
        self.allocator.free(self.name);
        self.allocator.free(self.description);
        self.allocator.free(self.kms_key_id);
        self.allocator.free(self.rotation_lambda_arn);
        self.allocator.free(self.primary_region);
        self.allocator.free(self.owning_service);
        for (self.tags) |t| t.deinit();
        self.allocator.free(self.tags);
    }
};

pub const Result = struct {
    allocator: Allocator,
    secrets: []SecretEntry,
    next_token: ?[]u8,

    pub fn deinit(self: Result) void {
        for (self.secrets) |s| s.deinit();
        self.allocator.free(self.secrets);
        if (self.next_token) |t| self.allocator.free(t);
    }
};

// ============================================================================
// Public API
// ============================================================================

pub fn listSecrets(client: anytype, options: Options) !Result {
    return listSecretsWithIo(
        client.allocator,
        client.io,
        client.credentials,
        client.region,
        client.endpoint,
        options,
    );
}

pub fn listSecretsWithIo(
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
    try extra_headers.put("X-Amz-Target", "secretsmanager.ListSecrets");
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
            std.log.err("Secrets Manager ListSecrets error: {s} (status {d})", .{ code, @intFromEnum(result.status) });
            inline for (@typeInfo(ListSecretsError).error_set.?) |entry| {
                if (std.mem.eql(u8, entry.name, code)) return @field(ListSecretsError, entry.name);
            }
            return aws_errors.fromCode(code) orelse aws_errors.fromStatus(result.status);
        }
        std.log.err("Secrets Manager ListSecrets error: status {d} body={s}", .{ @intFromEnum(result.status), response_body });
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

    try buf.appendSlice(allocator, "{");
    var first = true;

    if (options.filters) |filters| {
        if (!first) try buf.appendSlice(allocator, ",");
        first = false;
        try buf.appendSlice(allocator, "\"Filters\":[");
        for (filters, 0..) |f, i| {
            if (i > 0) try buf.appendSlice(allocator, ",");
            try buf.appendSlice(allocator, "{\"Key\":\"");
            try buf.appendSlice(allocator, f.key);
            try buf.appendSlice(allocator, "\",\"Values\":[");
            for (f.values, 0..) |v, j| {
                if (j > 0) try buf.appendSlice(allocator, ",");
                try buf.append(allocator, '"');
                try buf.appendSlice(allocator, v);
                try buf.append(allocator, '"');
            }
            try buf.appendSlice(allocator, "]}");
        }
        try buf.appendSlice(allocator, "]");
    }
    if (options.include_planned_deletion) |v| {
        if (!first) try buf.appendSlice(allocator, ",");
        first = false;
        try buf.appendSlice(allocator, if (v) "\"IncludePlannedDeletion\":true" else "\"IncludePlannedDeletion\":false");
    }
    if (options.max_results) |v| {
        if (!first) try buf.appendSlice(allocator, ",");
        first = false;
        const s = try std.fmt.allocPrint(allocator, "\"MaxResults\":{d}", .{v});
        defer allocator.free(s);
        try buf.appendSlice(allocator, s);
    }
    if (options.next_token) |v| {
        try writeJsonStringField(&buf, allocator, "NextToken", v, &first);
    }
    if (options.sort_order) |v| {
        try writeJsonStringField(&buf, allocator, "SortOrder", v, &first);
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

fn parseTags(allocator: Allocator, obj: std.json.ObjectMap) ![]Tag {
    var tags: std.ArrayList(Tag) = .empty;
    errdefer {
        for (tags.items) |t| t.deinit();
        tags.deinit(allocator);
    }

    if (obj.get("Tags")) |val| {
        switch (val) {
            .array => |arr| {
                for (arr.items) |item| {
                    switch (item) {
                        .object => |tag_obj| {
                            const key = try allocator.dupe(u8, jsonStr(tag_obj, "Key"));
                            errdefer allocator.free(key);
                            const value = try allocator.dupe(u8, jsonStr(tag_obj, "Value"));
                            errdefer allocator.free(value);
                            try tags.append(allocator, .{ .allocator = allocator, .key = key, .value = value });
                        },
                        else => {},
                    }
                }
            },
            else => {},
        }
    }

    return tags.toOwnedSlice(allocator);
}

fn parseSecretEntry(allocator: Allocator, obj: std.json.ObjectMap) !SecretEntry {
    const arn = try allocator.dupe(u8, jsonStr(obj, "ARN"));
    errdefer allocator.free(arn);
    const name = try allocator.dupe(u8, jsonStr(obj, "Name"));
    errdefer allocator.free(name);
    const description = try allocator.dupe(u8, jsonStr(obj, "Description"));
    errdefer allocator.free(description);
    const kms_key_id = try allocator.dupe(u8, jsonStr(obj, "KmsKeyId"));
    errdefer allocator.free(kms_key_id);
    const rotation_lambda_arn = try allocator.dupe(u8, jsonStr(obj, "RotationLambdaARN"));
    errdefer allocator.free(rotation_lambda_arn);
    const primary_region = try allocator.dupe(u8, jsonStr(obj, "PrimaryRegion"));
    errdefer allocator.free(primary_region);
    const owning_service = try allocator.dupe(u8, jsonStr(obj, "OwningService"));
    errdefer allocator.free(owning_service);
    const tags = try parseTags(allocator, obj);
    errdefer {
        for (tags) |t| t.deinit();
        allocator.free(tags);
    }

    return .{
        .allocator = allocator,
        .arn = arn,
        .name = name,
        .description = description,
        .kms_key_id = kms_key_id,
        .rotation_enabled = jsonBool(obj, "RotationEnabled"),
        .rotation_lambda_arn = rotation_lambda_arn,
        .last_rotated_date = jsonF64(obj, "LastRotatedDate"),
        .last_changed_date = jsonF64(obj, "LastChangedDate"),
        .last_accessed_date = jsonF64(obj, "LastAccessedDate"),
        .deleted_date = jsonF64(obj, "DeletedDate"),
        .next_rotation_date = jsonF64(obj, "NextRotationDate"),
        .created_date = jsonF64(obj, "CreatedDate"),
        .primary_region = primary_region,
        .owning_service = owning_service,
        .tags = tags,
    };
}

fn parseResponse(allocator: Allocator, body: []const u8) !Result {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    const root = switch (parsed.value) {
        .object => |o| o,
        else => return error.UnexpectedJsonType,
    };

    var secrets: std.ArrayList(SecretEntry) = .empty;
    errdefer {
        for (secrets.items) |s| s.deinit();
        secrets.deinit(allocator);
    }

    if (root.get("SecretList")) |val| {
        switch (val) {
            .array => |arr| {
                for (arr.items) |item| {
                    switch (item) {
                        .object => |obj| {
                            const s = try parseSecretEntry(allocator, obj);
                            errdefer s.deinit();
                            try secrets.append(allocator, s);
                        },
                        else => {},
                    }
                }
            },
            else => {},
        }
    }

    const next_token: ?[]u8 = blk: {
        const v = root.get("NextToken") orelse break :blk null;
        break :blk switch (v) {
            .string => |s| try allocator.dupe(u8, s),
            else => null,
        };
    };
    errdefer if (next_token) |t| allocator.free(t);

    return .{
        .allocator = allocator,
        .secrets = try secrets.toOwnedSlice(allocator),
        .next_token = next_token,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "buildBody empty options" {
    const allocator = std.testing.allocator;
    const body = try buildBody(allocator, .{});
    defer allocator.free(body);
    try std.testing.expectEqualStrings("{}", body);
}

test "buildBody with max_results and next_token" {
    const allocator = std.testing.allocator;
    const body = try buildBody(allocator, .{ .max_results = 20, .next_token = "tok" });
    defer allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"MaxResults\":20") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"NextToken\":\"tok\"") != null);
}

test "buildBody with filters" {
    const allocator = std.testing.allocator;
    const values = [_][]const u8{"prod/"};
    const filters = [_]Filter{.{ .key = "name", .values = &values }};
    const body = try buildBody(allocator, .{ .filters = &filters });
    defer allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"Filters\":[{\"Key\":\"name\",\"Values\":[\"prod/\"]}]") != null);
}

test "parseResponse basic" {
    const allocator = std.testing.allocator;
    const response =
        \\{
        \\  "SecretList": [
        \\    {
        \\      "ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:my-secret-AbCdEf",
        \\      "Name": "my-secret",
        \\      "Description": "test secret",
        \\      "KmsKeyId": "alias/aws/secretsmanager",
        \\      "RotationEnabled": true,
        \\      "RotationLambdaARN": "arn:aws:lambda:us-east-1:123456789012:function:rotate",
        \\      "LastChangedDate": 1700000000.123,
        \\      "CreatedDate": 1690000000.0,
        \\      "Tags": [{"Key": "env", "Value": "prod"}]
        \\    }
        \\  ]
        \\}
    ;
    const result = try parseResponse(allocator, response);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.secrets.len);
    const s = result.secrets[0];
    try std.testing.expectEqualStrings("my-secret", s.name);
    try std.testing.expectEqualStrings("arn:aws:secretsmanager:us-east-1:123456789012:secret:my-secret-AbCdEf", s.arn);
    try std.testing.expect(s.rotation_enabled);
    try std.testing.expectEqual(@as(?f64, 1700000000.123), s.last_changed_date);
    try std.testing.expectEqual(@as(usize, 1), s.tags.len);
    try std.testing.expectEqualStrings("env", s.tags[0].key);
    try std.testing.expectEqualStrings("prod", s.tags[0].value);
    try std.testing.expect(result.next_token == null);
}

test "parseResponse with NextToken" {
    const allocator = std.testing.allocator;
    const response = \\{"SecretList":[],"NextToken":"abc"}
    ;
    const result = try parseResponse(allocator, response);
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 0), result.secrets.len);
    try std.testing.expectEqualStrings("abc", result.next_token.?);
}
