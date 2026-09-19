const std = @import("std");
const Allocator = std.mem.Allocator;

const sigv4 = @import("../../../sig/sigv4.zig");
const aws_errors = @import("../../aws_errors.zig");
const Credentials = @import("../../../credentials/fetcher.zig").Credentials;

pub const DescribeTrailsError = error{UnsupportedOperationException};

pub const Options = struct {
    /// Trail names or ARNs to describe. If omitted, CloudTrail describes the
    /// trail in the current region belonging to this account.
    trail_name_list: ?[]const []const u8 = null,
    /// Include trails shadowed in other regions (multi-region trails looked
    /// up from a non-home region).
    include_shadow_trails: ?bool = null,
};

pub const TrailDetail = struct {
    allocator: Allocator,
    name: []u8,
    trail_arn: []u8,
    is_organization_trail: bool,

    pub fn deinit(self: TrailDetail) void {
        self.allocator.free(self.name);
        self.allocator.free(self.trail_arn);
    }
};

pub const Result = struct {
    allocator: Allocator,
    trails: []TrailDetail,

    pub fn deinit(self: Result) void {
        for (self.trails) |t| t.deinit();
        self.allocator.free(self.trails);
    }
};

// ============================================================================
// Public API
// ============================================================================

pub fn describeTrails(client: anytype, options: Options) !Result {
    return describeTrailsWithIo(
        client.allocator,
        client.io,
        client.credentials,
        client.region,
        client.endpoint,
        options,
    );
}

pub fn describeTrailsWithIo(
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
    try extra_headers.put("X-Amz-Target", "CloudTrail_20131101.DescribeTrails");
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
            std.log.err("CloudTrail DescribeTrails error: {s} (status {d})", .{ code, @intFromEnum(result.status) });
            inline for (@typeInfo(DescribeTrailsError).error_set.?) |entry| {
                if (std.mem.eql(u8, entry.name, code)) return @field(DescribeTrailsError, entry.name);
            }
            return aws_errors.fromCode(code) orelse aws_errors.fromStatus(result.status);
        }
        std.log.err("CloudTrail DescribeTrails error: status {d} body={s}", .{ @intFromEnum(result.status), response_body });
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

    try buf.appendSlice(allocator, "{");
    var first = true;

    if (options.trail_name_list) |names| {
        if (!first) try buf.appendSlice(allocator, ",");
        first = false;
        try buf.appendSlice(allocator, "\"trailNameList\":[");
        for (names, 0..) |n, i| {
            if (i > 0) try buf.appendSlice(allocator, ",");
            try buf.append(allocator, '"');
            try buf.appendSlice(allocator, n);
            try buf.append(allocator, '"');
        }
        try buf.appendSlice(allocator, "]");
    }
    if (options.include_shadow_trails) |v| {
        if (!first) try buf.appendSlice(allocator, ",");
        first = false;
        try buf.appendSlice(allocator, if (v) "\"includeShadowTrails\":true" else "\"includeShadowTrails\":false");
    }

    try buf.appendSlice(allocator, "}");
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

fn parseTrailDetail(allocator: Allocator, obj: std.json.ObjectMap) !TrailDetail {
    const trail_name = try allocator.dupe(u8, jsonStr(obj, "Name"));
    errdefer allocator.free(trail_name);
    const trail_arn = try allocator.dupe(u8, jsonStr(obj, "TrailARN"));
    errdefer allocator.free(trail_arn);

    return .{
        .allocator = allocator,
        .name = trail_name,
        .trail_arn = trail_arn,
        .is_organization_trail = jsonBool(obj, "IsOrganizationTrail"),
    };
}

fn parseResponse(allocator: Allocator, body: []const u8) !Result {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    const root = switch (parsed.value) {
        .object => |o| o,
        else => return error.UnexpectedJsonType,
    };

    var trails: std.ArrayList(TrailDetail) = .empty;
    errdefer {
        for (trails.items) |t| t.deinit();
        trails.deinit(allocator);
    }

    if (root.get("trailList")) |val| {
        switch (val) {
            .array => |arr| {
                for (arr.items) |item| {
                    switch (item) {
                        .object => |obj| {
                            const t = try parseTrailDetail(allocator, obj);
                            errdefer t.deinit();
                            try trails.append(allocator, t);
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
        .trails = try trails.toOwnedSlice(allocator),
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

test "buildBody with trail name list" {
    const allocator = std.testing.allocator;
    const body = try buildBody(allocator, .{
        .trail_name_list = &.{ "arn:aws:cloudtrail:us-east-1:123:trail/a", "arn:aws:cloudtrail:us-east-1:123:trail/b" },
    });
    defer allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"trailNameList\":[\"arn:aws:cloudtrail:us-east-1:123:trail/a\",\"arn:aws:cloudtrail:us-east-1:123:trail/b\"]") != null);
}

test "parseResponse basic" {
    const allocator = std.testing.allocator;
    const response =
        \\{
        \\  "trailList": [
        \\    {
        \\      "Name": "aws-controltower-BaselineCloudTrail",
        \\      "TrailARN": "arn:aws:cloudtrail:us-east-1:006262944085:trail/aws-controltower-BaselineCloudTrail",
        \\      "IsOrganizationTrail": true
        \\    },
        \\    {
        \\      "Name": "my-trail",
        \\      "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/my-trail",
        \\      "IsOrganizationTrail": false
        \\    }
        \\  ]
        \\}
    ;
    const result = try parseResponse(allocator, response);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 2), result.trails.len);
    try std.testing.expect(result.trails[0].is_organization_trail);
    try std.testing.expect(!result.trails[1].is_organization_trail);
}
