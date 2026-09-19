const std = @import("std");
const Allocator = std.mem.Allocator;

const sigv4 = @import("../../../sig/sigv4.zig");
const aws_errors = @import("../../aws_errors.zig");
const Credentials = @import("../../../credentials/fetcher.zig").Credentials;

pub const ListTrailsError = error{UnsupportedOperationException};

pub const Options = struct {
    next_token: ?[]const u8 = null,
};

pub const TrailInfo = struct {
    allocator: Allocator,
    trail_arn: []u8,
    name: []u8,
    home_region: []u8,

    pub fn deinit(self: TrailInfo) void {
        self.allocator.free(self.trail_arn);
        self.allocator.free(self.name);
        self.allocator.free(self.home_region);
    }
};

pub const Result = struct {
    allocator: Allocator,
    trails: []TrailInfo,
    next_token: ?[]u8,

    pub fn deinit(self: Result) void {
        for (self.trails) |t| t.deinit();
        self.allocator.free(self.trails);
        if (self.next_token) |t| self.allocator.free(t);
    }
};

// ============================================================================
// Public API
// ============================================================================

pub fn listTrails(client: anytype, options: Options) !Result {
    return listTrailsWithIo(
        client.allocator,
        client.io,
        client.credentials,
        client.region,
        client.endpoint,
        options,
    );
}

pub fn listTrailsWithIo(
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
    try extra_headers.put("X-Amz-Target", "CloudTrail_20131101.ListTrails");
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
            std.log.err("CloudTrail ListTrails error: {s} (status {d})", .{ code, @intFromEnum(result.status) });
            inline for (@typeInfo(ListTrailsError).error_set.?) |entry| {
                if (std.mem.eql(u8, entry.name, code)) return @field(ListTrailsError, entry.name);
            }
            return aws_errors.fromCode(code) orelse aws_errors.fromStatus(result.status);
        }
        std.log.err("CloudTrail ListTrails error: status {d} body={s}", .{ @intFromEnum(result.status), response_body });
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
    if (options.next_token) |v| {
        try writeJsonStringField(&buf, allocator, "NextToken", v, &first);
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

fn parseTrail(allocator: Allocator, obj: std.json.ObjectMap) !TrailInfo {
    const trail_arn = try allocator.dupe(u8, jsonStr(obj, "TrailARN"));
    errdefer allocator.free(trail_arn);
    const name = try allocator.dupe(u8, jsonStr(obj, "Name"));
    errdefer allocator.free(name);
    const home_region = try allocator.dupe(u8, jsonStr(obj, "HomeRegion"));
    errdefer allocator.free(home_region);

    return .{
        .allocator = allocator,
        .trail_arn = trail_arn,
        .name = name,
        .home_region = home_region,
    };
}

fn parseResponse(allocator: Allocator, body: []const u8) !Result {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    const root = switch (parsed.value) {
        .object => |o| o,
        else => return error.UnexpectedJsonType,
    };

    var trails: std.ArrayList(TrailInfo) = .empty;
    errdefer {
        for (trails.items) |t| t.deinit();
        trails.deinit(allocator);
    }

    if (root.get("Trails")) |val| {
        switch (val) {
            .array => |arr| {
                for (arr.items) |item| {
                    switch (item) {
                        .object => |obj| {
                            const t = try parseTrail(allocator, obj);
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
        .trails = try trails.toOwnedSlice(allocator),
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

test "buildBody with next_token" {
    const allocator = std.testing.allocator;
    const body = try buildBody(allocator, .{ .next_token = "tok123" });
    defer allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"NextToken\":\"tok123\"") != null);
}

test "parseResponse basic" {
    const allocator = std.testing.allocator;
    const response =
        \\{
        \\  "Trails": [
        \\    {
        \\      "Name": "my-trail",
        \\      "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/my-trail",
        \\      "HomeRegion": "us-east-1"
        \\    }
        \\  ]
        \\}
    ;
    const result = try parseResponse(allocator, response);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.trails.len);
    const t = result.trails[0];
    try std.testing.expectEqualStrings("my-trail", t.name);
    try std.testing.expectEqualStrings("arn:aws:cloudtrail:us-east-1:123456789012:trail/my-trail", t.trail_arn);
    try std.testing.expectEqualStrings("us-east-1", t.home_region);
    try std.testing.expect(result.next_token == null);
}

test "parseResponse with NextToken" {
    const allocator = std.testing.allocator;
    const response =
        \\{"Trails":[],"NextToken":"abc"}
    ;
    const result = try parseResponse(allocator, response);
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 0), result.trails.len);
    try std.testing.expectEqualStrings("abc", result.next_token.?);
}
