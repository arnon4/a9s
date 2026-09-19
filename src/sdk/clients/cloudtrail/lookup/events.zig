const std = @import("std");
const Allocator = std.mem.Allocator;

const sigv4 = @import("../../../sig/sigv4.zig");
const aws_errors = @import("../../aws_errors.zig");
const Credentials = @import("../../../credentials/fetcher.zig").Credentials;

pub const LookupEventsError = error{InvalidLookupAttributesException};

pub const LookupAttribute = struct {
    /// EventId, EventName, ReadOnly, Username, ResourceType, ResourceName, EventSource, AccessKeyId.
    key: []const u8,
    value: []const u8,
};

pub const Options = struct {
    lookup_attributes: ?[]const LookupAttribute = null,
    /// Epoch seconds.
    start_time: ?i64 = null,
    /// Epoch seconds.
    end_time: ?i64 = null,
    event_category: ?[]const u8 = null,
    max_results: ?u32 = null,
    next_token: ?[]const u8 = null,
};

pub const Resource = struct {
    allocator: Allocator,
    resource_type: []u8,
    resource_name: []u8,

    pub fn deinit(self: Resource) void {
        self.allocator.free(self.resource_type);
        self.allocator.free(self.resource_name);
    }
};

pub const Event = struct {
    allocator: Allocator,
    event_id: []u8,
    event_name: []u8,
    event_time: ?f64,
    event_source: []u8,
    username: []u8,
    access_key_id: []u8,
    read_only: []u8,
    resources: []Resource,
    cloud_trail_event: []u8,
    /// AWS account the event was recorded in — parsed out of `cloud_trail_event`,
    /// since LookupEvents doesn't return it as a top-level field. Empty if absent.
    account_id: []u8,

    pub fn deinit(self: Event) void {
        self.allocator.free(self.event_id);
        self.allocator.free(self.event_name);
        self.allocator.free(self.event_source);
        self.allocator.free(self.username);
        self.allocator.free(self.access_key_id);
        self.allocator.free(self.read_only);
        for (self.resources) |r| r.deinit();
        self.allocator.free(self.resources);
        self.allocator.free(self.cloud_trail_event);
        self.allocator.free(self.account_id);
    }
};

pub const Result = struct {
    allocator: Allocator,
    events: []Event,
    next_token: ?[]u8,

    pub fn deinit(self: Result) void {
        for (self.events) |e| e.deinit();
        self.allocator.free(self.events);
        if (self.next_token) |t| self.allocator.free(t);
    }
};

// ============================================================================
// Public API
// ============================================================================

pub fn lookupEvents(client: anytype, options: Options) !Result {
    return lookupEventsWithIo(
        client.allocator,
        client.io,
        client.credentials,
        client.region,
        client.endpoint,
        options,
    );
}

pub fn lookupEventsWithIo(
    allocator: Allocator,
    io: std.Io,
    credentials: Credentials,
    region: []const u8,
    endpoint: []const u8,
    options: Options,
) !Result {
    const body = try buildBody(allocator, options);
    defer allocator.free(body);

    std.log.debug("LookupEvents request: body={s}", .{body});

    var extra_headers = std.StringHashMap([]const u8).init(allocator);
    defer extra_headers.deinit();
    try extra_headers.put("Content-Type", "application/x-amz-json-1.1");
    try extra_headers.put("X-Amz-Target", "CloudTrail_20131101.LookupEvents");
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
            std.log.err("CloudTrail LookupEvents error: {s} (status {d})", .{ code, @intFromEnum(result.status) });
            inline for (@typeInfo(LookupEventsError).error_set.?) |entry| {
                if (std.mem.eql(u8, entry.name, code)) return @field(LookupEventsError, entry.name);
            }
            return aws_errors.fromCode(code) orelse aws_errors.fromStatus(result.status);
        }
        std.log.err("CloudTrail LookupEvents error: status {d} body={s}", .{ @intFromEnum(result.status), response_body });
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

    if (options.lookup_attributes) |attrs| {
        if (!first) try buf.appendSlice(allocator, ",");
        first = false;
        try buf.appendSlice(allocator, "\"LookupAttributes\":[");
        for (attrs, 0..) |attr, i| {
            if (i > 0) try buf.appendSlice(allocator, ",");
            try buf.appendSlice(allocator, "{\"AttributeKey\":\"");
            try buf.appendSlice(allocator, attr.key);
            try buf.appendSlice(allocator, "\",\"AttributeValue\":\"");
            try buf.appendSlice(allocator, attr.value);
            try buf.appendSlice(allocator, "\"}");
        }
        try buf.appendSlice(allocator, "]");
    }
    if (options.start_time) |v| {
        try writeJsonI64Field(&buf, allocator, "StartTime", v, &first);
    }
    if (options.end_time) |v| {
        try writeJsonI64Field(&buf, allocator, "EndTime", v, &first);
    }
    if (options.event_category) |v| {
        try writeJsonStringField(&buf, allocator, "EventCategory", v, &first);
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

fn jsonF64(obj: std.json.ObjectMap, key: []const u8) ?f64 {
    const v = obj.get(key) orelse return null;
    return switch (v) {
        .float => |f| f,
        .integer => |i| @floatFromInt(i),
        else => null,
    };
}

/// Extract the recording account id from a raw CloudTrailEvent JSON record.
/// Tries the top-level `recipientAccountId` first, then `userIdentity.accountId`.
/// Returns an empty string if the record isn't JSON or neither field is present.
fn extractAccountId(allocator: Allocator, cloud_trail_event: []const u8) ![]u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, cloud_trail_event, .{}) catch
        return allocator.dupe(u8, "");
    defer parsed.deinit();

    const root = switch (parsed.value) {
        .object => |o| o,
        else => return allocator.dupe(u8, ""),
    };

    if (root.get("recipientAccountId")) |v| {
        if (v == .string and v.string.len > 0) return allocator.dupe(u8, v.string);
    }
    if (root.get("userIdentity")) |ui| {
        if (ui == .object) {
            if (ui.object.get("accountId")) |v| {
                if (v == .string and v.string.len > 0) return allocator.dupe(u8, v.string);
            }
        }
    }
    return allocator.dupe(u8, "");
}

fn parseResource(allocator: Allocator, obj: std.json.ObjectMap) !Resource {
    const resource_type = try allocator.dupe(u8, jsonStr(obj, "ResourceType"));
    errdefer allocator.free(resource_type);
    const resource_name = try allocator.dupe(u8, jsonStr(obj, "ResourceName"));
    errdefer allocator.free(resource_name);

    return .{
        .allocator = allocator,
        .resource_type = resource_type,
        .resource_name = resource_name,
    };
}

fn parseEvent(allocator: Allocator, obj: std.json.ObjectMap) !Event {
    const event_id = try allocator.dupe(u8, jsonStr(obj, "EventId"));
    errdefer allocator.free(event_id);
    const event_name = try allocator.dupe(u8, jsonStr(obj, "EventName"));
    errdefer allocator.free(event_name);
    const event_source = try allocator.dupe(u8, jsonStr(obj, "EventSource"));
    errdefer allocator.free(event_source);
    const username = try allocator.dupe(u8, jsonStr(obj, "Username"));
    errdefer allocator.free(username);
    const access_key_id = try allocator.dupe(u8, jsonStr(obj, "AccessKeyId"));
    errdefer allocator.free(access_key_id);
    const read_only = try allocator.dupe(u8, jsonStr(obj, "ReadOnly"));
    errdefer allocator.free(read_only);
    const cloud_trail_event = try allocator.dupe(u8, jsonStr(obj, "CloudTrailEvent"));
    errdefer allocator.free(cloud_trail_event);
    const account_id = try extractAccountId(allocator, cloud_trail_event);
    errdefer allocator.free(account_id);

    var resources: std.ArrayList(Resource) = .empty;
    errdefer {
        for (resources.items) |r| r.deinit();
        resources.deinit(allocator);
    }
    if (obj.get("Resources")) |val| {
        switch (val) {
            .array => |arr| {
                for (arr.items) |item| {
                    switch (item) {
                        .object => |robj| {
                            const r = try parseResource(allocator, robj);
                            errdefer r.deinit();
                            try resources.append(allocator, r);
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
        .event_id = event_id,
        .event_name = event_name,
        .event_time = jsonF64(obj, "EventTime"),
        .event_source = event_source,
        .username = username,
        .access_key_id = access_key_id,
        .read_only = read_only,
        .resources = try resources.toOwnedSlice(allocator),
        .cloud_trail_event = cloud_trail_event,
        .account_id = account_id,
    };
}

fn parseResponse(allocator: Allocator, body: []const u8) !Result {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    const root = switch (parsed.value) {
        .object => |o| o,
        else => return error.UnexpectedJsonType,
    };

    var events: std.ArrayList(Event) = .empty;
    errdefer {
        for (events.items) |e| e.deinit();
        events.deinit(allocator);
    }

    if (root.get("Events")) |val| {
        switch (val) {
            .array => |arr| {
                for (arr.items) |item| {
                    switch (item) {
                        .object => |obj| {
                            const e = try parseEvent(allocator, obj);
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
        .events = try events.toOwnedSlice(allocator),
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

test "buildBody with lookup attributes and time range" {
    const allocator = std.testing.allocator;
    const body = try buildBody(allocator, .{
        .lookup_attributes = &.{.{ .key = "EventName", .value = "ConsoleLogin" }},
        .start_time = 1700000000,
        .end_time = 1700003600,
        .max_results = 25,
    });
    defer allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"AttributeKey\":\"EventName\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"AttributeValue\":\"ConsoleLogin\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"StartTime\":1700000000") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"EndTime\":1700003600") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"MaxResults\":25") != null);
}

test "parseResponse basic" {
    const allocator = std.testing.allocator;
    const response =
        \\{
        \\  "Events": [
        \\    {
        \\      "EventId": "abc-123",
        \\      "EventName": "ConsoleLogin",
        \\      "EventTime": 1700000000.0,
        \\      "EventSource": "signin.amazonaws.com",
        \\      "Username": "alice",
        \\      "Resources": [
        \\        {"ResourceType": "AWS::IAM::User", "ResourceName": "alice"}
        \\      ],
        \\      "CloudTrailEvent": "{\"eventVersion\":\"1.08\",\"recipientAccountId\":\"123456789012\"}"
        \\    }
        \\  ],
        \\  "NextToken": "tok"
        \\}
    ;
    const result = try parseResponse(allocator, response);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.events.len);
    const e = result.events[0];
    try std.testing.expectEqualStrings("abc-123", e.event_id);
    try std.testing.expectEqualStrings("ConsoleLogin", e.event_name);
    try std.testing.expectEqual(@as(?f64, 1700000000.0), e.event_time);
    try std.testing.expectEqualStrings("alice", e.username);
    try std.testing.expectEqual(@as(usize, 1), e.resources.len);
    try std.testing.expectEqualStrings("AWS::IAM::User", e.resources[0].resource_type);
    try std.testing.expectEqualStrings("123456789012", e.account_id);
    try std.testing.expectEqualStrings("tok", result.next_token.?);
}

test "extractAccountId falls back to userIdentity.accountId" {
    const allocator = std.testing.allocator;
    const id = try extractAccountId(allocator, "{\"userIdentity\":{\"accountId\":\"999988887777\"}}");
    defer allocator.free(id);
    try std.testing.expectEqualStrings("999988887777", id);
}

test "extractAccountId empty when absent" {
    const allocator = std.testing.allocator;
    const id = try extractAccountId(allocator, "{\"eventVersion\":\"1.08\"}");
    defer allocator.free(id);
    try std.testing.expectEqualStrings("", id);
}

test "extractAccountId empty on non-json" {
    const allocator = std.testing.allocator;
    const id = try extractAccountId(allocator, "not json");
    defer allocator.free(id);
    try std.testing.expectEqualStrings("", id);
}

test "parseResponse empty events" {
    const allocator = std.testing.allocator;
    const response =
        \\{"Events":[]}
    ;
    const result = try parseResponse(allocator, response);
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 0), result.events.len);
    try std.testing.expect(result.next_token == null);
}
