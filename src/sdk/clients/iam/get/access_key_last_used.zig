const std = @import("std");
const Allocator = std.mem.Allocator;

const sigv4 = @import("../../../sig/sigv4.zig");
const xml = @import("../../../utils/xml.zig");
const aws_errors = @import("../../aws_errors.zig");

pub const IamGetAccessKeyLastUsedError = error{
    NoSuchEntityException,
    ServiceFailureException,
};

pub const Options = struct {
    access_key_id: []const u8,
};

pub const GetAccessKeyLastUsedResult = struct {
    allocator: Allocator,
    user_name: []u8,
    /// Empty if the key has never been used.
    last_used_date: ?[]u8,
    service_name: ?[]u8,
    region: ?[]u8,

    pub fn deinit(self: GetAccessKeyLastUsedResult) void {
        self.allocator.free(self.user_name);
        if (self.last_used_date) |d| self.allocator.free(d);
        if (self.service_name) |s| self.allocator.free(s);
        if (self.region) |r| self.allocator.free(r);
    }
};

pub fn getAccessKeyLastUsed(client: anytype, options: Options) !GetAccessKeyLastUsedResult {
    const body = try buildBody(client.allocator, options.access_key_id);
    defer client.allocator.free(body);

    var extra_headers = std.StringHashMap([]const u8).init(client.allocator);
    defer extra_headers.deinit();
    try extra_headers.put("Content-Type", "application/x-www-form-urlencoded");
    if (client.credentials.session_token) |token| {
        try extra_headers.put("X-Amz-Security-Token", token);
    }

    var signed = try sigv4.sign(
        client.allocator,
        client.io,
        .{
            .access_key = client.credentials.access_key_id,
            .secret_key = client.credentials.secret_access_key,
            .region = client.region,
            .service = "iam",
            .include_sha256_header = false,
        },
        .POST,
        client.endpoint,
        extra_headers,
        body,
        null,
    );
    defer signed.deinit();

    var header_list: std.ArrayList(std.http.Header) = .empty;
    defer header_list.deinit(client.allocator);
    var iter = signed.headers.iterator();
    while (iter.next()) |entry| {
        if (std.ascii.eqlIgnoreCase(entry.key_ptr.*, "host")) continue;
        try header_list.append(client.allocator, .{ .name = entry.key_ptr.*, .value = entry.value_ptr.* });
    }

    var http_client = std.http.Client{ .allocator = client.allocator, .io = client.io };
    defer http_client.deinit();

    var resp_writer: std.Io.Writer.Allocating = .init(client.allocator);
    defer resp_writer.deinit();

    const result = try http_client.fetch(.{
        .method = .POST,
        .location = .{ .url = client.endpoint },
        .extra_headers = header_list.items,
        .payload = body,
        .response_writer = &resp_writer.writer,
    });

    const resp_body = resp_writer.writer.buffer[0..resp_writer.writer.end];

    if (result.status != .ok) {
        const code = xml.extractTagContent(client.allocator, resp_body, "Code") catch {
            std.log.err("IAM GetAccessKeyLastUsed error: status {d}", .{@intFromEnum(result.status)});
            return aws_errors.fromStatus(result.status);
        };
        defer client.allocator.free(code);
        std.log.err("IAM GetAccessKeyLastUsed error: {s} (status {d})", .{ code, @intFromEnum(result.status) });
        inline for (@typeInfo(IamGetAccessKeyLastUsedError).error_set.?) |entry| {
            if (std.mem.eql(u8, entry.name, code)) return @field(IamGetAccessKeyLastUsedError, entry.name);
        }
        return aws_errors.fromCode(code) orelse aws_errors.fromStatus(result.status);
    }

    return parseResponse(client.allocator, resp_body);
}

fn buildBody(allocator: Allocator, access_key_id: []const u8) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "Action=GetAccessKeyLastUsed&Version=2010-05-08&AccessKeyId={s}",
        .{access_key_id},
    );
}

fn xmlStr(allocator: Allocator, src: []const u8, tag: []const u8) ![]u8 {
    return xml.extractTagContent(allocator, src, tag) catch try allocator.dupe(u8, "");
}

fn parseResponse(allocator: Allocator, body: []const u8) !GetAccessKeyLastUsedResult {
    const user_name = try xmlStr(allocator, body, "UserName");
    errdefer allocator.free(user_name);

    // AccessKeyLastUsed block is always present, but its fields are empty
    // when the key has never been used.
    const last_used_date: ?[]u8 = xml.extractTagContent(allocator, body, "LastUsedDate") catch null;
    errdefer if (last_used_date) |d| allocator.free(d);
    const service_name: ?[]u8 = xml.extractTagContent(allocator, body, "ServiceName") catch null;
    errdefer if (service_name) |s| allocator.free(s);
    const region: ?[]u8 = xml.extractTagContent(allocator, body, "Region") catch null;
    errdefer if (region) |r| allocator.free(r);

    return .{
        .allocator = allocator,
        .user_name = user_name,
        .last_used_date = if (last_used_date) |d| (if (d.len > 0) d else blk: {
            allocator.free(d);
            break :blk null;
        }) else null,
        .service_name = if (service_name) |s| (if (s.len > 0) s else blk: {
            allocator.free(s);
            break :blk null;
        }) else null,
        .region = if (region) |r| (if (r.len > 0) r else blk: {
            allocator.free(r);
            break :blk null;
        }) else null,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "parseResponse used key" {
    const body =
        \\<GetAccessKeyLastUsedResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        \\  <GetAccessKeyLastUsedResult>
        \\    <UserName>alice</UserName>
        \\    <AccessKeyLastUsed>
        \\      <LastUsedDate>2024-11-30T12:00:00Z</LastUsedDate>
        \\      <ServiceName>s3</ServiceName>
        \\      <Region>us-east-1</Region>
        \\    </AccessKeyLastUsed>
        \\  </GetAccessKeyLastUsedResult>
        \\</GetAccessKeyLastUsedResponse>
    ;
    const result = try parseResponse(std.testing.allocator, body);
    defer result.deinit();

    try std.testing.expectEqualStrings("alice", result.user_name);
    try std.testing.expectEqualStrings("2024-11-30T12:00:00Z", result.last_used_date.?);
    try std.testing.expectEqualStrings("s3", result.service_name.?);
    try std.testing.expectEqualStrings("us-east-1", result.region.?);
}

test "parseResponse never used key" {
    const body =
        \\<GetAccessKeyLastUsedResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        \\  <GetAccessKeyLastUsedResult>
        \\    <UserName>bob</UserName>
        \\    <AccessKeyLastUsed>
        \\      <ServiceName>N/A</ServiceName>
        \\      <Region>N/A</Region>
        \\    </AccessKeyLastUsed>
        \\  </GetAccessKeyLastUsedResult>
        \\</GetAccessKeyLastUsedResponse>
    ;
    const result = try parseResponse(std.testing.allocator, body);
    defer result.deinit();

    try std.testing.expectEqualStrings("bob", result.user_name);
    try std.testing.expect(result.last_used_date == null);
}

test "buildBody encodes access key id" {
    const body = try buildBody(std.testing.allocator, "AKIAIOSFODNN7EXAMPLE");
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("Action=GetAccessKeyLastUsed&Version=2010-05-08&AccessKeyId=AKIAIOSFODNN7EXAMPLE", body);
}
