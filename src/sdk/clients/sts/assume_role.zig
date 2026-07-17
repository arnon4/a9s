const std = @import("std");
const Allocator = std.mem.Allocator;

const sigv4 = @import("../../sig/sigv4.zig");
const uri = @import("../../utils/uri.zig");
const Credentials = @import("../../credentials/fetcher.zig").Credentials;
const parseAssumeRoleResponse = @import("response.zig").parseAssumeRoleResponse;

pub const AssumeRoleParams = struct {
    role_arn: []const u8,
    role_session_name: []const u8,
    external_id: ?[]const u8 = null,
    duration_seconds: ?u32 = null,
};

pub fn assumeRole(client: anytype, params: AssumeRoleParams) !Credentials {
    client.clearLastError();
    const creds = client.source_creds orelse return error.MissingSourceCredentials;

    const body = try buildRequestBody(client.allocator, params);
    defer client.allocator.free(body);

    var extra_headers = std.StringHashMap([]const u8).init(client.allocator);
    defer extra_headers.deinit();
    try extra_headers.put("Content-Type", "application/x-www-form-urlencoded");
    if (creds.session_token) |token| {
        try extra_headers.put("X-Amz-Security-Token", token);
    }

    var signed = try sigv4.sign(
        client.allocator,
        client.io,
        .{
            .access_key = creds.access_key_id,
            .secret_key = creds.secret_access_key,
            .region = client.region,
            .service = "sts",
            .include_sha256_header = false,
        },
        .POST,
        client.url,
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

    var body_writer: std.Io.Writer.Allocating = .init(client.allocator);
    defer body_writer.deinit();

    const result = try http_client.fetch(.{
        .method = .POST,
        .location = .{ .url = client.url },
        .extra_headers = header_list.items,
        .payload = body,
        .response_writer = &body_writer.writer,
    });

    const response_body = body_writer.writer.buffer[0..body_writer.writer.end];

    if (result.status != .ok) return client.classifyError(result.status, response_body);

    return parseAssumeRoleResponse(client.allocator, params.role_arn, response_body);
}

fn buildRequestBody(allocator: Allocator, params: AssumeRoleParams) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);

    const encoded_arn = try uri.encodeStandard(allocator, params.role_arn);
    defer allocator.free(encoded_arn);
    const encoded_session = try uri.encodeStandard(allocator, params.role_session_name);
    defer allocator.free(encoded_session);

    try body.appendSlice(allocator, "Action=AssumeRole&Version=2011-06-15&RoleArn=");
    try body.appendSlice(allocator, encoded_arn);
    try body.appendSlice(allocator, "&RoleSessionName=");
    try body.appendSlice(allocator, encoded_session);

    if (params.external_id) |ext| {
        const encoded = try uri.encodeStandard(allocator, ext);
        defer allocator.free(encoded);
        try body.appendSlice(allocator, "&ExternalId=");
        try body.appendSlice(allocator, encoded);
    }
    if (params.duration_seconds) |dur| {
        const dur_str = try std.fmt.allocPrint(allocator, "&DurationSeconds={d}", .{dur});
        defer allocator.free(dur_str);
        try body.appendSlice(allocator, dur_str);
    }

    return body.toOwnedSlice(allocator);
}

// ============================================================================
// Tests
// ============================================================================

test "buildRequestBody basic params" {
    const allocator = std.testing.allocator;
    const body = try buildRequestBody(allocator, .{
        .role_arn = "arn:aws:iam::123456789:role/MyRole",
        .role_session_name = "my-session",
    });
    defer allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "Action=AssumeRole") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "RoleArn=arn%3Aaws%3Aiam%3A%3A123456789%3Arole%2FMyRole") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "RoleSessionName=my-session") != null);
}

test "buildRequestBody optional params" {
    const allocator = std.testing.allocator;
    const body = try buildRequestBody(allocator, .{
        .role_arn = "arn:aws:iam::123:role/R",
        .role_session_name = "s",
        .external_id = "ext-123",
        .duration_seconds = 3600,
    });
    defer allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "ExternalId=ext-123") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "DurationSeconds=3600") != null);
}
