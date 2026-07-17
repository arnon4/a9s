const std = @import("std");
const Allocator = std.mem.Allocator;

const uri = @import("../../utils/uri.zig");
const Credentials = @import("../../credentials/fetcher.zig").Credentials;
const parseAssumeRoleResponse = @import("response.zig").parseAssumeRoleResponse;

pub const AssumeRoleWithWebIdentityParams = struct {
    role_arn: []const u8,
    role_session_name: []const u8,
    web_identity_token: []const u8,
    duration_seconds: ?u32 = null,
};

pub fn assumeRoleWithWebIdentity(client: anytype, params: AssumeRoleWithWebIdentityParams) !Credentials {
    client.clearLastError();
    const body = try buildWebIdentityRequestBody(client.allocator, params);
    defer client.allocator.free(body);

    var http_client = std.http.Client{ .allocator = client.allocator, .io = client.io };
    defer http_client.deinit();

    var body_writer: std.Io.Writer.Allocating = .init(client.allocator);
    defer body_writer.deinit();

    const result = try http_client.fetch(.{
        .method = .POST,
        .location = .{ .url = client.url },
        .extra_headers = &.{.{ .name = "Content-Type", .value = "application/x-www-form-urlencoded" }},
        .payload = body,
        .response_writer = &body_writer.writer,
    });

    const response_body = body_writer.writer.buffer[0..body_writer.writer.end];

    if (result.status != .ok) return client.classifyError(result.status, response_body);

    return parseAssumeRoleResponse(client.allocator, params.role_arn, response_body);
}

fn buildWebIdentityRequestBody(allocator: Allocator, params: AssumeRoleWithWebIdentityParams) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);

    const encoded_arn = try uri.encodeStandard(allocator, params.role_arn);
    defer allocator.free(encoded_arn);
    const encoded_session = try uri.encodeStandard(allocator, params.role_session_name);
    defer allocator.free(encoded_session);
    const encoded_token = try uri.encodeStandard(allocator, params.web_identity_token);
    defer allocator.free(encoded_token);

    try body.appendSlice(allocator, "Action=AssumeRoleWithWebIdentity&Version=2011-06-15&RoleArn=");
    try body.appendSlice(allocator, encoded_arn);
    try body.appendSlice(allocator, "&RoleSessionName=");
    try body.appendSlice(allocator, encoded_session);
    try body.appendSlice(allocator, "&WebIdentityToken=");
    try body.appendSlice(allocator, encoded_token);

    if (params.duration_seconds) |dur| {
        const dur_str = try std.fmt.allocPrint(allocator, "&DurationSeconds={d}", .{dur});
        defer allocator.free(dur_str);
        try body.appendSlice(allocator, dur_str);
    }

    return body.toOwnedSlice(allocator);
}
