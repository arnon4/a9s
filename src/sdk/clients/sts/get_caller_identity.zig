const std = @import("std");
const Allocator = std.mem.Allocator;

const sigv4 = @import("../../sig/sigv4.zig");
const xml = @import("../../utils/xml.zig");

pub const CallerIdentity = struct {
    allocator: Allocator,
    account: []u8,
    user_id: []u8,
    arn: []u8,

    pub fn deinit(self: CallerIdentity) void {
        self.allocator.free(self.account);
        self.allocator.free(self.user_id);
        self.allocator.free(self.arn);
    }
};

pub fn getCallerIdentity(client: anytype) !CallerIdentity {
    client.clearLastError();
    const creds = client.source_creds orelse return error.MissingSourceCredentials;

    const body = "Action=GetCallerIdentity&Version=2011-06-15";

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

    var resp_writer: std.Io.Writer.Allocating = .init(client.allocator);
    defer resp_writer.deinit();

    const result = try http_client.fetch(.{
        .method = .POST,
        .location = .{ .url = client.url },
        .extra_headers = header_list.items,
        .payload = body,
        .response_writer = &resp_writer.writer,
    });

    const resp_body = resp_writer.writer.buffer[0..resp_writer.writer.end];

    if (result.status != .ok) return client.classifyError(result.status, resp_body);

    return parseResponse(client.allocator, resp_body);
}

fn parseResponse(allocator: Allocator, body: []const u8) !CallerIdentity {
    const account = try xml.extractTagContent(allocator, body, "Account");
    errdefer allocator.free(account);
    const user_id = try xml.extractTagContent(allocator, body, "UserId");
    errdefer allocator.free(user_id);
    const arn = try xml.extractTagContent(allocator, body, "Arn");
    errdefer allocator.free(arn);
    return .{ .allocator = allocator, .account = account, .user_id = user_id, .arn = arn };
}

// ============================================================================
// Tests
// ============================================================================

test "parseResponse extracts fields" {
    const body =
        \\<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
        \\  <GetCallerIdentityResult>
        \\    <Arn>arn:aws:iam::123456789012:user/Alice</Arn>
        \\    <UserId>AKIAI44QH8DHBEXAMPLE</UserId>
        \\    <Account>123456789012</Account>
        \\  </GetCallerIdentityResult>
        \\</GetCallerIdentityResponse>
    ;
    const identity = try parseResponse(std.testing.allocator, body);
    defer identity.deinit();
    try std.testing.expectEqualStrings("123456789012", identity.account);
    try std.testing.expectEqualStrings("AKIAI44QH8DHBEXAMPLE", identity.user_id);
    try std.testing.expectEqualStrings("arn:aws:iam::123456789012:user/Alice", identity.arn);
}
