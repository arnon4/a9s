const std = @import("std");
const Allocator = std.mem.Allocator;

const sigv4 = @import("../../../sig/sigv4.zig");
const xml = @import("../../../utils/xml.zig");
const aws_errors = @import("../../aws_errors.zig");

pub const IamGetUserError = error{
    NoSuchEntityException,
    ServiceFailureException,
};

pub const Options = struct {
    /// If null, IAM returns the user calling the API (based on the signing credentials).
    user_name: ?[]const u8 = null,
};

pub const GetUserResult = struct {
    allocator: Allocator,
    user_name: []u8,
    user_id: []u8,
    arn: []u8,
    path: []u8,
    create_date: []u8,
    password_last_used: ?[]u8,

    pub fn deinit(self: GetUserResult) void {
        self.allocator.free(self.user_name);
        self.allocator.free(self.user_id);
        self.allocator.free(self.arn);
        self.allocator.free(self.path);
        self.allocator.free(self.create_date);
        if (self.password_last_used) |p| self.allocator.free(p);
    }
};

pub fn getUser(client: anytype, options: Options) !GetUserResult {
    const body = try buildBody(client.allocator, options.user_name);
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
            std.log.err("IAM GetUser error: status {d}", .{@intFromEnum(result.status)});
            return aws_errors.fromStatus(result.status);
        };
        defer client.allocator.free(code);
        std.log.err("IAM GetUser error: {s} (status {d})", .{ code, @intFromEnum(result.status) });
        inline for (@typeInfo(IamGetUserError).error_set.?) |entry| {
            if (std.mem.eql(u8, entry.name, code)) return @field(IamGetUserError, entry.name);
        }
        return aws_errors.fromCode(code) orelse aws_errors.fromStatus(result.status);
    }

    return parseResponse(client.allocator, resp_body);
}

fn buildBody(allocator: Allocator, user_name: ?[]const u8) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);

    try body.appendSlice(allocator, "Action=GetUser&Version=2010-05-08");

    if (user_name) |name| {
        const encoded = try uriEncode(allocator, name);
        defer allocator.free(encoded);
        try body.appendSlice(allocator, "&UserName=");
        try body.appendSlice(allocator, encoded);
    }

    return body.toOwnedSlice(allocator);
}

fn uriEncode(allocator: Allocator, input: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    for (input) |c| {
        if (std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '~' or c == '/') {
            try out.append(allocator, c);
        } else {
            const hex = try std.fmt.allocPrint(allocator, "%{X:0>2}", .{c});
            defer allocator.free(hex);
            try out.appendSlice(allocator, hex);
        }
    }
    return out.toOwnedSlice(allocator);
}

fn xmlStr(allocator: Allocator, src: []const u8, tag: []const u8) ![]u8 {
    return xml.extractTagContent(allocator, src, tag) catch try allocator.dupe(u8, "");
}

fn parseResponse(allocator: Allocator, body: []const u8) !GetUserResult {
    const user_name = try xmlStr(allocator, body, "UserName");
    errdefer allocator.free(user_name);
    const user_id = try xmlStr(allocator, body, "UserId");
    errdefer allocator.free(user_id);
    const arn = try xmlStr(allocator, body, "Arn");
    errdefer allocator.free(arn);
    const path = try xmlStr(allocator, body, "Path");
    errdefer allocator.free(path);
    const create_date = try xmlStr(allocator, body, "CreateDate");
    errdefer allocator.free(create_date);
    const password_last_used: ?[]u8 = xml.extractTagContent(allocator, body, "PasswordLastUsed") catch null;
    errdefer if (password_last_used) |p| allocator.free(p);

    return .{
        .allocator = allocator,
        .user_name = user_name,
        .user_id = user_id,
        .arn = arn,
        .path = path,
        .create_date = create_date,
        .password_last_used = password_last_used,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "parseResponse basic user" {
    const body =
        \\<GetUserResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        \\  <GetUserResult>
        \\    <User>
        \\      <UserName>alice</UserName>
        \\      <UserId>AIDAI3UMHF7RYEXAMPLE</UserId>
        \\      <Arn>arn:aws:iam::123456789012:user/alice</Arn>
        \\      <Path>/</Path>
        \\      <CreateDate>2013-04-18T05:01:58Z</CreateDate>
        \\      <PasswordLastUsed>2024-11-30T12:00:00Z</PasswordLastUsed>
        \\    </User>
        \\  </GetUserResult>
        \\</GetUserResponse>
    ;
    const result = try parseResponse(std.testing.allocator, body);
    defer result.deinit();

    try std.testing.expectEqualStrings("alice", result.user_name);
    try std.testing.expectEqualStrings("arn:aws:iam::123456789012:user/alice", result.arn);
    try std.testing.expectEqualStrings("/", result.path);
    try std.testing.expect(result.password_last_used != null);
    try std.testing.expectEqualStrings("2024-11-30T12:00:00Z", result.password_last_used.?);
}

test "parseResponse user never logged in" {
    const body =
        \\<GetUserResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        \\  <GetUserResult>
        \\    <User>
        \\      <UserName>bob</UserName>
        \\      <UserId>USERID</UserId>
        \\      <Arn>arn:aws:iam::123:user/bob</Arn>
        \\      <Path>/</Path>
        \\      <CreateDate>2020-01-01T00:00:00Z</CreateDate>
        \\    </User>
        \\  </GetUserResult>
        \\</GetUserResponse>
    ;
    const result = try parseResponse(std.testing.allocator, body);
    defer result.deinit();

    try std.testing.expectEqualStrings("bob", result.user_name);
    try std.testing.expect(result.password_last_used == null);
}

test "buildBody with user name" {
    const body = try buildBody(std.testing.allocator, "alice");
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("Action=GetUser&Version=2010-05-08&UserName=alice", body);
}

test "buildBody without user name" {
    const body = try buildBody(std.testing.allocator, null);
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("Action=GetUser&Version=2010-05-08", body);
}
