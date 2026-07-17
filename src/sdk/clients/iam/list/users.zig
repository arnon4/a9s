const std = @import("std");
const Allocator = std.mem.Allocator;

const sigv4 = @import("../../../sig/sigv4.zig");
const xml = @import("../../../utils/xml.zig");
const aws_errors = @import("../../aws_errors.zig");

pub const IamListUsersError = error{
    NoSuchEntityException,
    ServiceFailureException,
};

pub const Params = struct {
    path_prefix: ?[]const u8 = null,
    marker: ?[]const u8 = null,
    max_items: ?u32 = null,
};

pub const Options = struct {
    params: Params = .{},
};

pub const User = struct {
    allocator: Allocator,
    user_name: []u8,
    user_id: []u8,
    arn: []u8,
    path: []u8,
    create_date: []u8,
    password_last_used: ?[]u8,

    pub fn deinit(self: User) void {
        self.allocator.free(self.user_name);
        self.allocator.free(self.user_id);
        self.allocator.free(self.arn);
        self.allocator.free(self.path);
        self.allocator.free(self.create_date);
        if (self.password_last_used) |p| self.allocator.free(p);
    }

    pub fn clone(self: User, allocator: Allocator) !User {
        const user_name = try allocator.dupe(u8, self.user_name);
        errdefer allocator.free(user_name);
        const user_id = try allocator.dupe(u8, self.user_id);
        errdefer allocator.free(user_id);
        const arn = try allocator.dupe(u8, self.arn);
        errdefer allocator.free(arn);
        const path = try allocator.dupe(u8, self.path);
        errdefer allocator.free(path);
        const create_date = try allocator.dupe(u8, self.create_date);
        errdefer allocator.free(create_date);
        const password_last_used: ?[]u8 = if (self.password_last_used) |p| try allocator.dupe(u8, p) else null;
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
};

pub const Result = struct {
    allocator: Allocator,
    users: []User,
    next_marker: ?[]u8,

    pub fn deinit(self: Result) void {
        for (self.users) |u| u.deinit();
        self.allocator.free(self.users);
        if (self.next_marker) |m| self.allocator.free(m);
    }
};

pub fn listUsers(client: anytype, options: Options) !Result {
    const body = try buildBody(client.allocator, options.params);
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
            std.log.err("IAM ListUsers error: status {d}", .{@intFromEnum(result.status)});
            return aws_errors.fromStatus(result.status);
        };
        defer client.allocator.free(code);
        std.log.err("IAM ListUsers error: {s} (status {d})", .{ code, @intFromEnum(result.status) });
        inline for (@typeInfo(IamListUsersError).error_set.?) |entry| {
            if (std.mem.eql(u8, entry.name, code)) return @field(IamListUsersError, entry.name);
        }
        return aws_errors.fromCode(code) orelse aws_errors.fromStatus(result.status);
    }

    return parseResponse(client.allocator, resp_body);
}

fn buildBody(allocator: Allocator, params: Params) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);

    try body.appendSlice(allocator, "Action=ListUsers&Version=2010-05-08");

    if (params.path_prefix) |pp| {
        const encoded = try uriEncode(allocator, pp);
        defer allocator.free(encoded);
        try body.appendSlice(allocator, "&PathPrefix=");
        try body.appendSlice(allocator, encoded);
    }
    if (params.marker) |m| {
        const encoded = try uriEncode(allocator, m);
        defer allocator.free(encoded);
        try body.appendSlice(allocator, "&Marker=");
        try body.appendSlice(allocator, encoded);
    }
    if (params.max_items) |mi| {
        const s = try std.fmt.allocPrint(allocator, "&MaxItems={d}", .{mi});
        defer allocator.free(s);
        try body.appendSlice(allocator, s);
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

fn parseResponse(allocator: Allocator, body: []const u8) !Result {
    const users_block = xml.extractTagContent(allocator, body, "Users") catch
        try allocator.dupe(u8, "");
    defer allocator.free(users_block);

    var users: std.ArrayList(User) = .empty;
    errdefer {
        for (users.items) |u| u.deinit();
        users.deinit(allocator);
    }

    var offset: usize = 0;
    while (true) {
        const slice = users_block[offset..];
        const start_tag = "<member";
        const m_start = std.mem.indexOf(u8, slice, start_tag) orelse break;
        const gt = std.mem.indexOfScalarPos(u8, slice, m_start + start_tag.len, '>') orelse break;
        const content_start = gt + 1;
        const end_tag = "</member>";
        const m_end = std.mem.indexOf(u8, slice[content_start..], end_tag) orelse break;
        const member_content = slice[content_start .. content_start + m_end];

        const user = try parseMember(allocator, member_content);
        errdefer user.deinit();
        try users.append(allocator, user);

        offset += content_start + m_end + end_tag.len;
    }

    const next_marker: ?[]u8 = xml.extractTagContent(allocator, body, "Marker") catch null;
    errdefer if (next_marker) |m| allocator.free(m);

    return .{
        .allocator = allocator,
        .users = try users.toOwnedSlice(allocator),
        .next_marker = next_marker,
    };
}

fn xmlStr(allocator: Allocator, src: []const u8, tag: []const u8) ![]u8 {
    return xml.extractTagContent(allocator, src, tag) catch try allocator.dupe(u8, "");
}

fn parseMember(allocator: Allocator, src: []const u8) !User {
    const user_name = try xmlStr(allocator, src, "UserName");
    errdefer allocator.free(user_name);
    const user_id = try xmlStr(allocator, src, "UserId");
    errdefer allocator.free(user_id);
    const arn = try xmlStr(allocator, src, "Arn");
    errdefer allocator.free(arn);
    const path = try xmlStr(allocator, src, "Path");
    errdefer allocator.free(path);
    const create_date = try xmlStr(allocator, src, "CreateDate");
    errdefer allocator.free(create_date);
    const password_last_used: ?[]u8 = xml.extractTagContent(allocator, src, "PasswordLastUsed") catch null;
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

test "parseResponse single user" {
    const body =
        \\<ListUsersResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        \\  <ListUsersResult>
        \\    <IsTruncated>false</IsTruncated>
        \\    <Users>
        \\      <member>
        \\        <UserName>alice</UserName>
        \\        <UserId>AIDAI3UMHF7RYEXAMPLE</UserId>
        \\        <Arn>arn:aws:iam::123456789012:user/alice</Arn>
        \\        <Path>/</Path>
        \\        <CreateDate>2013-04-18T05:01:58Z</CreateDate>
        \\        <PasswordLastUsed>2024-01-01T00:00:00Z</PasswordLastUsed>
        \\      </member>
        \\    </Users>
        \\  </ListUsersResult>
        \\</ListUsersResponse>
    ;
    const result = try parseResponse(std.testing.allocator, body);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.users.len);
    const u = result.users[0];
    try std.testing.expectEqualStrings("alice", u.user_name);
    try std.testing.expectEqualStrings("AIDAI3UMHF7RYEXAMPLE", u.user_id);
    try std.testing.expectEqualStrings("arn:aws:iam::123456789012:user/alice", u.arn);
    try std.testing.expectEqualStrings("/", u.path);
    try std.testing.expectEqualStrings("2013-04-18T05:01:58Z", u.create_date);
    try std.testing.expectEqualStrings("2024-01-01T00:00:00Z", u.password_last_used.?);
    try std.testing.expect(result.next_marker == null);
}

test "parseResponse user without password last used" {
    const body =
        \\<ListUsersResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        \\  <ListUsersResult>
        \\    <IsTruncated>false</IsTruncated>
        \\    <Users>
        \\      <member>
        \\        <UserName>bob</UserName>
        \\        <UserId>USERID2</UserId>
        \\        <Arn>arn:aws:iam::123:user/bob</Arn>
        \\        <Path>/</Path>
        \\        <CreateDate>2020-01-01T00:00:00Z</CreateDate>
        \\      </member>
        \\    </Users>
        \\  </ListUsersResult>
        \\</ListUsersResponse>
    ;
    const result = try parseResponse(std.testing.allocator, body);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.users.len);
    try std.testing.expect(result.users[0].password_last_used == null);
}

test "parseResponse with pagination marker" {
    const body =
        \\<ListUsersResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        \\  <ListUsersResult>
        \\    <IsTruncated>true</IsTruncated>
        \\    <Users></Users>
        \\    <Marker>NEXT_PAGE_TOKEN</Marker>
        \\  </ListUsersResult>
        \\</ListUsersResponse>
    ;
    const result = try parseResponse(std.testing.allocator, body);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 0), result.users.len);
    try std.testing.expect(result.next_marker != null);
    try std.testing.expectEqualStrings("NEXT_PAGE_TOKEN", result.next_marker.?);
}

test "buildBody action only" {
    const body = try buildBody(std.testing.allocator, .{});
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("Action=ListUsers&Version=2010-05-08", body);
}

test "buildBody with path prefix" {
    const body = try buildBody(std.testing.allocator, .{ .path_prefix = "/svc/" });
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("Action=ListUsers&Version=2010-05-08&PathPrefix=/svc/", body);
}

test "buildBody with max items" {
    const body = try buildBody(std.testing.allocator, .{ .max_items = 50 });
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("Action=ListUsers&Version=2010-05-08&MaxItems=50", body);
}
