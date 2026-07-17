const std = @import("std");
const Allocator = std.mem.Allocator;

const sigv4 = @import("../../../sig/sigv4.zig");
const xml = @import("../../../utils/xml.zig");
const aws_errors = @import("../../aws_errors.zig");

pub const IamGetGroupError = error{
    NoSuchEntityException,
    ServiceFailureException,
};

pub const Params = struct {
    marker: ?[]const u8 = null,
    max_items: ?u32 = null,
};

pub const Options = struct {
    group_name: []const u8,
    params: Params = .{},
};

pub const GroupMember = struct {
    allocator: Allocator,
    user_name: []u8,
    user_id: []u8,
    arn: []u8,
    path: []u8,
    create_date: []u8,

    pub fn deinit(self: GroupMember) void {
        self.allocator.free(self.user_name);
        self.allocator.free(self.user_id);
        self.allocator.free(self.arn);
        self.allocator.free(self.path);
        self.allocator.free(self.create_date);
    }
};

pub const GetGroupResult = struct {
    allocator: Allocator,
    group_name: []u8,
    group_id: []u8,
    arn: []u8,
    path: []u8,
    create_date: []u8,
    users: []GroupMember,
    next_marker: ?[]u8,

    pub fn deinit(self: GetGroupResult) void {
        self.allocator.free(self.group_name);
        self.allocator.free(self.group_id);
        self.allocator.free(self.arn);
        self.allocator.free(self.path);
        self.allocator.free(self.create_date);
        for (self.users) |u| u.deinit();
        self.allocator.free(self.users);
        if (self.next_marker) |m| self.allocator.free(m);
    }
};

pub fn getGroup(client: anytype, options: Options) !GetGroupResult {
    const body = try buildBody(client.allocator, options.group_name, options.params);
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
            std.log.err("IAM GetGroup error: status {d}", .{@intFromEnum(result.status)});
            return aws_errors.fromStatus(result.status);
        };
        defer client.allocator.free(code);
        std.log.err("IAM GetGroup error: {s} (status {d})", .{ code, @intFromEnum(result.status) });
        inline for (@typeInfo(IamGetGroupError).error_set.?) |entry| {
            if (std.mem.eql(u8, entry.name, code)) return @field(IamGetGroupError, entry.name);
        }
        return aws_errors.fromCode(code) orelse aws_errors.fromStatus(result.status);
    }

    return parseResponse(client.allocator, resp_body);
}

fn buildBody(allocator: Allocator, group_name: []const u8, params: Params) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);

    try body.appendSlice(allocator, "Action=GetGroup&Version=2010-05-08&GroupName=");
    const group_encoded = try uriEncode(allocator, group_name);
    defer allocator.free(group_encoded);
    try body.appendSlice(allocator, group_encoded);

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

fn xmlStr(allocator: Allocator, src: []const u8, tag: []const u8) ![]u8 {
    return xml.extractTagContent(allocator, src, tag) catch try allocator.dupe(u8, "");
}

fn parseMember(allocator: Allocator, src: []const u8) !GroupMember {
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

    return .{
        .allocator = allocator,
        .user_name = user_name,
        .user_id = user_id,
        .arn = arn,
        .path = path,
        .create_date = create_date,
    };
}

fn parseResponse(allocator: Allocator, body: []const u8) !GetGroupResult {
    const group_block = xml.extractTagContent(allocator, body, "Group") catch
        try allocator.dupe(u8, "");
    defer allocator.free(group_block);

    const group_name = try xmlStr(allocator, group_block, "GroupName");
    errdefer allocator.free(group_name);
    const group_id = try xmlStr(allocator, group_block, "GroupId");
    errdefer allocator.free(group_id);
    const arn = try xmlStr(allocator, group_block, "Arn");
    errdefer allocator.free(arn);
    const path = try xmlStr(allocator, group_block, "Path");
    errdefer allocator.free(path);
    const create_date = try xmlStr(allocator, group_block, "CreateDate");
    errdefer allocator.free(create_date);

    const users_block = xml.extractTagContent(allocator, body, "Users") catch
        try allocator.dupe(u8, "");
    defer allocator.free(users_block);

    var users: std.ArrayList(GroupMember) = .empty;
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

        const member = try parseMember(allocator, member_content);
        errdefer member.deinit();
        try users.append(allocator, member);

        offset += content_start + m_end + end_tag.len;
    }

    const next_marker: ?[]u8 = xml.extractTagContent(allocator, body, "Marker") catch null;
    errdefer if (next_marker) |m| allocator.free(m);

    return .{
        .allocator = allocator,
        .group_name = group_name,
        .group_id = group_id,
        .arn = arn,
        .path = path,
        .create_date = create_date,
        .users = try users.toOwnedSlice(allocator),
        .next_marker = next_marker,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "parseResponse group with members" {
    const body =
        \\<GetGroupResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        \\  <GetGroupResult>
        \\    <Group>
        \\      <Path>/</Path>
        \\      <GroupName>Admins</GroupName>
        \\      <GroupId>AGPAI3UMHF7RYEXAMPLE</GroupId>
        \\      <Arn>arn:aws:iam::123456789012:group/Admins</Arn>
        \\      <CreateDate>2013-04-18T05:01:58Z</CreateDate>
        \\    </Group>
        \\    <Users>
        \\      <member>
        \\        <UserName>alice</UserName>
        \\        <UserId>AIDAI3UMHF7RYEXAMPLE</UserId>
        \\        <Arn>arn:aws:iam::123456789012:user/alice</Arn>
        \\        <Path>/</Path>
        \\        <CreateDate>2013-04-18T05:01:58Z</CreateDate>
        \\      </member>
        \\    </Users>
        \\    <IsTruncated>false</IsTruncated>
        \\  </GetGroupResult>
        \\</GetGroupResponse>
    ;
    const result = try parseResponse(std.testing.allocator, body);
    defer result.deinit();

    try std.testing.expectEqualStrings("Admins", result.group_name);
    try std.testing.expectEqualStrings("AGPAI3UMHF7RYEXAMPLE", result.group_id);
    try std.testing.expectEqualStrings("arn:aws:iam::123456789012:group/Admins", result.arn);
    try std.testing.expectEqualStrings("/", result.path);
    try std.testing.expectEqual(@as(usize, 1), result.users.len);
    try std.testing.expectEqualStrings("alice", result.users[0].user_name);
    try std.testing.expect(result.next_marker == null);
}

test "parseResponse group with no members and marker" {
    const body =
        \\<GetGroupResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        \\  <GetGroupResult>
        \\    <Group>
        \\      <Path>/</Path>
        \\      <GroupName>Empty</GroupName>
        \\      <GroupId>ID</GroupId>
        \\      <Arn>arn:aws:iam::123:group/Empty</Arn>
        \\      <CreateDate>2020-01-01T00:00:00Z</CreateDate>
        \\    </Group>
        \\    <Users></Users>
        \\    <IsTruncated>true</IsTruncated>
        \\    <Marker>NEXT_PAGE_TOKEN</Marker>
        \\  </GetGroupResult>
        \\</GetGroupResponse>
    ;
    const result = try parseResponse(std.testing.allocator, body);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 0), result.users.len);
    try std.testing.expectEqualStrings("NEXT_PAGE_TOKEN", result.next_marker.?);
}

test "buildBody group name only" {
    const body = try buildBody(std.testing.allocator, "Admins", .{});
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("Action=GetGroup&Version=2010-05-08&GroupName=Admins", body);
}

test "buildBody with marker" {
    const body = try buildBody(std.testing.allocator, "Admins", .{ .marker = "abc" });
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("Action=GetGroup&Version=2010-05-08&GroupName=Admins&Marker=abc", body);
}
