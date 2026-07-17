const std = @import("std");
const Allocator = std.mem.Allocator;

const sigv4 = @import("../../../sig/sigv4.zig");
const xml = @import("../../../utils/xml.zig");
const aws_errors = @import("../../aws_errors.zig");

pub const IamListGroupsForUserError = error{
    NoSuchEntityException,
    ServiceFailureException,
};

pub const Params = struct {
    marker: ?[]const u8 = null,
    max_items: ?u32 = null,
};

pub const Options = struct {
    user_name: []const u8,
    params: Params = .{},
};

pub const Group = struct {
    allocator: Allocator,
    group_name: []u8,
    group_id: []u8,
    arn: []u8,
    path: []u8,
    create_date: []u8,

    pub fn deinit(self: Group) void {
        self.allocator.free(self.group_name);
        self.allocator.free(self.group_id);
        self.allocator.free(self.arn);
        self.allocator.free(self.path);
        self.allocator.free(self.create_date);
    }
};

pub const Result = struct {
    allocator: Allocator,
    groups: []Group,
    next_marker: ?[]u8,

    pub fn deinit(self: Result) void {
        for (self.groups) |g| g.deinit();
        self.allocator.free(self.groups);
        if (self.next_marker) |m| self.allocator.free(m);
    }
};

pub fn listGroupsForUser(client: anytype, options: Options) !Result {
    const body = try buildBody(client.allocator, options.user_name, options.params);
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
            std.log.err("IAM ListGroupsForUser error: status {d}", .{@intFromEnum(result.status)});
            return aws_errors.fromStatus(result.status);
        };
        defer client.allocator.free(code);
        std.log.err("IAM ListGroupsForUser error: {s} (status {d})", .{ code, @intFromEnum(result.status) });
        inline for (@typeInfo(IamListGroupsForUserError).error_set.?) |entry| {
            if (std.mem.eql(u8, entry.name, code)) return @field(IamListGroupsForUserError, entry.name);
        }
        return aws_errors.fromCode(code) orelse aws_errors.fromStatus(result.status);
    }

    return parseResponse(client.allocator, resp_body);
}

fn buildBody(allocator: Allocator, user_name: []const u8, params: Params) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);

    try body.appendSlice(allocator, "Action=ListGroupsForUser&Version=2010-05-08&UserName=");
    const user_encoded = try uriEncode(allocator, user_name);
    defer allocator.free(user_encoded);
    try body.appendSlice(allocator, user_encoded);

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
    const groups_block = xml.extractTagContent(allocator, body, "Groups") catch
        try allocator.dupe(u8, "");
    defer allocator.free(groups_block);

    var groups: std.ArrayList(Group) = .empty;
    errdefer {
        for (groups.items) |g| g.deinit();
        groups.deinit(allocator);
    }

    var offset: usize = 0;
    while (true) {
        const slice = groups_block[offset..];
        const start_tag = "<member";
        const m_start = std.mem.indexOf(u8, slice, start_tag) orelse break;
        const gt = std.mem.indexOfScalarPos(u8, slice, m_start + start_tag.len, '>') orelse break;
        const content_start = gt + 1;
        const end_tag = "</member>";
        const m_end = std.mem.indexOf(u8, slice[content_start..], end_tag) orelse break;
        const member_content = slice[content_start .. content_start + m_end];

        const group = try parseMember(allocator, member_content);
        errdefer group.deinit();
        try groups.append(allocator, group);

        offset += content_start + m_end + end_tag.len;
    }

    const next_marker: ?[]u8 = xml.extractTagContent(allocator, body, "Marker") catch null;
    errdefer if (next_marker) |m| allocator.free(m);

    return .{
        .allocator = allocator,
        .groups = try groups.toOwnedSlice(allocator),
        .next_marker = next_marker,
    };
}

fn xmlStr(allocator: Allocator, src: []const u8, tag: []const u8) ![]u8 {
    return xml.extractTagContent(allocator, src, tag) catch try allocator.dupe(u8, "");
}

fn parseMember(allocator: Allocator, src: []const u8) !Group {
    const group_name = try xmlStr(allocator, src, "GroupName");
    errdefer allocator.free(group_name);
    const group_id = try xmlStr(allocator, src, "GroupId");
    errdefer allocator.free(group_id);
    const arn = try xmlStr(allocator, src, "Arn");
    errdefer allocator.free(arn);
    const path = try xmlStr(allocator, src, "Path");
    errdefer allocator.free(path);
    const create_date = try xmlStr(allocator, src, "CreateDate");
    errdefer allocator.free(create_date);

    return .{
        .allocator = allocator,
        .group_name = group_name,
        .group_id = group_id,
        .arn = arn,
        .path = path,
        .create_date = create_date,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "parseResponse single group" {
    const body =
        \\<ListGroupsForUserResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        \\  <ListGroupsForUserResult>
        \\    <Groups>
        \\      <member>
        \\        <GroupName>Admins</GroupName>
        \\        <GroupId>AGPAI3UMHF7RYEXAMPLE</GroupId>
        \\        <Arn>arn:aws:iam::123456789012:group/Admins</Arn>
        \\        <Path>/</Path>
        \\        <CreateDate>2013-04-18T05:01:58Z</CreateDate>
        \\      </member>
        \\    </Groups>
        \\    <IsTruncated>false</IsTruncated>
        \\  </ListGroupsForUserResult>
        \\</ListGroupsForUserResponse>
    ;
    const result = try parseResponse(std.testing.allocator, body);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.groups.len);
    try std.testing.expectEqualStrings("Admins", result.groups[0].group_name);
    try std.testing.expect(result.next_marker == null);
}

test "parseResponse multiple groups with marker" {
    const body =
        \\<ListGroupsForUserResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        \\  <ListGroupsForUserResult>
        \\    <Groups>
        \\      <member>
        \\        <GroupName>group-one</GroupName>
        \\        <GroupId>ID1</GroupId>
        \\        <Arn>arn:aws:iam::123:group/group-one</Arn>
        \\        <Path>/</Path>
        \\        <CreateDate>2020-01-01T00:00:00Z</CreateDate>
        \\      </member>
        \\      <member>
        \\        <GroupName>group-two</GroupName>
        \\        <GroupId>ID2</GroupId>
        \\        <Arn>arn:aws:iam::123:group/group-two</Arn>
        \\        <Path>/</Path>
        \\        <CreateDate>2021-01-01T00:00:00Z</CreateDate>
        \\      </member>
        \\    </Groups>
        \\    <Marker>NEXT_PAGE_TOKEN</Marker>
        \\  </ListGroupsForUserResult>
        \\</ListGroupsForUserResponse>
    ;
    const result = try parseResponse(std.testing.allocator, body);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 2), result.groups.len);
    try std.testing.expectEqualStrings("group-one", result.groups[0].group_name);
    try std.testing.expectEqualStrings("group-two", result.groups[1].group_name);
    try std.testing.expectEqualStrings("NEXT_PAGE_TOKEN", result.next_marker.?);
}

test "buildBody user name only" {
    const body = try buildBody(std.testing.allocator, "alice", .{});
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("Action=ListGroupsForUser&Version=2010-05-08&UserName=alice", body);
}
