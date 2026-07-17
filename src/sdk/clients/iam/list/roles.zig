const std = @import("std");
const Allocator = std.mem.Allocator;

const sigv4 = @import("../../../sig/sigv4.zig");
const xml = @import("../../../utils/xml.zig");
const aws_errors = @import("../../aws_errors.zig");

pub const IamListRolesError = error{
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

pub const Role = struct {
    allocator: Allocator,
    role_name: []u8,
    role_id: []u8,
    arn: []u8,
    path: []u8,
    create_date: []u8,
    description: []u8,
    max_session_duration: u32,

    pub fn deinit(self: Role) void {
        self.allocator.free(self.role_name);
        self.allocator.free(self.role_id);
        self.allocator.free(self.arn);
        self.allocator.free(self.path);
        self.allocator.free(self.create_date);
        self.allocator.free(self.description);
    }

    pub fn clone(self: Role, allocator: Allocator) !Role {
        const role_name = try allocator.dupe(u8, self.role_name);
        errdefer allocator.free(role_name);
        const role_id = try allocator.dupe(u8, self.role_id);
        errdefer allocator.free(role_id);
        const arn = try allocator.dupe(u8, self.arn);
        errdefer allocator.free(arn);
        const path = try allocator.dupe(u8, self.path);
        errdefer allocator.free(path);
        const create_date = try allocator.dupe(u8, self.create_date);
        errdefer allocator.free(create_date);
        const description = try allocator.dupe(u8, self.description);
        errdefer allocator.free(description);
        return .{
            .allocator = allocator,
            .role_name = role_name,
            .role_id = role_id,
            .arn = arn,
            .path = path,
            .create_date = create_date,
            .description = description,
            .max_session_duration = self.max_session_duration,
        };
    }
};

pub const Result = struct {
    allocator: Allocator,
    roles: []Role,
    next_marker: ?[]u8,

    pub fn deinit(self: Result) void {
        for (self.roles) |r| r.deinit();
        self.allocator.free(self.roles);
        if (self.next_marker) |m| self.allocator.free(m);
    }
};

pub fn listRoles(client: anytype, options: Options) !Result {
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
            std.log.err("IAM ListRoles error: status {d}", .{@intFromEnum(result.status)});
            return aws_errors.fromStatus(result.status);
        };
        defer client.allocator.free(code);
        std.log.err("IAM ListRoles error: {s} (status {d})", .{ code, @intFromEnum(result.status) });
        inline for (@typeInfo(IamListRolesError).error_set.?) |entry| {
            if (std.mem.eql(u8, entry.name, code)) return @field(IamListRolesError, entry.name);
        }
        return aws_errors.fromCode(code) orelse aws_errors.fromStatus(result.status);
    }

    return parseResponse(client.allocator, resp_body);
}

fn buildBody(allocator: Allocator, params: Params) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);

    try body.appendSlice(allocator, "Action=ListRoles&Version=2010-05-08");

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
    const roles_block = xml.extractTagContent(allocator, body, "Roles") catch
        try allocator.dupe(u8, "");
    defer allocator.free(roles_block);

    var roles: std.ArrayList(Role) = .empty;
    errdefer {
        for (roles.items) |r| r.deinit();
        roles.deinit(allocator);
    }

    var offset: usize = 0;
    while (true) {
        const slice = roles_block[offset..];
        const start_tag = "<member";
        const m_start = std.mem.indexOf(u8, slice, start_tag) orelse break;
        const gt = std.mem.indexOfScalarPos(u8, slice, m_start + start_tag.len, '>') orelse break;
        const content_start = gt + 1;
        const end_tag = "</member>";
        const m_end = std.mem.indexOf(u8, slice[content_start..], end_tag) orelse break;
        const member_content = slice[content_start .. content_start + m_end];

        const role = try parseMember(allocator, member_content);
        errdefer role.deinit();
        try roles.append(allocator, role);

        offset += content_start + m_end + end_tag.len;
    }

    const next_marker: ?[]u8 = xml.extractTagContent(allocator, body, "Marker") catch null;
    errdefer if (next_marker) |m| allocator.free(m);

    return .{
        .allocator = allocator,
        .roles = try roles.toOwnedSlice(allocator),
        .next_marker = next_marker,
    };
}

fn xmlStr(allocator: Allocator, src: []const u8, tag: []const u8) ![]u8 {
    return xml.extractTagContent(allocator, src, tag) catch try allocator.dupe(u8, "");
}

fn xmlInt(comptime T: type, src: []const u8, tag: []const u8) T {
    const allocator = std.heap.page_allocator;
    const val = xml.extractTagContent(allocator, src, tag) catch return 0;
    defer allocator.free(val);
    return std.fmt.parseInt(T, val, 10) catch 0;
}

fn parseMember(allocator: Allocator, src: []const u8) !Role {
    const role_name = try xmlStr(allocator, src, "RoleName");
    errdefer allocator.free(role_name);
    const role_id = try xmlStr(allocator, src, "RoleId");
    errdefer allocator.free(role_id);
    const arn = try xmlStr(allocator, src, "Arn");
    errdefer allocator.free(arn);
    const path = try xmlStr(allocator, src, "Path");
    errdefer allocator.free(path);
    const create_date = try xmlStr(allocator, src, "CreateDate");
    errdefer allocator.free(create_date);
    const description = try xmlStr(allocator, src, "Description");
    errdefer allocator.free(description);

    return .{
        .allocator = allocator,
        .role_name = role_name,
        .role_id = role_id,
        .arn = arn,
        .path = path,
        .create_date = create_date,
        .description = description,
        .max_session_duration = xmlInt(u32, src, "MaxSessionDuration"),
    };
}

// ============================================================================
// Tests
// ============================================================================

test "parseResponse single role" {
    const body =
        \\<ListRolesResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        \\  <ListRolesResult>
        \\    <IsTruncated>false</IsTruncated>
        \\    <Roles>
        \\      <member>
        \\        <RoleName>my-role</RoleName>
        \\        <RoleId>AROAI3UMHF7RYEXAMPLE</RoleId>
        \\        <Arn>arn:aws:iam::123456789012:role/my-role</Arn>
        \\        <Path>/</Path>
        \\        <CreateDate>2013-04-18T05:01:58Z</CreateDate>
        \\        <Description>A test role</Description>
        \\        <MaxSessionDuration>3600</MaxSessionDuration>
        \\      </member>
        \\    </Roles>
        \\  </ListRolesResult>
        \\</ListRolesResponse>
    ;
    const result = try parseResponse(std.testing.allocator, body);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.roles.len);
    const r = result.roles[0];
    try std.testing.expectEqualStrings("my-role", r.role_name);
    try std.testing.expectEqualStrings("AROAI3UMHF7RYEXAMPLE", r.role_id);
    try std.testing.expectEqualStrings("arn:aws:iam::123456789012:role/my-role", r.arn);
    try std.testing.expectEqualStrings("/", r.path);
    try std.testing.expectEqualStrings("2013-04-18T05:01:58Z", r.create_date);
    try std.testing.expectEqualStrings("A test role", r.description);
    try std.testing.expectEqual(@as(u32, 3600), r.max_session_duration);
    try std.testing.expect(result.next_marker == null);
}

test "parseResponse multiple roles" {
    const body =
        \\<ListRolesResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        \\  <ListRolesResult>
        \\    <IsTruncated>false</IsTruncated>
        \\    <Roles>
        \\      <member>
        \\        <RoleName>role-one</RoleName>
        \\        <RoleId>ROLEID1</RoleId>
        \\        <Arn>arn:aws:iam::123:role/role-one</Arn>
        \\        <Path>/</Path>
        \\        <CreateDate>2020-01-01T00:00:00Z</CreateDate>
        \\        <Description></Description>
        \\        <MaxSessionDuration>3600</MaxSessionDuration>
        \\      </member>
        \\      <member>
        \\        <RoleName>role-two</RoleName>
        \\        <RoleId>ROLEID2</RoleId>
        \\        <Arn>arn:aws:iam::123:role/role-two</Arn>
        \\        <Path>/svc/</Path>
        \\        <CreateDate>2021-06-15T12:00:00Z</CreateDate>
        \\        <Description>Service role</Description>
        \\        <MaxSessionDuration>7200</MaxSessionDuration>
        \\      </member>
        \\    </Roles>
        \\  </ListRolesResult>
        \\</ListRolesResponse>
    ;
    const result = try parseResponse(std.testing.allocator, body);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 2), result.roles.len);
    try std.testing.expectEqualStrings("role-one", result.roles[0].role_name);
    try std.testing.expectEqualStrings("role-two", result.roles[1].role_name);
    try std.testing.expectEqualStrings("/svc/", result.roles[1].path);
    try std.testing.expectEqual(@as(u32, 7200), result.roles[1].max_session_duration);
}

test "parseResponse with pagination marker" {
    const body =
        \\<ListRolesResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        \\  <ListRolesResult>
        \\    <IsTruncated>true</IsTruncated>
        \\    <Roles></Roles>
        \\    <Marker>NEXT_PAGE_TOKEN</Marker>
        \\  </ListRolesResult>
        \\</ListRolesResponse>
    ;
    const result = try parseResponse(std.testing.allocator, body);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 0), result.roles.len);
    try std.testing.expect(result.next_marker != null);
    try std.testing.expectEqualStrings("NEXT_PAGE_TOKEN", result.next_marker.?);
}

test "buildBody action only" {
    const body = try buildBody(std.testing.allocator, .{});
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("Action=ListRoles&Version=2010-05-08", body);
}

test "buildBody with path prefix" {
    const body = try buildBody(std.testing.allocator, .{ .path_prefix = "/svc/" });
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("Action=ListRoles&Version=2010-05-08&PathPrefix=/svc/", body);
}

test "buildBody with max items" {
    const body = try buildBody(std.testing.allocator, .{ .max_items = 50 });
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("Action=ListRoles&Version=2010-05-08&MaxItems=50", body);
}
