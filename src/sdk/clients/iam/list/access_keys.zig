const std = @import("std");
const Allocator = std.mem.Allocator;

const sigv4 = @import("../../../sig/sigv4.zig");
const xml = @import("../../../utils/xml.zig");
const aws_errors = @import("../../aws_errors.zig");

pub const IamListAccessKeysError = error{
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

pub const AccessKeyMetadata = struct {
    allocator: Allocator,
    user_name: []u8,
    access_key_id: []u8,
    status: []u8,
    create_date: []u8,

    pub fn deinit(self: AccessKeyMetadata) void {
        self.allocator.free(self.user_name);
        self.allocator.free(self.access_key_id);
        self.allocator.free(self.status);
        self.allocator.free(self.create_date);
    }
};

pub const Result = struct {
    allocator: Allocator,
    access_keys: []AccessKeyMetadata,
    next_marker: ?[]u8,

    pub fn deinit(self: Result) void {
        for (self.access_keys) |k| k.deinit();
        self.allocator.free(self.access_keys);
        if (self.next_marker) |m| self.allocator.free(m);
    }
};

pub fn listAccessKeys(client: anytype, options: Options) !Result {
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
            std.log.err("IAM ListAccessKeys error: status {d}", .{@intFromEnum(result.status)});
            return aws_errors.fromStatus(result.status);
        };
        defer client.allocator.free(code);
        std.log.err("IAM ListAccessKeys error: {s} (status {d})", .{ code, @intFromEnum(result.status) });
        inline for (@typeInfo(IamListAccessKeysError).error_set.?) |entry| {
            if (std.mem.eql(u8, entry.name, code)) return @field(IamListAccessKeysError, entry.name);
        }
        return aws_errors.fromCode(code) orelse aws_errors.fromStatus(result.status);
    }

    return parseResponse(client.allocator, resp_body);
}

fn buildBody(allocator: Allocator, user_name: []const u8, params: Params) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);

    try body.appendSlice(allocator, "Action=ListAccessKeys&Version=2010-05-08&UserName=");
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
    const keys_block = xml.extractTagContent(allocator, body, "AccessKeyMetadata") catch
        try allocator.dupe(u8, "");
    defer allocator.free(keys_block);

    var keys: std.ArrayList(AccessKeyMetadata) = .empty;
    errdefer {
        for (keys.items) |k| k.deinit();
        keys.deinit(allocator);
    }

    var offset: usize = 0;
    while (true) {
        const slice = keys_block[offset..];
        const start_tag = "<member";
        const m_start = std.mem.indexOf(u8, slice, start_tag) orelse break;
        const gt = std.mem.indexOfScalarPos(u8, slice, m_start + start_tag.len, '>') orelse break;
        const content_start = gt + 1;
        const end_tag = "</member>";
        const m_end = std.mem.indexOf(u8, slice[content_start..], end_tag) orelse break;
        const member_content = slice[content_start .. content_start + m_end];

        const key = try parseMember(allocator, member_content);
        errdefer key.deinit();
        try keys.append(allocator, key);

        offset += content_start + m_end + end_tag.len;
    }

    const next_marker: ?[]u8 = xml.extractTagContent(allocator, body, "Marker") catch null;
    errdefer if (next_marker) |m| allocator.free(m);

    return .{
        .allocator = allocator,
        .access_keys = try keys.toOwnedSlice(allocator),
        .next_marker = next_marker,
    };
}

fn xmlStr(allocator: Allocator, src: []const u8, tag: []const u8) ![]u8 {
    return xml.extractTagContent(allocator, src, tag) catch try allocator.dupe(u8, "");
}

fn parseMember(allocator: Allocator, src: []const u8) !AccessKeyMetadata {
    const user_name = try xmlStr(allocator, src, "UserName");
    errdefer allocator.free(user_name);
    const access_key_id = try xmlStr(allocator, src, "AccessKeyId");
    errdefer allocator.free(access_key_id);
    const status = try xmlStr(allocator, src, "Status");
    errdefer allocator.free(status);
    const create_date = try xmlStr(allocator, src, "CreateDate");
    errdefer allocator.free(create_date);

    return .{
        .allocator = allocator,
        .user_name = user_name,
        .access_key_id = access_key_id,
        .status = status,
        .create_date = create_date,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "parseResponse single key" {
    const body =
        \\<ListAccessKeysResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        \\  <ListAccessKeysResult>
        \\    <AccessKeyMetadata>
        \\      <member>
        \\        <UserName>alice</UserName>
        \\        <AccessKeyId>AKIAIOSFODNN7EXAMPLE</AccessKeyId>
        \\        <Status>Active</Status>
        \\        <CreateDate>2013-04-18T05:01:58Z</CreateDate>
        \\      </member>
        \\    </AccessKeyMetadata>
        \\    <IsTruncated>false</IsTruncated>
        \\  </ListAccessKeysResult>
        \\</ListAccessKeysResponse>
    ;
    const result = try parseResponse(std.testing.allocator, body);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.access_keys.len);
    try std.testing.expectEqualStrings("AKIAIOSFODNN7EXAMPLE", result.access_keys[0].access_key_id);
    try std.testing.expectEqualStrings("Active", result.access_keys[0].status);
    try std.testing.expect(result.next_marker == null);
}

test "parseResponse two keys" {
    const body =
        \\<ListAccessKeysResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        \\  <ListAccessKeysResult>
        \\    <AccessKeyMetadata>
        \\      <member>
        \\        <UserName>alice</UserName>
        \\        <AccessKeyId>KEY1</AccessKeyId>
        \\        <Status>Active</Status>
        \\        <CreateDate>2020-01-01T00:00:00Z</CreateDate>
        \\      </member>
        \\      <member>
        \\        <UserName>alice</UserName>
        \\        <AccessKeyId>KEY2</AccessKeyId>
        \\        <Status>Inactive</Status>
        \\        <CreateDate>2021-01-01T00:00:00Z</CreateDate>
        \\      </member>
        \\    </AccessKeyMetadata>
        \\  </ListAccessKeysResult>
        \\</ListAccessKeysResponse>
    ;
    const result = try parseResponse(std.testing.allocator, body);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 2), result.access_keys.len);
    try std.testing.expectEqualStrings("KEY1", result.access_keys[0].access_key_id);
    try std.testing.expectEqualStrings("KEY2", result.access_keys[1].access_key_id);
    try std.testing.expectEqualStrings("Inactive", result.access_keys[1].status);
}

test "buildBody user name only" {
    const body = try buildBody(std.testing.allocator, "alice", .{});
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("Action=ListAccessKeys&Version=2010-05-08&UserName=alice", body);
}
