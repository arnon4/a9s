const std = @import("std");
const Allocator = std.mem.Allocator;

const sigv4 = @import("../../../sig/sigv4.zig");
const xml = @import("../../../utils/xml.zig");
const aws_errors = @import("../../aws_errors.zig");

pub const IamListGroupPoliciesError = error{
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

pub const Result = struct {
    allocator: Allocator,
    /// Names of inline policies embedded directly in the group.
    policy_names: [][]u8,
    next_marker: ?[]u8,

    pub fn deinit(self: Result) void {
        for (self.policy_names) |n| self.allocator.free(n);
        self.allocator.free(self.policy_names);
        if (self.next_marker) |m| self.allocator.free(m);
    }
};

pub fn listGroupPolicies(client: anytype, options: Options) !Result {
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
            std.log.err("IAM ListGroupPolicies error: status {d}", .{@intFromEnum(result.status)});
            return aws_errors.fromStatus(result.status);
        };
        defer client.allocator.free(code);
        std.log.err("IAM ListGroupPolicies error: {s} (status {d})", .{ code, @intFromEnum(result.status) });
        inline for (@typeInfo(IamListGroupPoliciesError).error_set.?) |entry| {
            if (std.mem.eql(u8, entry.name, code)) return @field(IamListGroupPoliciesError, entry.name);
        }
        return aws_errors.fromCode(code) orelse aws_errors.fromStatus(result.status);
    }

    return parseResponse(client.allocator, resp_body);
}

fn buildBody(allocator: Allocator, group_name: []const u8, params: Params) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);

    try body.appendSlice(allocator, "Action=ListGroupPolicies&Version=2010-05-08&GroupName=");
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

fn parseResponse(allocator: Allocator, body: []const u8) !Result {
    const names_block = xml.extractTagContent(allocator, body, "PolicyNames") catch
        try allocator.dupe(u8, "");
    defer allocator.free(names_block);

    var names: std.ArrayList([]u8) = .empty;
    errdefer {
        for (names.items) |n| allocator.free(n);
        names.deinit(allocator);
    }

    var offset: usize = 0;
    while (true) {
        const slice = names_block[offset..];
        const start_tag = "<member";
        const m_start = std.mem.indexOf(u8, slice, start_tag) orelse break;
        const gt = std.mem.indexOfScalarPos(u8, slice, m_start + start_tag.len, '>') orelse break;
        const content_start = gt + 1;
        const end_tag = "</member>";
        const m_end = std.mem.indexOf(u8, slice[content_start..], end_tag) orelse break;
        const member_content = slice[content_start .. content_start + m_end];

        const name = try allocator.dupe(u8, member_content);
        errdefer allocator.free(name);
        try names.append(allocator, name);

        offset += content_start + m_end + end_tag.len;
    }

    const next_marker: ?[]u8 = xml.extractTagContent(allocator, body, "Marker") catch null;
    errdefer if (next_marker) |m| allocator.free(m);

    return .{
        .allocator = allocator,
        .policy_names = try names.toOwnedSlice(allocator),
        .next_marker = next_marker,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "parseResponse single inline policy" {
    const body =
        \\<ListGroupPoliciesResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        \\  <ListGroupPoliciesResult>
        \\    <IsTruncated>false</IsTruncated>
        \\    <PolicyNames>
        \\      <member>MyInlinePolicy</member>
        \\    </PolicyNames>
        \\  </ListGroupPoliciesResult>
        \\</ListGroupPoliciesResponse>
    ;
    const result = try parseResponse(std.testing.allocator, body);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.policy_names.len);
    try std.testing.expectEqualStrings("MyInlinePolicy", result.policy_names[0]);
    try std.testing.expect(result.next_marker == null);
}

test "parseResponse multiple inline policies with marker" {
    const body =
        \\<ListGroupPoliciesResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        \\  <ListGroupPoliciesResult>
        \\    <IsTruncated>true</IsTruncated>
        \\    <PolicyNames>
        \\      <member>policy-one</member>
        \\      <member>policy-two</member>
        \\    </PolicyNames>
        \\    <Marker>NEXT_PAGE_TOKEN</Marker>
        \\  </ListGroupPoliciesResult>
        \\</ListGroupPoliciesResponse>
    ;
    const result = try parseResponse(std.testing.allocator, body);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 2), result.policy_names.len);
    try std.testing.expectEqualStrings("policy-one", result.policy_names[0]);
    try std.testing.expectEqualStrings("policy-two", result.policy_names[1]);
    try std.testing.expectEqualStrings("NEXT_PAGE_TOKEN", result.next_marker.?);
}

test "parseResponse no inline policies" {
    const body =
        \\<ListGroupPoliciesResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        \\  <ListGroupPoliciesResult>
        \\    <IsTruncated>false</IsTruncated>
        \\    <PolicyNames></PolicyNames>
        \\  </ListGroupPoliciesResult>
        \\</ListGroupPoliciesResponse>
    ;
    const result = try parseResponse(std.testing.allocator, body);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 0), result.policy_names.len);
}

test "buildBody group name only" {
    const body = try buildBody(std.testing.allocator, "Admins", .{});
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("Action=ListGroupPolicies&Version=2010-05-08&GroupName=Admins", body);
}

test "buildBody with marker" {
    const body = try buildBody(std.testing.allocator, "Admins", .{ .marker = "abc" });
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("Action=ListGroupPolicies&Version=2010-05-08&GroupName=Admins&Marker=abc", body);
}
