const std = @import("std");
const Allocator = std.mem.Allocator;

const sigv4 = @import("../../../sig/sigv4.zig");
const xml = @import("../../../utils/xml.zig");
const aws_errors = @import("../../aws_errors.zig");

pub const IamListAttachedGroupPoliciesError = error{
    NoSuchEntityException,
    ServiceFailureException,
    InvalidInputException,
};

pub const Params = struct {
    path_prefix: ?[]const u8 = null,
    marker: ?[]const u8 = null,
    max_items: ?u32 = null,
};

pub const Options = struct {
    group_name: []const u8,
    params: Params = .{},
};

pub const AttachedPolicy = struct {
    allocator: Allocator,
    policy_name: []u8,
    policy_arn: []u8,

    pub fn deinit(self: AttachedPolicy) void {
        self.allocator.free(self.policy_name);
        self.allocator.free(self.policy_arn);
    }
};

pub const Result = struct {
    allocator: Allocator,
    policies: []AttachedPolicy,
    next_marker: ?[]u8,

    pub fn deinit(self: Result) void {
        for (self.policies) |p| p.deinit();
        self.allocator.free(self.policies);
        if (self.next_marker) |m| self.allocator.free(m);
    }
};

pub fn listAttachedGroupPolicies(client: anytype, options: Options) !Result {
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
            std.log.err("IAM ListAttachedGroupPolicies error: status {d}", .{@intFromEnum(result.status)});
            return aws_errors.fromStatus(result.status);
        };
        defer client.allocator.free(code);
        std.log.err("IAM ListAttachedGroupPolicies error: {s} (status {d})", .{ code, @intFromEnum(result.status) });
        inline for (@typeInfo(IamListAttachedGroupPoliciesError).error_set.?) |entry| {
            if (std.mem.eql(u8, entry.name, code)) return @field(IamListAttachedGroupPoliciesError, entry.name);
        }
        return aws_errors.fromCode(code) orelse aws_errors.fromStatus(result.status);
    }

    return parseResponse(client.allocator, resp_body);
}

fn buildBody(allocator: Allocator, group_name: []const u8, params: Params) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);

    try body.appendSlice(allocator, "Action=ListAttachedGroupPolicies&Version=2010-05-08&GroupName=");
    const group_encoded = try uriEncode(allocator, group_name);
    defer allocator.free(group_encoded);
    try body.appendSlice(allocator, group_encoded);

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
    const policies_block = xml.extractTagContent(allocator, body, "AttachedPolicies") catch
        try allocator.dupe(u8, "");
    defer allocator.free(policies_block);

    var policies: std.ArrayList(AttachedPolicy) = .empty;
    errdefer {
        for (policies.items) |p| p.deinit();
        policies.deinit(allocator);
    }

    var offset: usize = 0;
    while (true) {
        const slice = policies_block[offset..];
        const start_tag = "<member";
        const m_start = std.mem.indexOf(u8, slice, start_tag) orelse break;
        const gt = std.mem.indexOfScalarPos(u8, slice, m_start + start_tag.len, '>') orelse break;
        const content_start = gt + 1;
        const end_tag = "</member>";
        const m_end = std.mem.indexOf(u8, slice[content_start..], end_tag) orelse break;
        const member_content = slice[content_start .. content_start + m_end];

        const policy = try parseMember(allocator, member_content);
        errdefer policy.deinit();
        try policies.append(allocator, policy);

        offset += content_start + m_end + end_tag.len;
    }

    const next_marker: ?[]u8 = xml.extractTagContent(allocator, body, "Marker") catch null;
    errdefer if (next_marker) |m| allocator.free(m);

    return .{
        .allocator = allocator,
        .policies = try policies.toOwnedSlice(allocator),
        .next_marker = next_marker,
    };
}

fn xmlStr(allocator: Allocator, src: []const u8, tag: []const u8) ![]u8 {
    return xml.extractTagContent(allocator, src, tag) catch try allocator.dupe(u8, "");
}

fn parseMember(allocator: Allocator, src: []const u8) !AttachedPolicy {
    const policy_name = try xmlStr(allocator, src, "PolicyName");
    errdefer allocator.free(policy_name);
    const policy_arn = try xmlStr(allocator, src, "PolicyArn");
    errdefer allocator.free(policy_arn);

    return .{
        .allocator = allocator,
        .policy_name = policy_name,
        .policy_arn = policy_arn,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "parseResponse single attached policy" {
    const body =
        \\<ListAttachedGroupPoliciesResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        \\  <ListAttachedGroupPoliciesResult>
        \\    <IsTruncated>false</IsTruncated>
        \\    <AttachedPolicies>
        \\      <member>
        \\        <PolicyName>AdministratorAccess</PolicyName>
        \\        <PolicyArn>arn:aws:iam::aws:policy/AdministratorAccess</PolicyArn>
        \\      </member>
        \\    </AttachedPolicies>
        \\  </ListAttachedGroupPoliciesResult>
        \\</ListAttachedGroupPoliciesResponse>
    ;
    const result = try parseResponse(std.testing.allocator, body);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.policies.len);
    try std.testing.expectEqualStrings("AdministratorAccess", result.policies[0].policy_name);
    try std.testing.expectEqualStrings("arn:aws:iam::aws:policy/AdministratorAccess", result.policies[0].policy_arn);
    try std.testing.expect(result.next_marker == null);
}

test "parseResponse multiple attached policies" {
    const body =
        \\<ListAttachedGroupPoliciesResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        \\  <ListAttachedGroupPoliciesResult>
        \\    <IsTruncated>true</IsTruncated>
        \\    <AttachedPolicies>
        \\      <member>
        \\        <PolicyName>policy-one</PolicyName>
        \\        <PolicyArn>arn:aws:iam::123:policy/policy-one</PolicyArn>
        \\      </member>
        \\      <member>
        \\        <PolicyName>policy-two</PolicyName>
        \\        <PolicyArn>arn:aws:iam::123:policy/policy-two</PolicyArn>
        \\      </member>
        \\    </AttachedPolicies>
        \\    <Marker>NEXT_PAGE_TOKEN</Marker>
        \\  </ListAttachedGroupPoliciesResult>
        \\</ListAttachedGroupPoliciesResponse>
    ;
    const result = try parseResponse(std.testing.allocator, body);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 2), result.policies.len);
    try std.testing.expectEqualStrings("policy-one", result.policies[0].policy_name);
    try std.testing.expectEqualStrings("policy-two", result.policies[1].policy_name);
    try std.testing.expect(result.next_marker != null);
    try std.testing.expectEqualStrings("NEXT_PAGE_TOKEN", result.next_marker.?);
}

test "buildBody group name only" {
    const body = try buildBody(std.testing.allocator, "Admins", .{});
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("Action=ListAttachedGroupPolicies&Version=2010-05-08&GroupName=Admins", body);
}

test "buildBody with marker" {
    const body = try buildBody(std.testing.allocator, "Admins", .{ .marker = "abc" });
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("Action=ListAttachedGroupPolicies&Version=2010-05-08&GroupName=Admins&Marker=abc", body);
}
