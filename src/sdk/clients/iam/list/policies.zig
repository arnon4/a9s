const std = @import("std");
const Allocator = std.mem.Allocator;

const sigv4 = @import("../../../sig/sigv4.zig");
const xml = @import("../../../utils/xml.zig");
const aws_errors = @import("../../aws_errors.zig");

pub const IamListPoliciesError = error{
    ServiceFailureException,
    InvalidInputException,
};

pub const Scope = enum {
    all,
    aws,
    local,

    fn toParam(self: Scope) []const u8 {
        return switch (self) {
            .all => "All",
            .aws => "AWS",
            .local => "Local",
        };
    }
};

pub const PolicyUsageFilter = enum {
    permissions_policy,
    permissions_boundary,

    fn toParam(self: PolicyUsageFilter) []const u8 {
        return switch (self) {
            .permissions_policy => "PermissionsPolicy",
            .permissions_boundary => "PermissionsBoundary",
        };
    }
};

pub const Params = struct {
    scope: ?Scope = null,
    only_attached: ?bool = null,
    path_prefix: ?[]const u8 = null,
    policy_usage_filter: ?PolicyUsageFilter = null,
    marker: ?[]const u8 = null,
    max_items: ?u32 = null,
};

pub const Options = struct {
    params: Params = .{},
};

pub const Policy = struct {
    allocator: Allocator,
    policy_name: []u8,
    policy_id: []u8,
    arn: []u8,
    path: []u8,
    default_version_id: []u8,
    description: []u8,
    create_date: []u8,
    update_date: []u8,
    attachment_count: u32,
    permissions_boundary_usage_count: u32,
    is_attachable: bool,

    pub fn deinit(self: Policy) void {
        self.allocator.free(self.policy_name);
        self.allocator.free(self.policy_id);
        self.allocator.free(self.arn);
        self.allocator.free(self.path);
        self.allocator.free(self.default_version_id);
        self.allocator.free(self.description);
        self.allocator.free(self.create_date);
        self.allocator.free(self.update_date);
    }

    pub fn clone(self: Policy, allocator: Allocator) !Policy {
        const policy_name = try allocator.dupe(u8, self.policy_name);
        errdefer allocator.free(policy_name);
        const policy_id = try allocator.dupe(u8, self.policy_id);
        errdefer allocator.free(policy_id);
        const arn = try allocator.dupe(u8, self.arn);
        errdefer allocator.free(arn);
        const path = try allocator.dupe(u8, self.path);
        errdefer allocator.free(path);
        const default_version_id = try allocator.dupe(u8, self.default_version_id);
        errdefer allocator.free(default_version_id);
        const description = try allocator.dupe(u8, self.description);
        errdefer allocator.free(description);
        const create_date = try allocator.dupe(u8, self.create_date);
        errdefer allocator.free(create_date);
        const update_date = try allocator.dupe(u8, self.update_date);
        errdefer allocator.free(update_date);
        return .{
            .allocator = allocator,
            .policy_name = policy_name,
            .policy_id = policy_id,
            .arn = arn,
            .path = path,
            .default_version_id = default_version_id,
            .description = description,
            .create_date = create_date,
            .update_date = update_date,
            .attachment_count = self.attachment_count,
            .permissions_boundary_usage_count = self.permissions_boundary_usage_count,
            .is_attachable = self.is_attachable,
        };
    }
};

pub const Result = struct {
    allocator: Allocator,
    policies: []Policy,
    next_marker: ?[]u8,

    pub fn deinit(self: Result) void {
        for (self.policies) |p| p.deinit();
        self.allocator.free(self.policies);
        if (self.next_marker) |m| self.allocator.free(m);
    }
};

pub fn listPolicies(client: anytype, options: Options) !Result {
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
            std.log.err("IAM ListPolicies error: status {d}", .{@intFromEnum(result.status)});
            return aws_errors.fromStatus(result.status);
        };
        defer client.allocator.free(code);
        std.log.err("IAM ListPolicies error: {s} (status {d})", .{ code, @intFromEnum(result.status) });
        inline for (@typeInfo(IamListPoliciesError).error_set.?) |entry| {
            if (std.mem.eql(u8, entry.name, code)) return @field(IamListPoliciesError, entry.name);
        }
        return aws_errors.fromCode(code) orelse aws_errors.fromStatus(result.status);
    }

    return parseResponse(client.allocator, resp_body);
}

fn buildBody(allocator: Allocator, params: Params) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);

    try body.appendSlice(allocator, "Action=ListPolicies&Version=2010-05-08");

    if (params.scope) |s| {
        try body.appendSlice(allocator, "&Scope=");
        try body.appendSlice(allocator, s.toParam());
    }
    if (params.only_attached) |oa| {
        try body.appendSlice(allocator, if (oa) "&OnlyAttached=true" else "&OnlyAttached=false");
    }
    if (params.path_prefix) |pp| {
        const encoded = try uriEncode(allocator, pp);
        defer allocator.free(encoded);
        try body.appendSlice(allocator, "&PathPrefix=");
        try body.appendSlice(allocator, encoded);
    }
    if (params.policy_usage_filter) |puf| {
        try body.appendSlice(allocator, "&PolicyUsageFilter=");
        try body.appendSlice(allocator, puf.toParam());
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
    const policies_block = xml.extractTagContent(allocator, body, "Policies") catch
        try allocator.dupe(u8, "");
    defer allocator.free(policies_block);

    var policies: std.ArrayList(Policy) = .empty;
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

fn xmlInt(comptime T: type, src: []const u8, tag: []const u8) T {
    const allocator = std.heap.page_allocator;
    const val = xml.extractTagContent(allocator, src, tag) catch return 0;
    defer allocator.free(val);
    return std.fmt.parseInt(T, val, 10) catch 0;
}

fn xmlBool(src: []const u8, tag: []const u8) bool {
    const allocator = std.heap.page_allocator;
    const val = xml.extractTagContent(allocator, src, tag) catch return false;
    defer allocator.free(val);
    return std.mem.eql(u8, val, "true");
}

/// Exposed for reuse by get/policy.zig — GetPolicy's <Policy> block has the same child tags.
pub fn parseMember(allocator: Allocator, src: []const u8) !Policy {
    const policy_name = try xmlStr(allocator, src, "PolicyName");
    errdefer allocator.free(policy_name);
    const policy_id = try xmlStr(allocator, src, "PolicyId");
    errdefer allocator.free(policy_id);
    const arn = try xmlStr(allocator, src, "Arn");
    errdefer allocator.free(arn);
    const path = try xmlStr(allocator, src, "Path");
    errdefer allocator.free(path);
    const default_version_id = try xmlStr(allocator, src, "DefaultVersionId");
    errdefer allocator.free(default_version_id);
    const description = try xmlStr(allocator, src, "Description");
    errdefer allocator.free(description);
    const create_date = try xmlStr(allocator, src, "CreateDate");
    errdefer allocator.free(create_date);
    const update_date = try xmlStr(allocator, src, "UpdateDate");
    errdefer allocator.free(update_date);

    return .{
        .allocator = allocator,
        .policy_name = policy_name,
        .policy_id = policy_id,
        .arn = arn,
        .path = path,
        .default_version_id = default_version_id,
        .description = description,
        .create_date = create_date,
        .update_date = update_date,
        .attachment_count = xmlInt(u32, src, "AttachmentCount"),
        .permissions_boundary_usage_count = xmlInt(u32, src, "PermissionsBoundaryUsageCount"),
        .is_attachable = xmlBool(src, "IsAttachable"),
    };
}

// ============================================================================
// Tests
// ============================================================================

test "parseResponse single policy" {
    const body =
        \\<ListPoliciesResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        \\  <ListPoliciesResult>
        \\    <IsTruncated>false</IsTruncated>
        \\    <Policies>
        \\      <member>
        \\        <PolicyName>my-policy</PolicyName>
        \\        <PolicyId>ANPAI3UMHF7RYEXAMPLE</PolicyId>
        \\        <Arn>arn:aws:iam::123456789012:policy/my-policy</Arn>
        \\        <Path>/</Path>
        \\        <DefaultVersionId>v1</DefaultVersionId>
        \\        <AttachmentCount>2</AttachmentCount>
        \\        <PermissionsBoundaryUsageCount>0</PermissionsBoundaryUsageCount>
        \\        <IsAttachable>true</IsAttachable>
        \\        <Description>A test policy</Description>
        \\        <CreateDate>2013-04-18T05:01:58Z</CreateDate>
        \\        <UpdateDate>2013-04-18T05:01:58Z</UpdateDate>
        \\      </member>
        \\    </Policies>
        \\  </ListPoliciesResult>
        \\</ListPoliciesResponse>
    ;
    const result = try parseResponse(std.testing.allocator, body);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.policies.len);
    const p = result.policies[0];
    try std.testing.expectEqualStrings("my-policy", p.policy_name);
    try std.testing.expectEqualStrings("ANPAI3UMHF7RYEXAMPLE", p.policy_id);
    try std.testing.expectEqualStrings("arn:aws:iam::123456789012:policy/my-policy", p.arn);
    try std.testing.expectEqualStrings("/", p.path);
    try std.testing.expectEqualStrings("v1", p.default_version_id);
    try std.testing.expectEqual(@as(u32, 2), p.attachment_count);
    try std.testing.expectEqual(@as(u32, 0), p.permissions_boundary_usage_count);
    try std.testing.expect(p.is_attachable);
    try std.testing.expectEqualStrings("A test policy", p.description);
    try std.testing.expectEqualStrings("2013-04-18T05:01:58Z", p.create_date);
    try std.testing.expect(result.next_marker == null);
}

test "parseResponse multiple policies" {
    const body =
        \\<ListPoliciesResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        \\  <ListPoliciesResult>
        \\    <IsTruncated>false</IsTruncated>
        \\    <Policies>
        \\      <member>
        \\        <PolicyName>policy-one</PolicyName>
        \\        <PolicyId>ID1</PolicyId>
        \\        <Arn>arn:aws:iam::123:policy/policy-one</Arn>
        \\        <Path>/</Path>
        \\        <DefaultVersionId>v1</DefaultVersionId>
        \\        <AttachmentCount>0</AttachmentCount>
        \\        <PermissionsBoundaryUsageCount>0</PermissionsBoundaryUsageCount>
        \\        <IsAttachable>true</IsAttachable>
        \\        <Description></Description>
        \\        <CreateDate>2020-01-01T00:00:00Z</CreateDate>
        \\        <UpdateDate>2020-01-01T00:00:00Z</UpdateDate>
        \\      </member>
        \\      <member>
        \\        <PolicyName>policy-two</PolicyName>
        \\        <PolicyId>ID2</PolicyId>
        \\        <Arn>arn:aws:iam::123:policy/policy-two</Arn>
        \\        <Path>/svc/</Path>
        \\        <DefaultVersionId>v2</DefaultVersionId>
        \\        <AttachmentCount>3</AttachmentCount>
        \\        <PermissionsBoundaryUsageCount>1</PermissionsBoundaryUsageCount>
        \\        <IsAttachable>false</IsAttachable>
        \\        <Description>Service policy</Description>
        \\        <CreateDate>2021-06-15T12:00:00Z</CreateDate>
        \\        <UpdateDate>2021-07-01T00:00:00Z</UpdateDate>
        \\      </member>
        \\    </Policies>
        \\  </ListPoliciesResult>
        \\</ListPoliciesResponse>
    ;
    const result = try parseResponse(std.testing.allocator, body);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 2), result.policies.len);
    try std.testing.expectEqualStrings("policy-one", result.policies[0].policy_name);
    try std.testing.expectEqualStrings("policy-two", result.policies[1].policy_name);
    try std.testing.expectEqualStrings("/svc/", result.policies[1].path);
    try std.testing.expectEqual(@as(u32, 3), result.policies[1].attachment_count);
    try std.testing.expect(!result.policies[1].is_attachable);
}

test "parseResponse with pagination marker" {
    const body =
        \\<ListPoliciesResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        \\  <ListPoliciesResult>
        \\    <IsTruncated>true</IsTruncated>
        \\    <Policies></Policies>
        \\    <Marker>NEXT_PAGE_TOKEN</Marker>
        \\  </ListPoliciesResult>
        \\</ListPoliciesResponse>
    ;
    const result = try parseResponse(std.testing.allocator, body);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 0), result.policies.len);
    try std.testing.expect(result.next_marker != null);
    try std.testing.expectEqualStrings("NEXT_PAGE_TOKEN", result.next_marker.?);
}

test "buildBody action only" {
    const body = try buildBody(std.testing.allocator, .{});
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("Action=ListPolicies&Version=2010-05-08", body);
}

test "buildBody with scope and only attached" {
    const body = try buildBody(std.testing.allocator, .{ .scope = .local, .only_attached = true });
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("Action=ListPolicies&Version=2010-05-08&Scope=Local&OnlyAttached=true", body);
}

test "buildBody with path prefix and marker" {
    const body = try buildBody(std.testing.allocator, .{ .path_prefix = "/svc/", .marker = "abc" });
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("Action=ListPolicies&Version=2010-05-08&PathPrefix=/svc/&Marker=abc", body);
}

test "buildBody with max items" {
    const body = try buildBody(std.testing.allocator, .{ .max_items = 50 });
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("Action=ListPolicies&Version=2010-05-08&MaxItems=50", body);
}
