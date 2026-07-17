const std = @import("std");
const Allocator = std.mem.Allocator;

const sigv4 = @import("../../../sig/sigv4.zig");
const xml = @import("../../../utils/xml.zig");
const aws_errors = @import("../../aws_errors.zig");

pub const IamListSAMLProvidersError = error{
    ServiceFailureException,
};

pub const Options = struct {};

pub const SAMLProvider = struct {
    allocator: Allocator,
    arn: []u8,
    create_date: []u8,
    valid_until: []u8,

    pub fn deinit(self: SAMLProvider) void {
        self.allocator.free(self.arn);
        self.allocator.free(self.create_date);
        self.allocator.free(self.valid_until);
    }
};

pub const Result = struct {
    allocator: Allocator,
    providers: []SAMLProvider,

    pub fn deinit(self: Result) void {
        for (self.providers) |p| p.deinit();
        self.allocator.free(self.providers);
    }
};

pub fn listSAMLProviders(client: anytype, options: Options) !Result {
    _ = options;
    const body = "Action=ListSAMLProviders&Version=2010-05-08";

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
            std.log.err("IAM ListSAMLProviders error: status {d}", .{@intFromEnum(result.status)});
            return aws_errors.fromStatus(result.status);
        };
        defer client.allocator.free(code);
        std.log.err("IAM ListSAMLProviders error: {s} (status {d})", .{ code, @intFromEnum(result.status) });
        inline for (@typeInfo(IamListSAMLProvidersError).error_set.?) |entry| {
            if (std.mem.eql(u8, entry.name, code)) return @field(IamListSAMLProvidersError, entry.name);
        }
        return aws_errors.fromCode(code) orelse aws_errors.fromStatus(result.status);
    }

    return parseResponse(client.allocator, resp_body);
}

fn xmlStr(allocator: Allocator, src: []const u8, tag: []const u8) ![]u8 {
    return xml.extractTagContent(allocator, src, tag) catch try allocator.dupe(u8, "");
}

fn parseResponse(allocator: Allocator, body: []const u8) !Result {
    const list_block = xml.extractTagContent(allocator, body, "SAMLProviderList") catch
        try allocator.dupe(u8, "");
    defer allocator.free(list_block);

    var providers: std.ArrayList(SAMLProvider) = .empty;
    errdefer {
        for (providers.items) |p| p.deinit();
        providers.deinit(allocator);
    }

    var offset: usize = 0;
    while (true) {
        const slice = list_block[offset..];
        const start_tag = "<member";
        const m_start = std.mem.indexOf(u8, slice, start_tag) orelse break;
        const gt = std.mem.indexOfScalarPos(u8, slice, m_start + start_tag.len, '>') orelse break;
        const content_start = gt + 1;
        const end_tag = "</member>";
        const m_end = std.mem.indexOf(u8, slice[content_start..], end_tag) orelse break;
        const member_content = slice[content_start .. content_start + m_end];

        const provider = try parseMember(allocator, member_content);
        errdefer provider.deinit();
        try providers.append(allocator, provider);

        offset += content_start + m_end + end_tag.len;
    }

    return .{
        .allocator = allocator,
        .providers = try providers.toOwnedSlice(allocator),
    };
}

fn parseMember(allocator: Allocator, src: []const u8) !SAMLProvider {
    const arn = try xmlStr(allocator, src, "Arn");
    errdefer allocator.free(arn);
    const create_date = try xmlStr(allocator, src, "CreateDate");
    errdefer allocator.free(create_date);
    const valid_until = try xmlStr(allocator, src, "ValidUntil");
    errdefer allocator.free(valid_until);

    return .{
        .allocator = allocator,
        .arn = arn,
        .create_date = create_date,
        .valid_until = valid_until,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "parseResponse single provider" {
    const body =
        \\<ListSAMLProvidersResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        \\  <ListSAMLProvidersResult>
        \\    <SAMLProviderList>
        \\      <member>
        \\        <Arn>arn:aws:iam::123456789012:saml-provider/MyProvider</Arn>
        \\        <ValidUntil>2026-12-31T23:59:59Z</ValidUntil>
        \\        <CreateDate>2013-04-18T05:01:58Z</CreateDate>
        \\      </member>
        \\    </SAMLProviderList>
        \\  </ListSAMLProvidersResult>
        \\</ListSAMLProvidersResponse>
    ;
    const result = try parseResponse(std.testing.allocator, body);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.providers.len);
    const p = result.providers[0];
    try std.testing.expectEqualStrings("arn:aws:iam::123456789012:saml-provider/MyProvider", p.arn);
    try std.testing.expectEqualStrings("2026-12-31T23:59:59Z", p.valid_until);
    try std.testing.expectEqualStrings("2013-04-18T05:01:58Z", p.create_date);
}

test "parseResponse multiple providers" {
    const body =
        \\<ListSAMLProvidersResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        \\  <ListSAMLProvidersResult>
        \\    <SAMLProviderList>
        \\      <member>
        \\        <Arn>arn:aws:iam::123:saml-provider/one</Arn>
        \\        <ValidUntil>2026-01-01T00:00:00Z</ValidUntil>
        \\        <CreateDate>2020-01-01T00:00:00Z</CreateDate>
        \\      </member>
        \\      <member>
        \\        <Arn>arn:aws:iam::123:saml-provider/two</Arn>
        \\        <ValidUntil>2027-01-01T00:00:00Z</ValidUntil>
        \\        <CreateDate>2021-01-01T00:00:00Z</CreateDate>
        \\      </member>
        \\    </SAMLProviderList>
        \\  </ListSAMLProvidersResult>
        \\</ListSAMLProvidersResponse>
    ;
    const result = try parseResponse(std.testing.allocator, body);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 2), result.providers.len);
    try std.testing.expectEqualStrings("one", result.providers[0].arn[std.mem.lastIndexOfScalar(u8, result.providers[0].arn, '/').? + 1 ..]);
    try std.testing.expectEqualStrings("two", result.providers[1].arn[std.mem.lastIndexOfScalar(u8, result.providers[1].arn, '/').? + 1 ..]);
}

test "parseResponse no providers" {
    const body =
        \\<ListSAMLProvidersResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        \\  <ListSAMLProvidersResult>
        \\    <SAMLProviderList></SAMLProviderList>
        \\  </ListSAMLProvidersResult>
        \\</ListSAMLProvidersResponse>
    ;
    const result = try parseResponse(std.testing.allocator, body);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 0), result.providers.len);
}
