const std = @import("std");
const Allocator = std.mem.Allocator;

const sigv4 = @import("../../../sig/sigv4.zig");
const xml = @import("../../../utils/xml.zig");
const aws_errors = @import("../../aws_errors.zig");

pub const IamListOpenIDConnectProvidersError = error{
    ServiceFailureException,
};

pub const Options = struct {};

pub const OpenIDConnectProvider = struct {
    allocator: Allocator,
    arn: []u8,

    pub fn deinit(self: OpenIDConnectProvider) void {
        self.allocator.free(self.arn);
    }
};

pub const Result = struct {
    allocator: Allocator,
    providers: []OpenIDConnectProvider,

    pub fn deinit(self: Result) void {
        for (self.providers) |p| p.deinit();
        self.allocator.free(self.providers);
    }
};

pub fn listOpenIDConnectProviders(client: anytype, options: Options) !Result {
    _ = options;
    const body = "Action=ListOpenIDConnectProviders&Version=2010-05-08";

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
            std.log.err("IAM ListOpenIDConnectProviders error: status {d}", .{@intFromEnum(result.status)});
            return aws_errors.fromStatus(result.status);
        };
        defer client.allocator.free(code);
        std.log.err("IAM ListOpenIDConnectProviders error: {s} (status {d})", .{ code, @intFromEnum(result.status) });
        inline for (@typeInfo(IamListOpenIDConnectProvidersError).error_set.?) |entry| {
            if (std.mem.eql(u8, entry.name, code)) return @field(IamListOpenIDConnectProvidersError, entry.name);
        }
        return aws_errors.fromCode(code) orelse aws_errors.fromStatus(result.status);
    }

    return parseResponse(client.allocator, resp_body);
}

fn xmlStr(allocator: Allocator, src: []const u8, tag: []const u8) ![]u8 {
    return xml.extractTagContent(allocator, src, tag) catch try allocator.dupe(u8, "");
}

fn parseResponse(allocator: Allocator, body: []const u8) !Result {
    const list_block = xml.extractTagContent(allocator, body, "OpenIDConnectProviderList") catch
        try allocator.dupe(u8, "");
    defer allocator.free(list_block);

    var providers: std.ArrayList(OpenIDConnectProvider) = .empty;
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

        const arn = try xmlStr(allocator, member_content, "Arn");
        errdefer allocator.free(arn);
        try providers.append(allocator, .{ .allocator = allocator, .arn = arn });

        offset += content_start + m_end + end_tag.len;
    }

    return .{
        .allocator = allocator,
        .providers = try providers.toOwnedSlice(allocator),
    };
}

// ============================================================================
// Tests
// ============================================================================

test "parseResponse single provider" {
    const body =
        \\<ListOpenIDConnectProvidersResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        \\  <ListOpenIDConnectProvidersResult>
        \\    <OpenIDConnectProviderList>
        \\      <member>
        \\        <Arn>arn:aws:iam::123456789012:oidc-provider/server.example.com</Arn>
        \\      </member>
        \\    </OpenIDConnectProviderList>
        \\  </ListOpenIDConnectProvidersResult>
        \\</ListOpenIDConnectProvidersResponse>
    ;
    const result = try parseResponse(std.testing.allocator, body);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.providers.len);
    try std.testing.expectEqualStrings("arn:aws:iam::123456789012:oidc-provider/server.example.com", result.providers[0].arn);
}

test "parseResponse multiple providers" {
    const body =
        \\<ListOpenIDConnectProvidersResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        \\  <ListOpenIDConnectProvidersResult>
        \\    <OpenIDConnectProviderList>
        \\      <member>
        \\        <Arn>arn:aws:iam::123:oidc-provider/one.example.com</Arn>
        \\      </member>
        \\      <member>
        \\        <Arn>arn:aws:iam::123:oidc-provider/two.example.com</Arn>
        \\      </member>
        \\    </OpenIDConnectProviderList>
        \\  </ListOpenIDConnectProvidersResult>
        \\</ListOpenIDConnectProvidersResponse>
    ;
    const result = try parseResponse(std.testing.allocator, body);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 2), result.providers.len);
    try std.testing.expectEqualStrings("arn:aws:iam::123:oidc-provider/one.example.com", result.providers[0].arn);
    try std.testing.expectEqualStrings("arn:aws:iam::123:oidc-provider/two.example.com", result.providers[1].arn);
}

test "parseResponse no providers" {
    const body =
        \\<ListOpenIDConnectProvidersResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        \\  <ListOpenIDConnectProvidersResult>
        \\    <OpenIDConnectProviderList></OpenIDConnectProviderList>
        \\  </ListOpenIDConnectProvidersResult>
        \\</ListOpenIDConnectProvidersResponse>
    ;
    const result = try parseResponse(std.testing.allocator, body);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 0), result.providers.len);
}
