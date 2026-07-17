const std = @import("std");
const Allocator = std.mem.Allocator;

const sigv4 = @import("../../../sig/sigv4.zig");
const xml = @import("../../../utils/xml.zig");
const aws_errors = @import("../../aws_errors.zig");

pub const IamGetOpenIDConnectProviderError = error{
    InvalidInputException,
    NoSuchEntityException,
    ServiceFailureException,
};

pub const Options = struct {
    open_id_connect_provider_arn: []const u8,
};

pub const GetOpenIDConnectProviderResult = struct {
    allocator: Allocator,
    url: []u8,
    client_id_list: [][]u8,
    thumbprint_list: [][]u8,
    create_date: []u8,

    pub fn deinit(self: GetOpenIDConnectProviderResult) void {
        self.allocator.free(self.url);
        for (self.client_id_list) |c| self.allocator.free(c);
        self.allocator.free(self.client_id_list);
        for (self.thumbprint_list) |t| self.allocator.free(t);
        self.allocator.free(self.thumbprint_list);
        self.allocator.free(self.create_date);
    }
};

pub fn getOpenIDConnectProvider(client: anytype, options: Options) !GetOpenIDConnectProviderResult {
    const encoded_arn = try encodeArn(client.allocator, options.open_id_connect_provider_arn);
    defer client.allocator.free(encoded_arn);

    const body = try std.fmt.allocPrint(
        client.allocator,
        "Action=GetOpenIDConnectProvider&Version=2010-05-08&OpenIDConnectProviderArn={s}",
        .{encoded_arn},
    );
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
            std.log.err("IAM GetOpenIDConnectProvider error: status {d}", .{@intFromEnum(result.status)});
            return aws_errors.fromStatus(result.status);
        };
        defer client.allocator.free(code);
        std.log.err("IAM GetOpenIDConnectProvider error: {s} (status {d})", .{ code, @intFromEnum(result.status) });
        inline for (@typeInfo(IamGetOpenIDConnectProviderError).error_set.?) |entry| {
            if (std.mem.eql(u8, entry.name, code)) return @field(IamGetOpenIDConnectProviderError, entry.name);
        }
        return aws_errors.fromCode(code) orelse aws_errors.fromStatus(result.status);
    }

    return parseResponse(client.allocator, resp_body);
}

fn encodeArn(allocator: Allocator, arn: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    for (arn) |c| {
        if (std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '~') {
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

fn parseStringMembers(allocator: Allocator, body: []const u8, list_tag: []const u8) ![][]u8 {
    const block = xml.extractTagContent(allocator, body, list_tag) catch
        try allocator.dupe(u8, "");
    defer allocator.free(block);

    var items: std.ArrayList([]u8) = .empty;
    errdefer {
        for (items.items) |i| allocator.free(i);
        items.deinit(allocator);
    }

    var offset: usize = 0;
    while (true) {
        const slice = block[offset..];
        const start_tag = "<member>";
        const m_start = std.mem.indexOf(u8, slice, start_tag) orelse break;
        const content_start = m_start + start_tag.len;
        const end_tag = "</member>";
        const m_end = std.mem.indexOf(u8, slice[content_start..], end_tag) orelse break;
        const value = try allocator.dupe(u8, slice[content_start .. content_start + m_end]);
        errdefer allocator.free(value);
        try items.append(allocator, value);

        offset += content_start + m_end + end_tag.len;
    }

    return items.toOwnedSlice(allocator);
}

fn parseResponse(allocator: Allocator, body: []const u8) !GetOpenIDConnectProviderResult {
    const url = try xmlStr(allocator, body, "Url");
    errdefer allocator.free(url);
    const create_date = try xmlStr(allocator, body, "CreateDate");
    errdefer allocator.free(create_date);

    const client_id_list = try parseStringMembers(allocator, body, "ClientIDList");
    errdefer {
        for (client_id_list) |c| allocator.free(c);
        allocator.free(client_id_list);
    }
    const thumbprint_list = try parseStringMembers(allocator, body, "ThumbprintList");
    errdefer {
        for (thumbprint_list) |t| allocator.free(t);
        allocator.free(thumbprint_list);
    }

    return .{
        .allocator = allocator,
        .url = url,
        .client_id_list = client_id_list,
        .thumbprint_list = thumbprint_list,
        .create_date = create_date,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "parseResponse basic provider" {
    const body =
        \\<GetOpenIDConnectProviderResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        \\  <GetOpenIDConnectProviderResult>
        \\    <Url>server.example.com</Url>
        \\    <ClientIDList>
        \\      <member>my-app-id</member>
        \\    </ClientIDList>
        \\    <ThumbprintList>
        \\      <member>ffffffffffffffffffffffffffffffffffffffff</member>
        \\    </ThumbprintList>
        \\    <CreateDate>2013-04-18T05:01:58Z</CreateDate>
        \\  </GetOpenIDConnectProviderResult>
        \\</GetOpenIDConnectProviderResponse>
    ;
    const result = try parseResponse(std.testing.allocator, body);
    defer result.deinit();

    try std.testing.expectEqualStrings("server.example.com", result.url);
    try std.testing.expectEqualStrings("2013-04-18T05:01:58Z", result.create_date);
    try std.testing.expectEqual(@as(usize, 1), result.client_id_list.len);
    try std.testing.expectEqualStrings("my-app-id", result.client_id_list[0]);
    try std.testing.expectEqual(@as(usize, 1), result.thumbprint_list.len);
    try std.testing.expectEqualStrings("ffffffffffffffffffffffffffffffffffffffff", result.thumbprint_list[0]);
}

test "parseResponse multiple client ids and thumbprints" {
    const body =
        \\<GetOpenIDConnectProviderResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        \\  <GetOpenIDConnectProviderResult>
        \\    <Url>token.actions.githubusercontent.com</Url>
        \\    <ClientIDList>
        \\      <member>sigstore</member>
        \\      <member>sts.amazonaws.com</member>
        \\    </ClientIDList>
        \\    <ThumbprintList>
        \\      <member>1111111111111111111111111111111111111111</member>
        \\      <member>2222222222222222222222222222222222222222</member>
        \\    </ThumbprintList>
        \\    <CreateDate>2022-06-01T00:00:00Z</CreateDate>
        \\  </GetOpenIDConnectProviderResult>
        \\</GetOpenIDConnectProviderResponse>
    ;
    const result = try parseResponse(std.testing.allocator, body);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 2), result.client_id_list.len);
    try std.testing.expectEqualStrings("sigstore", result.client_id_list[0]);
    try std.testing.expectEqualStrings("sts.amazonaws.com", result.client_id_list[1]);
    try std.testing.expectEqual(@as(usize, 2), result.thumbprint_list.len);
}

test "encodeArn encodes colons and slashes" {
    const encoded = try encodeArn(std.testing.allocator, "arn:aws:iam::123:oidc-provider/example.com");
    defer std.testing.allocator.free(encoded);
    try std.testing.expectEqualStrings("arn%3Aaws%3Aiam%3A%3A123%3Aoidc-provider%2Fexample.com", encoded);
}
