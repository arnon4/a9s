const std = @import("std");
const Allocator = std.mem.Allocator;

const sigv4 = @import("../../../sig/sigv4.zig");
const xml = @import("../../../utils/xml.zig");
const aws_errors = @import("../../aws_errors.zig");

pub const IamGetSAMLProviderError = error{
    InvalidInputException,
    NoSuchEntityException,
    ServiceFailureException,
};

pub const Options = struct {
    saml_provider_arn: []const u8,
};

pub const SAMLPrivateKey = struct {
    allocator: Allocator,
    key_id: []u8,
    timestamp: []u8,

    pub fn deinit(self: SAMLPrivateKey) void {
        self.allocator.free(self.key_id);
        self.allocator.free(self.timestamp);
    }
};

pub const GetSAMLProviderResult = struct {
    allocator: Allocator,
    saml_metadata_document: []u8,
    create_date: []u8,
    valid_until: []u8,
    assertion_encryption_mode: []u8,
    private_key_list: []SAMLPrivateKey,

    pub fn deinit(self: GetSAMLProviderResult) void {
        self.allocator.free(self.saml_metadata_document);
        self.allocator.free(self.create_date);
        self.allocator.free(self.valid_until);
        self.allocator.free(self.assertion_encryption_mode);
        for (self.private_key_list) |k| k.deinit();
        self.allocator.free(self.private_key_list);
    }
};

pub fn getSAMLProvider(client: anytype, options: Options) !GetSAMLProviderResult {
    const encoded_arn = try encodeArn(client.allocator, options.saml_provider_arn);
    defer client.allocator.free(encoded_arn);

    const body = try std.fmt.allocPrint(
        client.allocator,
        "Action=GetSAMLProvider&Version=2010-05-08&SAMLProviderArn={s}",
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
            std.log.err("IAM GetSAMLProvider error: status {d}", .{@intFromEnum(result.status)});
            return aws_errors.fromStatus(result.status);
        };
        defer client.allocator.free(code);
        std.log.err("IAM GetSAMLProvider error: {s} (status {d})", .{ code, @intFromEnum(result.status) });
        inline for (@typeInfo(IamGetSAMLProviderError).error_set.?) |entry| {
            if (std.mem.eql(u8, entry.name, code)) return @field(IamGetSAMLProviderError, entry.name);
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

fn parsePrivateKeyList(allocator: Allocator, body: []const u8) ![]SAMLPrivateKey {
    const block = xml.extractTagContent(allocator, body, "PrivateKeyList") catch
        try allocator.dupe(u8, "");
    defer allocator.free(block);

    var keys: std.ArrayList(SAMLPrivateKey) = .empty;
    errdefer {
        for (keys.items) |k| k.deinit();
        keys.deinit(allocator);
    }

    var offset: usize = 0;
    while (true) {
        const slice = block[offset..];
        const start_tag = "<member";
        const m_start = std.mem.indexOf(u8, slice, start_tag) orelse break;
        const gt = std.mem.indexOfScalarPos(u8, slice, m_start + start_tag.len, '>') orelse break;
        const content_start = gt + 1;
        const end_tag = "</member>";
        const m_end = std.mem.indexOf(u8, slice[content_start..], end_tag) orelse break;
        const member_content = slice[content_start .. content_start + m_end];

        const key_id = try xmlStr(allocator, member_content, "KeyId");
        errdefer allocator.free(key_id);
        const timestamp = try xmlStr(allocator, member_content, "Timestamp");
        errdefer allocator.free(timestamp);
        try keys.append(allocator, .{ .allocator = allocator, .key_id = key_id, .timestamp = timestamp });

        offset += content_start + m_end + end_tag.len;
    }

    return keys.toOwnedSlice(allocator);
}

fn parseResponse(allocator: Allocator, body: []const u8) !GetSAMLProviderResult {
    const saml_metadata_document = try xmlStr(allocator, body, "SAMLMetadataDocument");
    errdefer allocator.free(saml_metadata_document);
    const create_date = try xmlStr(allocator, body, "CreateDate");
    errdefer allocator.free(create_date);
    const valid_until = try xmlStr(allocator, body, "ValidUntil");
    errdefer allocator.free(valid_until);
    const assertion_encryption_mode = try xmlStr(allocator, body, "AssertionEncryptionMode");
    errdefer allocator.free(assertion_encryption_mode);
    const private_key_list = try parsePrivateKeyList(allocator, body);
    errdefer {
        for (private_key_list) |k| k.deinit();
        allocator.free(private_key_list);
    }

    return .{
        .allocator = allocator,
        .saml_metadata_document = saml_metadata_document,
        .create_date = create_date,
        .valid_until = valid_until,
        .assertion_encryption_mode = assertion_encryption_mode,
        .private_key_list = private_key_list,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "parseResponse basic provider" {
    const body =
        \\<GetSAMLProviderResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        \\  <GetSAMLProviderResult>
        \\    <SAMLMetadataDocument>&lt;EntityDescriptor/&gt;</SAMLMetadataDocument>
        \\    <CreateDate>2013-04-18T05:01:58Z</CreateDate>
        \\    <ValidUntil>2026-12-31T23:59:59Z</ValidUntil>
        \\  </GetSAMLProviderResult>
        \\</GetSAMLProviderResponse>
    ;
    const result = try parseResponse(std.testing.allocator, body);
    defer result.deinit();

    try std.testing.expectEqualStrings("2013-04-18T05:01:58Z", result.create_date);
    try std.testing.expectEqualStrings("2026-12-31T23:59:59Z", result.valid_until);
    try std.testing.expectEqual(@as(usize, 0), result.private_key_list.len);
}

test "parseResponse with encryption mode and private keys" {
    const body =
        \\<GetSAMLProviderResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        \\  <GetSAMLProviderResult>
        \\    <SAMLMetadataDocument>&lt;EntityDescriptor/&gt;</SAMLMetadataDocument>
        \\    <CreateDate>2013-04-18T05:01:58Z</CreateDate>
        \\    <ValidUntil>2026-12-31T23:59:59Z</ValidUntil>
        \\    <AssertionEncryptionMode>Required</AssertionEncryptionMode>
        \\    <PrivateKeyList>
        \\      <member>
        \\        <KeyId>key-1</KeyId>
        \\        <Timestamp>2024-01-01T00:00:00Z</Timestamp>
        \\      </member>
        \\      <member>
        \\        <KeyId>key-2</KeyId>
        \\        <Timestamp>2024-06-01T00:00:00Z</Timestamp>
        \\      </member>
        \\    </PrivateKeyList>
        \\  </GetSAMLProviderResult>
        \\</GetSAMLProviderResponse>
    ;
    const result = try parseResponse(std.testing.allocator, body);
    defer result.deinit();

    try std.testing.expectEqualStrings("Required", result.assertion_encryption_mode);
    try std.testing.expectEqual(@as(usize, 2), result.private_key_list.len);
    try std.testing.expectEqualStrings("key-1", result.private_key_list[0].key_id);
    try std.testing.expectEqualStrings("2024-01-01T00:00:00Z", result.private_key_list[0].timestamp);
    try std.testing.expectEqualStrings("key-2", result.private_key_list[1].key_id);
}

test "encodeArn encodes colons and slashes" {
    const encoded = try encodeArn(std.testing.allocator, "arn:aws:iam::123:saml-provider/MyProvider");
    defer std.testing.allocator.free(encoded);
    try std.testing.expectEqualStrings("arn%3Aaws%3Aiam%3A%3A123%3Asaml-provider%2FMyProvider", encoded);
}
