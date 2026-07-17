const std = @import("std");
const Allocator = std.mem.Allocator;

const sigv4 = @import("../../../sig/sigv4.zig");
const xml = @import("../../../utils/xml.zig");
const aws_errors = @import("../../aws_errors.zig");

pub const IamGetPolicyVersionError = error{
    NoSuchEntityException,
    ServiceFailureException,
    InvalidInputException,
};

pub const Options = struct {
    /// The ARN of the managed policy.
    arn: []const u8,
    /// The policy version to retrieve (e.g. the policy's DefaultVersionId).
    version_id: []const u8,
};

pub const GetPolicyVersionResult = struct {
    allocator: Allocator,
    version_id: []u8,
    /// URL-decoded policy document JSON.
    document: []u8,
    is_default_version: bool,
    create_date: []u8,

    pub fn deinit(self: GetPolicyVersionResult) void {
        self.allocator.free(self.version_id);
        self.allocator.free(self.document);
        self.allocator.free(self.create_date);
    }
};

pub fn getPolicyVersion(client: anytype, options: Options) !GetPolicyVersionResult {
    const encoded_arn = try encode(client.allocator, options.arn);
    defer client.allocator.free(encoded_arn);
    const encoded_version = try encode(client.allocator, options.version_id);
    defer client.allocator.free(encoded_version);

    const body = try std.fmt.allocPrint(
        client.allocator,
        "Action=GetPolicyVersion&Version=2010-05-08&PolicyArn={s}&VersionId={s}",
        .{ encoded_arn, encoded_version },
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
            std.log.err("IAM GetPolicyVersion error: status {d}", .{@intFromEnum(result.status)});
            return aws_errors.fromStatus(result.status);
        };
        defer client.allocator.free(code);
        std.log.err("IAM GetPolicyVersion error: {s} (status {d})", .{ code, @intFromEnum(result.status) });
        inline for (@typeInfo(IamGetPolicyVersionError).error_set.?) |entry| {
            if (std.mem.eql(u8, entry.name, code)) return @field(IamGetPolicyVersionError, entry.name);
        }
        return aws_errors.fromCode(code) orelse aws_errors.fromStatus(result.status);
    }

    return parseResponse(client.allocator, resp_body);
}

fn encode(allocator: Allocator, input: []const u8) ![]u8 {
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

fn urlDecode(allocator: Allocator, input: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var i: usize = 0;
    while (i < input.len) {
        if (input[i] == '%' and i + 2 < input.len) {
            const byte = std.fmt.parseInt(u8, input[i + 1 .. i + 3], 16) catch {
                try out.append(allocator, input[i]);
                i += 1;
                continue;
            };
            try out.append(allocator, byte);
            i += 3;
        } else {
            try out.append(allocator, input[i]);
            i += 1;
        }
    }
    return out.toOwnedSlice(allocator);
}

fn xmlStr(allocator: Allocator, src: []const u8, tag: []const u8) ![]u8 {
    return xml.extractTagContent(allocator, src, tag) catch try allocator.dupe(u8, "");
}

fn parseResponse(allocator: Allocator, body: []const u8) !GetPolicyVersionResult {
    const version_block = try xml.extractTagContent(allocator, body, "PolicyVersion");
    defer allocator.free(version_block);

    const version_id = try xmlStr(allocator, version_block, "VersionId");
    errdefer allocator.free(version_id);
    const create_date = try xmlStr(allocator, version_block, "CreateDate");
    errdefer allocator.free(create_date);

    const document: []u8 = blk: {
        const encoded = try xmlStr(allocator, version_block, "Document");
        defer allocator.free(encoded);
        break :blk try urlDecode(allocator, encoded);
    };
    errdefer allocator.free(document);

    const is_default: bool = blk: {
        const s = xml.extractTagContent(allocator, version_block, "IsDefaultVersion") catch break :blk false;
        defer allocator.free(s);
        break :blk std.mem.eql(u8, s, "true");
    };

    return .{
        .allocator = allocator,
        .version_id = version_id,
        .document = document,
        .is_default_version = is_default,
        .create_date = create_date,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "parseResponse basic version" {
    const body =
        \\<GetPolicyVersionResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        \\  <GetPolicyVersionResult>
        \\    <PolicyVersion>
        \\      <Document>%7B%22Version%22%3A%222012-10-17%22%7D</Document>
        \\      <VersionId>v2</VersionId>
        \\      <IsDefaultVersion>true</IsDefaultVersion>
        \\      <CreateDate>2021-06-15T12:00:00Z</CreateDate>
        \\    </PolicyVersion>
        \\  </GetPolicyVersionResult>
        \\</GetPolicyVersionResponse>
    ;
    const result = try parseResponse(std.testing.allocator, body);
    defer result.deinit();

    try std.testing.expectEqualStrings("v2", result.version_id);
    try std.testing.expectEqualStrings("{\"Version\":\"2012-10-17\"}", result.document);
    try std.testing.expect(result.is_default_version);
    try std.testing.expectEqualStrings("2021-06-15T12:00:00Z", result.create_date);
}

test "encode arn" {
    const encoded = try encode(std.testing.allocator, "arn:aws:iam::123456789012:policy/my-policy");
    defer std.testing.allocator.free(encoded);
    try std.testing.expectEqualStrings("arn%3Aaws%3Aiam%3A%3A123456789012%3Apolicy/my-policy", encoded);
}
