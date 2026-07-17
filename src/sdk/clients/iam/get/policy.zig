const std = @import("std");
const Allocator = std.mem.Allocator;

const sigv4 = @import("../../../sig/sigv4.zig");
const xml = @import("../../../utils/xml.zig");
const aws_errors = @import("../../aws_errors.zig");
const policies_mod = @import("../list/policies.zig");

pub const IamGetPolicyError = error{
    NoSuchEntityException,
    ServiceFailureException,
    InvalidInputException,
};

pub const Options = struct {
    /// The ARN of the managed policy to fetch.
    arn: []const u8,
};

/// Same shape as list/policies.zig's Policy — GetPolicy returns a single <Policy> block.
pub const GetPolicyResult = policies_mod.Policy;

pub fn getPolicy(client: anytype, options: Options) !GetPolicyResult {
    const encoded_arn = try encodeArn(client.allocator, options.arn);
    defer client.allocator.free(encoded_arn);

    const body = try std.fmt.allocPrint(
        client.allocator,
        "Action=GetPolicy&Version=2010-05-08&PolicyArn={s}",
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
            std.log.err("IAM GetPolicy error: status {d}", .{@intFromEnum(result.status)});
            return aws_errors.fromStatus(result.status);
        };
        defer client.allocator.free(code);
        std.log.err("IAM GetPolicy error: {s} (status {d})", .{ code, @intFromEnum(result.status) });
        inline for (@typeInfo(IamGetPolicyError).error_set.?) |entry| {
            if (std.mem.eql(u8, entry.name, code)) return @field(IamGetPolicyError, entry.name);
        }
        return aws_errors.fromCode(code) orelse aws_errors.fromStatus(result.status);
    }

    return parseResponse(client.allocator, resp_body);
}

fn encodeArn(allocator: Allocator, arn: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    for (arn) |c| {
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

fn parseResponse(allocator: Allocator, body: []const u8) !GetPolicyResult {
    const policy_block = try xml.extractTagContent(allocator, body, "Policy");
    defer allocator.free(policy_block);
    return policies_mod.parseMember(allocator, policy_block);
}

// ============================================================================
// Tests
// ============================================================================

test "parseResponse basic policy" {
    const body =
        \\<GetPolicyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        \\  <GetPolicyResult>
        \\    <Policy>
        \\      <PolicyName>my-policy</PolicyName>
        \\      <PolicyId>ANPAI3UMHF7RYEXAMPLE</PolicyId>
        \\      <Arn>arn:aws:iam::123456789012:policy/my-policy</Arn>
        \\      <Path>/</Path>
        \\      <DefaultVersionId>v2</DefaultVersionId>
        \\      <AttachmentCount>1</AttachmentCount>
        \\      <PermissionsBoundaryUsageCount>0</PermissionsBoundaryUsageCount>
        \\      <IsAttachable>true</IsAttachable>
        \\      <Description>A test policy</Description>
        \\      <CreateDate>2013-04-18T05:01:58Z</CreateDate>
        \\      <UpdateDate>2021-06-15T12:00:00Z</UpdateDate>
        \\    </Policy>
        \\  </GetPolicyResult>
        \\</GetPolicyResponse>
    ;
    const result = try parseResponse(std.testing.allocator, body);
    defer result.deinit();

    try std.testing.expectEqualStrings("my-policy", result.policy_name);
    try std.testing.expectEqualStrings("arn:aws:iam::123456789012:policy/my-policy", result.arn);
    try std.testing.expectEqualStrings("v2", result.default_version_id);
    try std.testing.expectEqual(@as(u32, 1), result.attachment_count);
    try std.testing.expect(result.is_attachable);
    try std.testing.expectEqualStrings("A test policy", result.description);
    try std.testing.expectEqualStrings("2021-06-15T12:00:00Z", result.update_date);
}

test "encodeArn" {
    const encoded = try encodeArn(std.testing.allocator, "arn:aws:iam::123456789012:policy/my-policy");
    defer std.testing.allocator.free(encoded);
    try std.testing.expectEqualStrings("arn%3Aaws%3Aiam%3A%3A123456789012%3Apolicy/my-policy", encoded);
}
