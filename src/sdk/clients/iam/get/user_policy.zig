const std = @import("std");
const Allocator = std.mem.Allocator;

const sigv4 = @import("../../../sig/sigv4.zig");
const xml = @import("../../../utils/xml.zig");
const aws_errors = @import("../../aws_errors.zig");

pub const IamGetUserPolicyError = error{
    NoSuchEntityException,
    ServiceFailureException,
};

pub const Options = struct {
    user_name: []const u8,
    policy_name: []const u8,
};

pub const GetUserPolicyResult = struct {
    allocator: Allocator,
    user_name: []u8,
    policy_name: []u8,
    policy_document: []u8,

    pub fn deinit(self: GetUserPolicyResult) void {
        self.allocator.free(self.user_name);
        self.allocator.free(self.policy_name);
        self.allocator.free(self.policy_document);
    }
};

pub fn getUserPolicy(client: anytype, options: Options) !GetUserPolicyResult {
    const body = try buildBody(client.allocator, options.user_name, options.policy_name);
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
            std.log.err("IAM GetUserPolicy error: status {d}", .{@intFromEnum(result.status)});
            return aws_errors.fromStatus(result.status);
        };
        defer client.allocator.free(code);
        std.log.err("IAM GetUserPolicy error: {s} (status {d})", .{ code, @intFromEnum(result.status) });
        inline for (@typeInfo(IamGetUserPolicyError).error_set.?) |entry| {
            if (std.mem.eql(u8, entry.name, code)) return @field(IamGetUserPolicyError, entry.name);
        }
        return aws_errors.fromCode(code) orelse aws_errors.fromStatus(result.status);
    }

    return parseResponse(client.allocator, resp_body);
}

fn buildBody(allocator: Allocator, user_name: []const u8, policy_name: []const u8) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);

    try body.appendSlice(allocator, "Action=GetUserPolicy&Version=2010-05-08&UserName=");
    const user_encoded = try uriEncode(allocator, user_name);
    defer allocator.free(user_encoded);
    try body.appendSlice(allocator, user_encoded);

    try body.appendSlice(allocator, "&PolicyName=");
    const policy_encoded = try uriEncode(allocator, policy_name);
    defer allocator.free(policy_encoded);
    try body.appendSlice(allocator, policy_encoded);

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

fn parseResponse(allocator: Allocator, body: []const u8) !GetUserPolicyResult {
    const user_name = try xmlStr(allocator, body, "UserName");
    errdefer allocator.free(user_name);
    const policy_name = try xmlStr(allocator, body, "PolicyName");
    errdefer allocator.free(policy_name);

    const policy_document: []u8 = blk: {
        const encoded = try xmlStr(allocator, body, "PolicyDocument");
        defer allocator.free(encoded);
        break :blk try urlDecode(allocator, encoded);
    };
    errdefer allocator.free(policy_document);

    return .{
        .allocator = allocator,
        .user_name = user_name,
        .policy_name = policy_name,
        .policy_document = policy_document,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "parseResponse basic inline policy" {
    const body =
        \\<GetUserPolicyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        \\  <GetUserPolicyResult>
        \\    <UserName>alice</UserName>
        \\    <PolicyName>MyInlinePolicy</PolicyName>
        \\    <PolicyDocument>%7B%22Version%22%3A%222012-10-17%22%7D</PolicyDocument>
        \\  </GetUserPolicyResult>
        \\</GetUserPolicyResponse>
    ;
    const result = try parseResponse(std.testing.allocator, body);
    defer result.deinit();

    try std.testing.expectEqualStrings("alice", result.user_name);
    try std.testing.expectEqualStrings("MyInlinePolicy", result.policy_name);
    try std.testing.expectEqualStrings("{\"Version\":\"2012-10-17\"}", result.policy_document);
}

test "buildBody encodes user and policy name" {
    const body = try buildBody(std.testing.allocator, "alice", "My Policy");
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("Action=GetUserPolicy&Version=2010-05-08&UserName=alice&PolicyName=My%20Policy", body);
}
