const std = @import("std");
const Allocator = std.mem.Allocator;

const sigv4 = @import("../../../sig/sigv4.zig");
const xml = @import("../../../utils/xml.zig");
const aws_errors = @import("../../aws_errors.zig");

pub const IamGetRoleError = error{
    NoSuchEntityException,
    ServiceFailureException,
};

pub const Options = struct {
    role_name: []const u8,
};

pub const GetRoleResult = struct {
    allocator: Allocator,
    role_name: []u8,
    role_id: []u8,
    arn: []u8,
    path: []u8,
    create_date: []u8,
    description: []u8,
    max_session_duration: u32,
    assume_role_policy_document: []u8,
    last_used_date: ?[]u8,
    last_used_region: ?[]u8,

    pub fn deinit(self: GetRoleResult) void {
        self.allocator.free(self.role_name);
        self.allocator.free(self.role_id);
        self.allocator.free(self.arn);
        self.allocator.free(self.path);
        self.allocator.free(self.create_date);
        self.allocator.free(self.description);
        self.allocator.free(self.assume_role_policy_document);
        if (self.last_used_date) |d| self.allocator.free(d);
        if (self.last_used_region) |r| self.allocator.free(r);
    }
};

pub fn getRole(client: anytype, options: Options) !GetRoleResult {
    const encoded_name = try encodeName(client.allocator, options.role_name);
    defer client.allocator.free(encoded_name);

    const body = try std.fmt.allocPrint(
        client.allocator,
        "Action=GetRole&Version=2010-05-08&RoleName={s}",
        .{encoded_name},
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
            std.log.err("IAM GetRole error: status {d}", .{@intFromEnum(result.status)});
            return aws_errors.fromStatus(result.status);
        };
        defer client.allocator.free(code);
        std.log.err("IAM GetRole error: {s} (status {d})", .{ code, @intFromEnum(result.status) });
        inline for (@typeInfo(IamGetRoleError).error_set.?) |entry| {
            if (std.mem.eql(u8, entry.name, code)) return @field(IamGetRoleError, entry.name);
        }
        return aws_errors.fromCode(code) orelse aws_errors.fromStatus(result.status);
    }

    return parseResponse(client.allocator, resp_body);
}

/// Extract a human-readable comma-separated list of principals from a decoded
/// trust policy JSON document (the AssumeRolePolicyDocument value).
pub fn extractTrustedEntities(allocator: Allocator, policy_json: []const u8) ![]u8 {
    if (policy_json.len == 0) return allocator.dupe(u8, "");

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, policy_json, .{}) catch
        return allocator.dupe(u8, "");
    defer parsed.deinit();

    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);

    const root = switch (parsed.value) {
        .object => |o| o,
        else => return allocator.dupe(u8, ""),
    };

    const stmts = switch (root.get("Statement") orelse return allocator.dupe(u8, "")) {
        .array => |a| a,
        else => return allocator.dupe(u8, ""),
    };

    for (stmts.items) |stmt| {
        const stmt_obj = switch (stmt) {
            .object => |o| o,
            else => continue,
        };
        const principal = stmt_obj.get("Principal") orelse continue;
        switch (principal) {
            .string => |s| {
                if (result.items.len > 0) try result.appendSlice(allocator, ", ");
                try result.appendSlice(allocator, s);
            },
            .object => |p| {
                var it = p.iterator();
                while (it.next()) |kv| {
                    try appendPrincipalValues(allocator, &result, kv.value_ptr.*);
                }
            },
            else => {},
        }
    }

    if (result.items.len == 0) return allocator.dupe(u8, "");
    return result.toOwnedSlice(allocator);
}

fn appendPrincipalValues(allocator: Allocator, result: *std.ArrayList(u8), val: std.json.Value) !void {
    switch (val) {
        .string => |s| {
            if (result.items.len > 0) try result.appendSlice(allocator, ", ");
            try result.appendSlice(allocator, s);
        },
        .array => |arr| {
            for (arr.items) |item| {
                switch (item) {
                    .string => |s| {
                        if (result.items.len > 0) try result.appendSlice(allocator, ", ");
                        try result.appendSlice(allocator, s);
                    },
                    else => {},
                }
            }
        },
        else => {},
    }
}

fn encodeName(allocator: Allocator, name: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    for (name) |c| {
        if (std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.') {
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

fn parseResponse(allocator: Allocator, body: []const u8) !GetRoleResult {
    const role_name = try xmlStr(allocator, body, "RoleName");
    errdefer allocator.free(role_name);
    const role_id = try xmlStr(allocator, body, "RoleId");
    errdefer allocator.free(role_id);
    const arn = try xmlStr(allocator, body, "Arn");
    errdefer allocator.free(arn);
    const path = try xmlStr(allocator, body, "Path");
    errdefer allocator.free(path);
    const create_date = try xmlStr(allocator, body, "CreateDate");
    errdefer allocator.free(create_date);
    const description = try xmlStr(allocator, body, "Description");
    errdefer allocator.free(description);

    const max_session_duration: u32 = blk: {
        const s = xml.extractTagContent(allocator, body, "MaxSessionDuration") catch break :blk 0;
        defer allocator.free(s);
        break :blk std.fmt.parseInt(u32, s, 10) catch 0;
    };

    const policy_doc: []u8 = blk: {
        const encoded = try xmlStr(allocator, body, "AssumeRolePolicyDocument");
        defer allocator.free(encoded);
        break :blk try urlDecode(allocator, encoded);
    };
    errdefer allocator.free(policy_doc);

    // RoleLastUsed is absent when the role has never been used.
    const last_used_block = xml.extractTagContent(allocator, body, "RoleLastUsed") catch null;
    defer if (last_used_block) |b| allocator.free(b);

    const last_used_date: ?[]u8 = if (last_used_block) |block|
        xml.extractTagContent(allocator, block, "LastUsedDate") catch null
    else
        null;
    errdefer if (last_used_date) |d| allocator.free(d);

    const last_used_region: ?[]u8 = if (last_used_block) |block|
        xml.extractTagContent(allocator, block, "Region") catch null
    else
        null;
    errdefer if (last_used_region) |r| allocator.free(r);

    return .{
        .allocator = allocator,
        .role_name = role_name,
        .role_id = role_id,
        .arn = arn,
        .path = path,
        .create_date = create_date,
        .description = description,
        .max_session_duration = max_session_duration,
        .assume_role_policy_document = policy_doc,
        .last_used_date = last_used_date,
        .last_used_region = last_used_region,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "parseResponse basic role" {
    const body =
        \\<GetRoleResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        \\  <GetRoleResult>
        \\    <Role>
        \\      <RoleName>my-role</RoleName>
        \\      <RoleId>AROAI3UMHF7RYEXAMPLE</RoleId>
        \\      <Arn>arn:aws:iam::123456789012:role/my-role</Arn>
        \\      <Path>/</Path>
        \\      <CreateDate>2013-04-18T05:01:58Z</CreateDate>
        \\      <Description>A test role</Description>
        \\      <MaxSessionDuration>3600</MaxSessionDuration>
        \\      <AssumeRolePolicyDocument>%7B%22Version%22%3A%222012-10-17%22%7D</AssumeRolePolicyDocument>
        \\      <RoleLastUsed>
        \\        <LastUsedDate>2024-11-30T12:00:00Z</LastUsedDate>
        \\        <Region>us-east-1</Region>
        \\      </RoleLastUsed>
        \\    </Role>
        \\  </GetRoleResult>
        \\</GetRoleResponse>
    ;
    const result = try parseResponse(std.testing.allocator, body);
    defer result.deinit();

    try std.testing.expectEqualStrings("my-role", result.role_name);
    try std.testing.expectEqualStrings("arn:aws:iam::123456789012:role/my-role", result.arn);
    try std.testing.expectEqualStrings("/", result.path);
    try std.testing.expectEqualStrings("A test role", result.description);
    try std.testing.expectEqual(@as(u32, 3600), result.max_session_duration);
    try std.testing.expectEqualStrings("{\"Version\":\"2012-10-17\"}", result.assume_role_policy_document);
    try std.testing.expect(result.last_used_date != null);
    try std.testing.expectEqualStrings("2024-11-30T12:00:00Z", result.last_used_date.?);
    try std.testing.expectEqualStrings("us-east-1", result.last_used_region.?);
}

test "parseResponse never used role" {
    const body =
        \\<GetRoleResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        \\  <GetRoleResult>
        \\    <Role>
        \\      <RoleName>unused-role</RoleName>
        \\      <RoleId>ROLEID</RoleId>
        \\      <Arn>arn:aws:iam::123:role/unused-role</Arn>
        \\      <Path>/</Path>
        \\      <CreateDate>2020-01-01T00:00:00Z</CreateDate>
        \\      <Description></Description>
        \\      <MaxSessionDuration>43200</MaxSessionDuration>
        \\      <AssumeRolePolicyDocument>%7B%7D</AssumeRolePolicyDocument>
        \\    </Role>
        \\  </GetRoleResult>
        \\</GetRoleResponse>
    ;
    const result = try parseResponse(std.testing.allocator, body);
    defer result.deinit();

    try std.testing.expectEqualStrings("unused-role", result.role_name);
    try std.testing.expectEqual(@as(u32, 43200), result.max_session_duration);
    try std.testing.expect(result.last_used_date == null);
    try std.testing.expect(result.last_used_region == null);
}

test "extractTrustedEntities service principal" {
    const policy =
        \\{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}
    ;
    const result = try extractTrustedEntities(std.testing.allocator, policy);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("lambda.amazonaws.com", result);
}

test "extractTrustedEntities multiple principals" {
    const policy =
        \\{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":["lambda.amazonaws.com","edgelambda.amazonaws.com"]},"Action":"sts:AssumeRole"}]}
    ;
    const result = try extractTrustedEntities(std.testing.allocator, policy);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("lambda.amazonaws.com, edgelambda.amazonaws.com", result);
}

test "extractTrustedEntities aws account" {
    const policy =
        \\{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"sts:AssumeRole"}]}
    ;
    const result = try extractTrustedEntities(std.testing.allocator, policy);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("arn:aws:iam::123456789012:root", result);
}

test "extractTrustedEntities star" {
    const policy =
        \\{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}]}
    ;
    const result = try extractTrustedEntities(std.testing.allocator, policy);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("*", result);
}

test "urlDecode basic" {
    const decoded = try urlDecode(std.testing.allocator, "%7B%22key%22%3A%22value%22%7D");
    defer std.testing.allocator.free(decoded);
    try std.testing.expectEqualStrings("{\"key\":\"value\"}", decoded);
}
