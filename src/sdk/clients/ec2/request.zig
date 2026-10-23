const std = @import("std");
const Allocator = std.mem.Allocator;

const sigv4 = @import("../../sig/sigv4.zig");
const xml = @import("../../utils/xml.zig");
const uri = @import("../../utils/uri.zig");
const aws_errors = @import("../aws_errors.zig");

pub const api_version = "2016-11-15";

/// Append `&name=value` with the value percent-encoded.
pub fn appendParam(allocator: Allocator, body: *std.ArrayList(u8), name: []const u8, value: []const u8) !void {
    const encoded = try uri.encodeStandard(allocator, value);
    defer allocator.free(encoded);
    try body.append(allocator, '&');
    try body.appendSlice(allocator, name);
    try body.append(allocator, '=');
    try body.appendSlice(allocator, encoded);
}

/// Append `&name=value` with a decimal integer value.
pub fn appendIntParam(allocator: Allocator, body: *std.ArrayList(u8), name: []const u8, value: u32) !void {
    const s = try allocator.print("&{s}={d}", .{ name, value });
    defer allocator.free(s);
    try body.appendSlice(allocator, s);
}

/// Sign and POST an EC2 Query request. Returns the caller-owned response body.
/// Non-200 responses are mapped to a member of `OpError`, then to the common
/// AWS errors, then to a status-based fallback.
pub fn send(client: anytype, comptime OpError: type, comptime label: []const u8, body: []const u8) ![]u8 {
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
            .service = "ec2",
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
            std.log.err("EC2 " ++ label ++ " error: status {d}", .{@backingInt(result.status)});
            return aws_errors.fromStatus(result.status);
        };
        defer client.allocator.free(code);
        std.log.err("EC2 " ++ label ++ " error: {s} (status {d}): {s}", .{ code, @backingInt(result.status), resp_body });
        inline for (@typeInfo(OpError).error_set.error_names.?) |name| {
            if (std.mem.eql(u8, name, code)) return @field(OpError, name);
        }
        return aws_errors.fromCode(code) orelse aws_errors.fromStatus(result.status);
    }

    return client.allocator.dupe(u8, resp_body);
}

pub fn xmlStr(allocator: Allocator, src: []const u8, tag: []const u8) ![]u8 {
    return xml.unescape(allocator, xml.child(src, tag) orelse "");
}

pub fn xmlBool(src: []const u8, tag: []const u8) bool {
    const v = xml.child(src, tag) orelse return false;
    return std.mem.eql(u8, v, "true");
}

/// Unescaped text of `inner` inside the direct child `outer`, or an empty string.
pub fn xmlNested(allocator: Allocator, src: []const u8, outer: []const u8, inner: []const u8) ![]u8 {
    return xmlStr(allocator, xml.child(src, outer) orelse "", inner);
}

/// Unescaped text of `inner` in the first `<item>` of the set `set_tag`, or an empty string.
pub fn xmlFirstItemStr(allocator: Allocator, src: []const u8, set_tag: []const u8, inner: []const u8) ![]u8 {
    const set = xml.child(src, set_tag) orelse return allocator.dupe(u8, "");
    var it: xml.ChildIterator = .{ .src = set, .name = "item" };
    const item = it.next() orelse return allocator.dupe(u8, "");
    return xmlStr(allocator, item, inner);
}

test "xmlNested and xmlFirstItemStr" {
    const a = std.testing.allocator;
    const src = "<status><code>active</code></status><set><item><vpcId>vpc-1</vpcId></item><item><vpcId>vpc-2</vpcId></item></set><empty/>";
    const code = try xmlNested(a, src, "status", "code");
    defer a.free(code);
    try std.testing.expectEqualStrings("active", code);
    const first = try xmlFirstItemStr(a, src, "set", "vpcId");
    defer a.free(first);
    try std.testing.expectEqualStrings("vpc-1", first);
    const none = try xmlFirstItemStr(a, src, "empty", "vpcId");
    defer a.free(none);
    try std.testing.expectEqualStrings("", none);
}
