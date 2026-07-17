const std = @import("std");
const Allocator = std.mem.Allocator;

const Credentials = @import("../../credentials/fetcher.zig").Credentials;
const xml = @import("../../utils/xml.zig");
const time = @import("../../utils/time.zig");

pub fn parseAssumeRoleResponse(allocator: Allocator, role_arn: []const u8, body: []const u8) !Credentials {
    const access_key_id = try xml.extractTagContent(allocator, body, "AccessKeyId");
    errdefer allocator.free(access_key_id);
    const secret_access_key = try xml.extractTagContent(allocator, body, "SecretAccessKey");
    errdefer allocator.free(secret_access_key);
    const session_token = try xml.extractTagContent(allocator, body, "SessionToken");
    errdefer allocator.free(session_token);
    const expiration_str = try xml.extractTagContent(allocator, body, "Expiration");
    defer allocator.free(expiration_str);

    const expiration = time.parseIso8601ToTimestamp(expiration_str) orelse {
        std.log.err("STS: invalid expiration timestamp: {s}", .{expiration_str});
        return error.InvalidExpiration;
    };
    return .{
        .access_key_id = access_key_id,
        .secret_access_key = secret_access_key,
        .session_token = session_token,
        .expiration = expiration,
        .source = role_arn,
    };
}
