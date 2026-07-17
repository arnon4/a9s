const std = @import("std");
const Allocator = std.mem.Allocator;

const xml = @import("../../utils/xml.zig");
const Credentials = @import("../../credentials/fetcher.zig").Credentials;
const aws_errors = @import("../aws_errors.zig");

/// STS-specific error codes. Names match AWS error code strings exactly.
pub const StsSpecificError = error{
    ExpiredAuthenticationToken,
    IDPCommunicationError,
    IDPRejectedClaim,
    InvalidAuthorizationMessageException,
    InvalidIdentityToken,
    MalformedPolicyDocument,
    PackedPolicyTooLarge,
    RegionDisabledException,
};
const assumeRoleImpl = @import("assume_role.zig").assumeRole;
const assumeRoleWithWebIdentityImpl = @import("assume_role_with_web_identity.zig").assumeRoleWithWebIdentity;
const getCallerIdentityImpl = @import("get_caller_identity.zig").getCallerIdentity;

pub const AssumeRoleParams = @import("assume_role.zig").AssumeRoleParams;
pub const AssumeRoleWithWebIdentityParams = @import("assume_role_with_web_identity.zig").AssumeRoleWithWebIdentityParams;
pub const CallerIdentity = @import("get_caller_identity.zig").CallerIdentity;

pub const ClientOptions = struct {
    region: []const u8 = "us-east-1",
    io: std.Io,
    source_creds: ?Credentials = null,
    /// Override the STS endpoint (e.g. for local testing). If null, the
    /// regional endpoint is derived from `region`.
    endpoint_url: ?[]const u8 = null,
};

/// Parsed STS error response. Owned by the Client; valid until the next request.
pub const StsError = struct {
    /// The STS error code string, e.g. "AccessDenied".
    code: []const u8,
    /// Human-readable error message from the response body.
    message: []const u8,

    fn deinit(self: StsError, allocator: Allocator) void {
        allocator.free(self.code);
        allocator.free(self.message);
    }
};

pub const Client = struct {
    allocator: Allocator,
    io: std.Io,
    region: []const u8,
    source_creds: ?Credentials,
    /// Owned. Freed in deinit.
    url: []const u8,
    /// Set when a request fails with an STS error response. Cleared at the
    /// start of every request. Contains the AWS error code and human-readable message.
    last_error: ?StsError = null,
    /// HTTP status code of the last failed response. 0 when no failure occurred.
    last_status: u16 = 0,

    pub fn init(allocator: Allocator, options: ClientOptions) !Client {
        const url = if (options.endpoint_url) |ep|
            try allocator.dupe(u8, ep)
        else
            try std.fmt.allocPrint(allocator, "https://sts.{s}.amazonaws.com/", .{options.region});

        return .{
            .allocator = allocator,
            .io = options.io,
            .region = options.region,
            .source_creds = options.source_creds,
            .url = url,
        };
    }

    pub fn deinit(self: *Client) void {
        self.allocator.free(self.url);
        if (self.last_error) |e| e.deinit(self.allocator);
    }

    pub fn clearLastError(self: *Client) void {
        if (self.last_error) |e| e.deinit(self.allocator);
        self.last_error = null;
    }

    /// Parse body into last_error, then return the matching typed Zig error.
    pub fn classifyError(self: *Client, status: std.http.Status, body: []const u8) anyerror {
        self.setErrorFromBody(status, body);
        const code = if (self.last_error) |e| e.code else {
            std.log.err("STS error: status {d}, no XML error code in body", .{@intFromEnum(status)});
            return aws_errors.fromStatus(status);
        };
        std.log.err("STS error: {s} (status {d})", .{ code, @intFromEnum(status) });
        inline for (@typeInfo(StsSpecificError).error_set.?) |entry| {
            if (std.mem.eql(u8, entry.name, code)) return @field(StsSpecificError, entry.name);
        }
        return aws_errors.fromCode(code) orelse aws_errors.fromStatus(status);
    }

    pub fn setErrorFromBody(self: *Client, status: std.http.Status, body: []const u8) void {
        self.last_status = @intFromEnum(status);
        const code = xml.extractTagContent(self.allocator, body, "Code") catch {
            // Fall back to raw body so callers can always see what STS returned.
            self.last_error = .{
                .code = self.allocator.dupe(u8, "(no xml)") catch return,
                .message = self.allocator.dupe(u8, body) catch return,
            };
            return;
        };
        const message = xml.extractTagContent(self.allocator, body, "Message") catch {
            self.allocator.free(code);
            return;
        };
        self.last_error = .{ .code = code, .message = message };
    }

    /// Call STS AssumeRole using the client's source_creds and return temporary credentials.
    pub fn assumeRole(self: *Client, params: AssumeRoleParams) !Credentials {
        return assumeRoleImpl(self, params);
    }

    /// Call STS AssumeRoleWithWebIdentity and return temporary credentials.
    /// Does not require source_creds — the web identity token is the proof.
    pub fn assumeRoleWithWebIdentity(self: *Client, params: AssumeRoleWithWebIdentityParams) !Credentials {
        return assumeRoleWithWebIdentityImpl(self, params);
    }

    /// Call STS GetCallerIdentity and return the account ID, user ID, and ARN.
    pub fn getCallerIdentity(self: *Client) !CallerIdentity {
        return getCallerIdentityImpl(self);
    }
};

// ============================================================================
// Tests
// ============================================================================

test {
    _ = @import("assume_role.zig");
}

test "Client init constructs regional url" {
    const allocator = std.testing.allocator;
    var c = try Client.init(allocator, .{ .region = "eu-west-1", .io = std.testing.io });
    defer c.deinit();
    try std.testing.expectEqualStrings("https://sts.eu-west-1.amazonaws.com/", c.url);
}

test "Client init custom endpoint" {
    const allocator = std.testing.allocator;
    var c = try Client.init(allocator, .{ .endpoint_url = "http://localhost:4566/", .io = std.testing.io });
    defer c.deinit();
    try std.testing.expectEqualStrings("http://localhost:4566/", c.url);
}
