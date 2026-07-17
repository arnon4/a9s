const std = @import("std");
const Allocator = std.mem.Allocator;

const Credentials = @import("../../credentials/fetcher.zig").Credentials;

const listSecretsMod = @import("list/secrets.zig");
const listSecretsImpl = listSecretsMod.listSecrets;

pub const ListSecretsOptions = listSecretsMod.Options;
pub const ListSecretsResult = listSecretsMod.Result;
pub const SecretEntry = listSecretsMod.SecretEntry;
pub const SecretTag = listSecretsMod.Tag;
pub const SecretFilter = listSecretsMod.Filter;

const getSecretValueMod = @import("get/secret_value.zig");
const getSecretValueImpl = getSecretValueMod.getSecretValue;

pub const GetSecretValueOptions = getSecretValueMod.Options;
pub const GetSecretValueResult = getSecretValueMod.Result;

const getResourcePolicyMod = @import("get/resource_policy.zig");
const getResourcePolicyImpl = getResourcePolicyMod.getResourcePolicy;

pub const GetResourcePolicyOptions = getResourcePolicyMod.Options;
pub const GetResourcePolicyResult = getResourcePolicyMod.Result;

pub const ClientOptions = struct {
    region: []const u8 = "us-east-1",
    io: std.Io,
    credentials: Credentials,
    endpoint_url: ?[]const u8 = null,
};

pub const Client = struct {
    allocator: Allocator,
    io: std.Io,
    region: []const u8,
    credentials: Credentials,
    endpoint: []const u8,

    pub fn init(allocator: Allocator, options: ClientOptions) !Client {
        const endpoint = if (options.endpoint_url) |ep|
            try allocator.dupe(u8, ep)
        else
            try std.fmt.allocPrint(allocator, "https://secretsmanager.{s}.amazonaws.com", .{options.region});

        return .{
            .allocator = allocator,
            .io = options.io,
            .region = options.region,
            .credentials = options.credentials,
            .endpoint = endpoint,
        };
    }

    pub fn deinit(self: *Client) void {
        self.allocator.free(self.endpoint);
    }

    pub fn listSecrets(self: *Client, options: ListSecretsOptions) !ListSecretsResult {
        return listSecretsImpl(self, options);
    }

    pub fn getSecretValue(self: *Client, options: GetSecretValueOptions) !GetSecretValueResult {
        return getSecretValueImpl(self, options);
    }

    pub fn getResourcePolicy(self: *Client, options: GetResourcePolicyOptions) !GetResourcePolicyResult {
        return getResourcePolicyImpl(self, options);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "Client init regional endpoint" {
    const allocator = std.testing.allocator;
    var c = try Client.init(allocator, .{
        .region = "eu-west-1",
        .io = std.testing.io,
        .credentials = .{
            .access_key_id = "AKID",
            .secret_access_key = "SECRET",
            .session_token = null,
            .source = "test",
        },
    });
    defer c.deinit();
    try std.testing.expectEqualStrings("https://secretsmanager.eu-west-1.amazonaws.com", c.endpoint);
}

test "Client init custom endpoint" {
    const allocator = std.testing.allocator;
    var c = try Client.init(allocator, .{
        .region = "us-east-1",
        .io = std.testing.io,
        .credentials = .{
            .access_key_id = "AKID",
            .secret_access_key = "SECRET",
            .session_token = null,
            .source = "test",
        },
        .endpoint_url = "http://localhost:4566",
    });
    defer c.deinit();
    try std.testing.expectEqualStrings("http://localhost:4566", c.endpoint);
}
