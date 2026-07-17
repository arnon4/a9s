const std = @import("std");
const Allocator = std.mem.Allocator;

const Credentials = @import("../../credentials/fetcher.zig").Credentials;

const listFunctionsMod = @import("list/functions.zig");
const listFunctionsImpl = listFunctionsMod.listFunctions;

pub const ListFunctionsOptions = listFunctionsMod.Options;
pub const ListFunctionsResult = listFunctionsMod.Result;
pub const LambdaFunction = listFunctionsMod.Function;

const getFunctionConfigurationMod = @import("get/function_configuration.zig");
const getFunctionConfigurationImpl = getFunctionConfigurationMod.getFunctionConfiguration;

pub const GetFunctionConfigurationOptions = getFunctionConfigurationMod.Options;
pub const FunctionConfiguration = getFunctionConfigurationMod.FunctionConfiguration;
pub const FunctionConfigurationLayer = getFunctionConfigurationMod.Layer;
pub const FunctionEnvironment = getFunctionConfigurationMod.Environment;
pub const FunctionLoggingConfig = getFunctionConfigurationMod.LoggingConfig;
pub const FunctionVpcConfig = getFunctionConfigurationMod.VpcConfig;
pub const FunctionImageConfig = getFunctionConfigurationMod.ImageConfig;
pub const FunctionSnapStart = getFunctionConfigurationMod.SnapStart;

const getFunctionMod = @import("get/function.zig");
const getFunctionImpl = getFunctionMod.getFunction;

pub const GetFunctionOptions = getFunctionMod.Options;
pub const GetFunctionResult = getFunctionMod.GetFunctionResult;
pub const FunctionCodeLocation = getFunctionMod.FunctionCodeLocation;

pub const ClientOptions = struct {
    region: []const u8 = "us-east-1",
    io: std.Io,
    credentials: Credentials,
    /// Override the Lambda endpoint (e.g. for LocalStack).
    endpoint_url: ?[]const u8 = null,
};

pub const Client = struct {
    allocator: Allocator,
    io: std.Io,
    region: []const u8,
    credentials: Credentials,
    /// Owned. Base URL, no trailing slash.
    endpoint: []const u8,

    pub fn init(allocator: Allocator, options: ClientOptions) !Client {
        const endpoint = if (options.endpoint_url) |ep|
            try allocator.dupe(u8, ep)
        else
            try std.fmt.allocPrint(allocator, "https://lambda.{s}.amazonaws.com", .{options.region});

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

    /// List Lambda functions. Caller owns the result and must call deinit.
    pub fn listFunctions(
        self: *Client,
        options: ListFunctionsOptions,
    ) !ListFunctionsResult {
        return listFunctionsImpl(self, options);
    }

    /// Get detailed configuration for a single function. Caller owns the result and must call deinit.
    pub fn getFunctionConfiguration(
        self: *Client,
        options: GetFunctionConfigurationOptions,
    ) !FunctionConfiguration {
        return getFunctionConfigurationImpl(self, options);
    }

    /// Get function metadata including presigned code download URL. Caller owns the result and must call deinit.
    pub fn getFunction(
        self: *Client,
        options: GetFunctionOptions,
    ) !GetFunctionResult {
        return getFunctionImpl(self, options);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "Client init default endpoint" {
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
    try std.testing.expectEqualStrings("https://lambda.eu-west-1.amazonaws.com", c.endpoint);
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
