const std = @import("std");
const Allocator = std.mem.Allocator;

const Credentials = @import("../../credentials/fetcher.zig").Credentials;

const describeVpcsMod = @import("describe/vpcs.zig");
const describeVpcsImpl = describeVpcsMod.describeVpcs;

pub const DescribeVpcsOptions = describeVpcsMod.Options;
pub const DescribeVpcsParams = describeVpcsMod.Params;
pub const DescribeVpcsResult = describeVpcsMod.Result;
pub const Filter = describeVpcsMod.Filter;
pub const Vpc = describeVpcsMod.Vpc;
pub const VpcTag = describeVpcsMod.Tag;
pub const VpcCidrAssociation = describeVpcsMod.CidrAssociation;

const describeVpcAttributeMod = @import("describe/vpc_attribute.zig");
const describeVpcAttributeImpl = describeVpcAttributeMod.describeVpcAttribute;

pub const DescribeVpcAttributeOptions = describeVpcAttributeMod.Options;
pub const DescribeVpcAttributeParams = describeVpcAttributeMod.Params;
pub const DescribeVpcAttributeResult = describeVpcAttributeMod.Result;
pub const VpcAttribute = describeVpcAttributeMod.Attribute;

pub const ClientOptions = struct {
    region: []const u8 = "us-east-1",
    io: std.Io,
    credentials: Credentials,
    /// Override the EC2 endpoint (e.g. for LocalStack).
    endpoint_url: ?[]const u8 = null,
};

pub const Client = struct {
    allocator: Allocator,
    io: std.Io,
    region: []const u8,
    credentials: Credentials,
    /// Owned.
    endpoint: []const u8,

    pub fn init(allocator: Allocator, options: ClientOptions) !Client {
        const endpoint = if (options.endpoint_url) |ep|
            try allocator.dupe(u8, ep)
        else
            try allocator.print("https://ec2.{s}.amazonaws.com", .{options.region});

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

    /// Describe VPCs. Caller owns the result and must call deinit.
    pub fn describeVpcs(self: *Client, options: DescribeVpcsOptions) !DescribeVpcsResult {
        return describeVpcsImpl(self, options);
    }

    /// Describe one attribute of a VPC. Caller owns the result and must call deinit.
    pub fn describeVpcAttribute(self: *Client, options: DescribeVpcAttributeOptions) !DescribeVpcAttributeResult {
        return describeVpcAttributeImpl(self, options);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "Client init regional endpoint" {
    var c = try Client.init(std.testing.allocator, .{
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
    try std.testing.expectEqualStrings("https://ec2.eu-west-1.amazonaws.com", c.endpoint);
}

test "Client init custom endpoint" {
    var c = try Client.init(std.testing.allocator, .{
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

test {
    _ = @import("describe/vpcs.zig");
    _ = @import("describe/vpc_attribute.zig");
    _ = @import("request.zig");
}
