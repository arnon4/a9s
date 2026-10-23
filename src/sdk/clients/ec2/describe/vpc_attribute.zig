const std = @import("std");
const Allocator = std.mem.Allocator;

const xml = @import("../../../utils/xml.zig");
const req = @import("../request.zig");

pub const Ec2DescribeVpcAttributeError = error{
    @"InvalidVpcID.NotFound",
    @"InvalidVpcID.Malformed",
    InvalidParameterValue,
    MissingParameter,
    UnauthorizedOperation,
    AuthFailure,
    RequestLimitExceeded,
};

pub const Attribute = enum {
    enable_dns_support,
    enable_dns_hostnames,
    enable_network_address_usage_metrics,

    /// Wire name, also the response element holding the value.
    pub fn apiName(self: Attribute) []const u8 {
        return switch (self) {
            .enable_dns_support => "enableDnsSupport",
            .enable_dns_hostnames => "enableDnsHostnames",
            .enable_network_address_usage_metrics => "enableNetworkAddressUsageMetrics",
        };
    }
};

pub const Params = struct {
    vpc_id: []const u8,
    attribute: Attribute,
};

pub const Options = struct {
    params: Params,
};

pub const Result = struct {
    allocator: Allocator,
    vpc_id: []u8,
    attribute: Attribute,
    value: bool,

    pub fn deinit(self: Result) void {
        self.allocator.free(self.vpc_id);
    }
};

pub fn describeVpcAttribute(client: anytype, options: Options) !Result {
    const body = try buildBody(client.allocator, options.params);
    defer client.allocator.free(body);

    const resp = try req.send(client, Ec2DescribeVpcAttributeError, "DescribeVpcAttribute", body);
    defer client.allocator.free(resp);

    return parseResponse(client.allocator, resp, options.params.attribute);
}

fn buildBody(allocator: Allocator, params: Params) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);

    try body.appendSlice(allocator, "Action=DescribeVpcAttribute&Version=" ++ req.api_version);
    try req.appendParam(allocator, &body, "VpcId", params.vpc_id);
    try req.appendParam(allocator, &body, "Attribute", params.attribute.apiName());

    return body.toOwnedSlice(allocator);
}

fn parseResponse(allocator: Allocator, body: []const u8, attribute: Attribute) !Result {
    const root = xml.child(body, "DescribeVpcAttributeResponse") orelse return error.InvalidResponse;
    const attr_block = xml.child(root, attribute.apiName()) orelse return error.InvalidResponse;

    const vpc_id = try req.xmlStr(allocator, root, "vpcId");
    return .{
        .allocator = allocator,
        .vpc_id = vpc_id,
        .attribute = attribute,
        .value = req.xmlBool(attr_block, "value"),
    };
}

// ============================================================================
// Tests
// ============================================================================

test "parseResponse dns support" {
    const body =
        \\<DescribeVpcAttributeResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
        \\  <requestId>r</requestId>
        \\  <vpcId>vpc-0abc</vpcId>
        \\  <enableDnsSupport><value>true</value></enableDnsSupport>
        \\</DescribeVpcAttributeResponse>
    ;
    const r = try parseResponse(std.testing.allocator, body, .enable_dns_support);
    defer r.deinit();
    try std.testing.expectEqualStrings("vpc-0abc", r.vpc_id);
    try std.testing.expect(r.value);
}

test "parseResponse dns hostnames false" {
    const body =
        \\<DescribeVpcAttributeResponse>
        \\  <vpcId>vpc-1</vpcId>
        \\  <enableDnsHostnames><value>false</value></enableDnsHostnames>
        \\</DescribeVpcAttributeResponse>
    ;
    const r = try parseResponse(std.testing.allocator, body, .enable_dns_hostnames);
    defer r.deinit();
    try std.testing.expect(!r.value);
}

test "parseResponse missing attribute" {
    try std.testing.expectError(
        error.InvalidResponse,
        parseResponse(std.testing.allocator, "<DescribeVpcAttributeResponse><vpcId>v</vpcId></DescribeVpcAttributeResponse>", .enable_dns_support),
    );
}

test "buildBody" {
    const body = try buildBody(std.testing.allocator, .{ .vpc_id = "vpc-1", .attribute = .enable_network_address_usage_metrics });
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings(
        "Action=DescribeVpcAttribute&Version=2016-11-15&VpcId=vpc-1&Attribute=enableNetworkAddressUsageMetrics",
        body,
    );
}
