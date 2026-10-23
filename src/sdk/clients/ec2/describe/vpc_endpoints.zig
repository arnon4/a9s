const std = @import("std");
const Allocator = std.mem.Allocator;

const xml = @import("../../../utils/xml.zig");
const req = @import("../request.zig");
const vpcs = @import("vpcs.zig");

pub const Filter = vpcs.Filter;

pub const Ec2DescribeVpcEndpointsError = error{
    @"InvalidVpcEndpointId.NotFound",
    InvalidParameterValue,
    InvalidParameterCombination,
    UnauthorizedOperation,
    AuthFailure,
    RequestLimitExceeded,
};

pub const Params = struct {
    vpc_endpoint_ids: []const []const u8 = &.{},
    filters: []const Filter = &.{},
    /// 5..1000
    max_results: ?u32 = null,
    next_token: ?[]const u8 = null,
};

pub const Options = struct {
    params: Params = .{},
};

pub const VpcEndpoint = struct {
    allocator: Allocator,
    /// Endpoint ID.
    id: []u8,
    /// pendingAcceptance | pending | available | deleting | deleted | rejected | failed | expired.
    state: []u8,
    vpc_id: []u8,
    /// e.g. com.amazonaws.us-east-1.s3
    service_name: []u8,
    /// Interface | Gateway | GatewayLoadBalancer | Resource | ServiceNetwork.
    endpoint_type: []u8,
    /// Value of the `Name` tag, or empty.
    name: []u8,

    pub fn deinit(self: VpcEndpoint) void {
        const a = self.allocator;
        a.free(self.id);
        a.free(self.state);
        a.free(self.vpc_id);
        a.free(self.service_name);
        a.free(self.endpoint_type);
        a.free(self.name);
    }
};

pub const Result = struct {
    allocator: Allocator,
    vpc_endpoints: []VpcEndpoint,
    next_token: ?[]u8,

    pub fn deinit(self: Result) void {
        for (self.vpc_endpoints) |x| x.deinit();
        self.allocator.free(self.vpc_endpoints);
        if (self.next_token) |t| self.allocator.free(t);
    }
};

pub fn describeVpcEndpoints(client: anytype, options: Options) !Result {
    const body = try buildBody(client.allocator, options.params);
    defer client.allocator.free(body);

    const resp = try req.send(client, Ec2DescribeVpcEndpointsError, "DescribeVpcEndpoints", body);
    defer client.allocator.free(resp);

    return parseResponse(client.allocator, resp);
}

fn buildBody(allocator: Allocator, params: Params) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);

    try body.appendSlice(allocator, "Action=DescribeVpcEndpoints&Version=" ++ req.api_version);

    for (params.vpc_endpoint_ids, 1..) |id, n| {
        const key = try allocator.print("VpcEndpointId.{d}", .{n});
        defer allocator.free(key);
        try req.appendParam(allocator, &body, key, id);
    }
    for (params.filters, 1..) |f, n| {
        const name_key = try allocator.print("Filter.{d}.Name", .{n});
        defer allocator.free(name_key);
        try req.appendParam(allocator, &body, name_key, f.name);
        for (f.values, 1..) |v, m| {
            const value_key = try allocator.print("Filter.{d}.Value.{d}", .{ n, m });
            defer allocator.free(value_key);
            try req.appendParam(allocator, &body, value_key, v);
        }
    }
    if (params.max_results) |m| try req.appendIntParam(allocator, &body, "MaxResults", m);
    if (params.next_token) |t| try req.appendParam(allocator, &body, "NextToken", t);

    return body.toOwnedSlice(allocator);
}

fn parseResponse(allocator: Allocator, body: []const u8) !Result {
    const root = xml.child(body, "DescribeVpcEndpointsResponse") orelse return error.InvalidResponse;

    var items: std.ArrayList(VpcEndpoint) = .empty;
    errdefer {
        for (items.items) |x| x.deinit();
        items.deinit(allocator);
    }

    if (xml.child(root, "vpcEndpointSet")) |set| {
        var it: xml.ChildIterator = .{ .src = set, .name = "item" };
        while (it.next()) |src| {
            const parsed = try parseItem(allocator, src);
            errdefer parsed.deinit();
            try items.append(allocator, parsed);
        }
    }

    const next_token: ?[]u8 = if (xml.child(root, "nextToken")) |t|
        if (t.len > 0) try xml.unescape(allocator, t) else null
    else
        null;
    errdefer if (next_token) |t| allocator.free(t);

    return .{
        .allocator = allocator,
        .vpc_endpoints = try items.toOwnedSlice(allocator),
        .next_token = next_token,
    };
}

fn parseItem(allocator: Allocator, src: []const u8) !VpcEndpoint {
    const id = try req.xmlStr(allocator, src, "vpcEndpointId");
    errdefer allocator.free(id);
    const state = try req.xmlStr(allocator, src, "state");
    errdefer allocator.free(state);
    const vpc_id = try req.xmlStr(allocator, src, "vpcId");
    errdefer allocator.free(vpc_id);
    const service_name = try req.xmlStr(allocator, src, "serviceName");
    errdefer allocator.free(service_name);
    const endpoint_type = try req.xmlStr(allocator, src, "vpcEndpointType");
    errdefer allocator.free(endpoint_type);
    const name = try vpcs.parseNameTag(allocator, src);
    errdefer allocator.free(name);

    return .{
        .allocator = allocator,
        .id = id,
        .state = state,
        .vpc_id = vpc_id,
        .service_name = service_name,
        .endpoint_type = endpoint_type,
        .name = name,
    };
}

// ============================================================================
// Tests
// ============================================================================

const sample =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<DescribeVpcEndpointsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
    \\  <requestId>req-1</requestId>
    \\  <vpcEndpointSet>
    \\    <item>
    \\      <vpcEndpointId>vpce-1</vpcEndpointId>
    \\      <vpcEndpointType>Gateway</vpcEndpointType>
    \\      <vpcId>vpc-1</vpcId>
    \\      <serviceName>com.amazonaws.us-east-1.s3</serviceName>
    \\      <state>available</state>
    \\      <tagSet><item><key>Name</key><value>s3</value></item></tagSet>
    \\    </item>
    \\    <item>
    \\      <vpcEndpointId>vpce-2</vpcEndpointId>
    \\      <state>failed</state>
    \\    </item>
    \\  </vpcEndpointSet>
    \\  <nextToken>TOKEN</nextToken>
    \\</DescribeVpcEndpointsResponse>
;

test "parseResponse vpc_endpoints" {
    const result = try parseResponse(std.testing.allocator, sample);
    defer result.deinit();

    const items = result.vpc_endpoints;
    try std.testing.expectEqual(@as(usize, 2), items.len);
    try std.testing.expectEqualStrings("vpce-1", items[0].id);
    try std.testing.expectEqualStrings("Gateway", items[0].endpoint_type);
    try std.testing.expectEqualStrings("vpc-1", items[0].vpc_id);
    try std.testing.expectEqualStrings("com.amazonaws.us-east-1.s3", items[0].service_name);
    try std.testing.expectEqualStrings("available", items[0].state);
    try std.testing.expectEqualStrings("s3", items[0].name);
    try std.testing.expectEqualStrings("failed", items[1].state);
    try std.testing.expectEqualStrings("", items[1].service_name);
    try std.testing.expectEqualStrings("TOKEN", result.next_token.?);
}

test "parseResponse empty set" {
    const result = try parseResponse(
        std.testing.allocator,
        "<DescribeVpcEndpointsResponse><requestId>r</requestId><vpcEndpointSet/></DescribeVpcEndpointsResponse>",
    );
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 0), result.vpc_endpoints.len);
    try std.testing.expect(result.next_token == null);
}

test "buildBody action only" {
    const body = try buildBody(std.testing.allocator, .{});
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("Action=DescribeVpcEndpoints&Version=2016-11-15", body);
}

test "buildBody ids and filters" {
    const body = try buildBody(std.testing.allocator, .{
        .vpc_endpoint_ids = &.{ "vpce-1", "x-2" },
        .filters = &.{.{ .name = "vpc-id", .values = &.{"vpc-1"} }},
        .max_results = 5,
        .next_token = "tok/en",
    });
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings(
        "Action=DescribeVpcEndpoints&Version=2016-11-15&VpcEndpointId.1=vpce-1&VpcEndpointId.2=x-2" ++
            "&Filter.1.Name=vpc-id&Filter.1.Value.1=vpc-1&MaxResults=5&NextToken=tok%2Fen",
        body,
    );
}
