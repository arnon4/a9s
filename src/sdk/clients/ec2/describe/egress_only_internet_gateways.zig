const std = @import("std");
const Allocator = std.mem.Allocator;

const xml = @import("../../../utils/xml.zig");
const req = @import("../request.zig");
const vpcs = @import("vpcs.zig");

pub const Filter = vpcs.Filter;

pub const Ec2DescribeEgressOnlyInternetGatewaysError = error{
    @"InvalidGatewayID.NotFound",
    InvalidParameterValue,
    InvalidParameterCombination,
    UnauthorizedOperation,
    AuthFailure,
    RequestLimitExceeded,
};

pub const Params = struct {
    egress_only_internet_gateway_ids: []const []const u8 = &.{},
    filters: []const Filter = &.{},
    /// 5..255
    max_results: ?u32 = null,
    next_token: ?[]const u8 = null,
};

pub const Options = struct {
    params: Params = .{},
};

pub const EgressOnlyInternetGateway = struct {
    allocator: Allocator,
    /// Egress-only internet gateway ID.
    id: []u8,
    /// VPC of the first attachment, or empty.
    vpc_id: []u8,
    /// attaching | attached | detaching | detached.
    state: []u8,
    /// Value of the `Name` tag, or empty.
    name: []u8,

    pub fn deinit(self: EgressOnlyInternetGateway) void {
        const a = self.allocator;
        a.free(self.id);
        a.free(self.vpc_id);
        a.free(self.state);
        a.free(self.name);
    }
};

pub const Result = struct {
    allocator: Allocator,
    egress_only_internet_gateways: []EgressOnlyInternetGateway,
    next_token: ?[]u8,

    pub fn deinit(self: Result) void {
        for (self.egress_only_internet_gateways) |x| x.deinit();
        self.allocator.free(self.egress_only_internet_gateways);
        if (self.next_token) |t| self.allocator.free(t);
    }
};

pub fn describeEgressOnlyInternetGateways(client: anytype, options: Options) !Result {
    const body = try buildBody(client.allocator, options.params);
    defer client.allocator.free(body);

    const resp = try req.send(client, Ec2DescribeEgressOnlyInternetGatewaysError, "DescribeEgressOnlyInternetGateways", body);
    defer client.allocator.free(resp);

    return parseResponse(client.allocator, resp);
}

fn buildBody(allocator: Allocator, params: Params) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);

    try body.appendSlice(allocator, "Action=DescribeEgressOnlyInternetGateways&Version=" ++ req.api_version);

    for (params.egress_only_internet_gateway_ids, 1..) |id, n| {
        const key = try allocator.print("EgressOnlyInternetGatewayId.{d}", .{n});
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
    const root = xml.child(body, "DescribeEgressOnlyInternetGatewaysResponse") orelse return error.InvalidResponse;

    var items: std.ArrayList(EgressOnlyInternetGateway) = .empty;
    errdefer {
        for (items.items) |x| x.deinit();
        items.deinit(allocator);
    }

    if (xml.child(root, "egressOnlyInternetGatewaySet")) |set| {
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
        .egress_only_internet_gateways = try items.toOwnedSlice(allocator),
        .next_token = next_token,
    };
}

fn parseItem(allocator: Allocator, src: []const u8) !EgressOnlyInternetGateway {
    const id = try req.xmlStr(allocator, src, "egressOnlyInternetGatewayId");
    errdefer allocator.free(id);
    const vpc_id = try req.xmlFirstItemStr(allocator, src, "attachmentSet", "vpcId");
    errdefer allocator.free(vpc_id);
    const state = try req.xmlFirstItemStr(allocator, src, "attachmentSet", "state");
    errdefer allocator.free(state);
    const name = try vpcs.parseNameTag(allocator, src);
    errdefer allocator.free(name);

    return .{
        .allocator = allocator,
        .id = id,
        .vpc_id = vpc_id,
        .state = state,
        .name = name,
    };
}

// ============================================================================
// Tests
// ============================================================================

const sample =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<DescribeEgressOnlyInternetGatewaysResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
    \\  <requestId>req-1</requestId>
    \\  <egressOnlyInternetGatewaySet>
    \\    <item>
    \\      <egressOnlyInternetGatewayId>eigw-1</egressOnlyInternetGatewayId>
    \\      <attachmentSet><item><vpcId>vpc-1</vpcId><state>attached</state></item></attachmentSet>
    \\      <tagSet><item><key>Name</key><value>v6</value></item></tagSet>
    \\    </item>
    \\    <item>
    \\      <egressOnlyInternetGatewayId>eigw-2</egressOnlyInternetGatewayId>
    \\      <attachmentSet/>
    \\    </item>
    \\  </egressOnlyInternetGatewaySet>
    \\  <nextToken>TOKEN</nextToken>
    \\</DescribeEgressOnlyInternetGatewaysResponse>
;

test "parseResponse egress_only_internet_gateways" {
    const result = try parseResponse(std.testing.allocator, sample);
    defer result.deinit();

    const items = result.egress_only_internet_gateways;
    try std.testing.expectEqual(@as(usize, 2), items.len);
    try std.testing.expectEqualStrings("eigw-1", items[0].id);
    try std.testing.expectEqualStrings("vpc-1", items[0].vpc_id);
    try std.testing.expectEqualStrings("attached", items[0].state);
    try std.testing.expectEqualStrings("v6", items[0].name);
    try std.testing.expectEqualStrings("", items[1].vpc_id);
    try std.testing.expectEqualStrings("", items[1].state);
    try std.testing.expectEqualStrings("TOKEN", result.next_token.?);
}

test "parseResponse empty set" {
    const result = try parseResponse(
        std.testing.allocator,
        "<DescribeEgressOnlyInternetGatewaysResponse><requestId>r</requestId><egressOnlyInternetGatewaySet/></DescribeEgressOnlyInternetGatewaysResponse>",
    );
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 0), result.egress_only_internet_gateways.len);
    try std.testing.expect(result.next_token == null);
}

test "buildBody action only" {
    const body = try buildBody(std.testing.allocator, .{});
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("Action=DescribeEgressOnlyInternetGateways&Version=2016-11-15", body);
}

test "buildBody ids and filters" {
    const body = try buildBody(std.testing.allocator, .{
        .egress_only_internet_gateway_ids = &.{ "eigw-1", "x-2" },
        .filters = &.{.{ .name = "vpc-id", .values = &.{"vpc-1"} }},
        .max_results = 5,
        .next_token = "tok/en",
    });
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings(
        "Action=DescribeEgressOnlyInternetGateways&Version=2016-11-15&EgressOnlyInternetGatewayId.1=eigw-1&EgressOnlyInternetGatewayId.2=x-2" ++
            "&Filter.1.Name=vpc-id&Filter.1.Value.1=vpc-1&MaxResults=5&NextToken=tok%2Fen",
        body,
    );
}
