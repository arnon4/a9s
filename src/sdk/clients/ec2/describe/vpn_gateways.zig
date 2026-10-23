const std = @import("std");
const Allocator = std.mem.Allocator;

const xml = @import("../../../utils/xml.zig");
const req = @import("../request.zig");
const vpcs = @import("vpcs.zig");

pub const Filter = vpcs.Filter;

pub const Ec2DescribeVpnGatewaysError = error{
    @"InvalidVpnGatewayID.NotFound",
    InvalidParameterValue,
    InvalidParameterCombination,
    UnauthorizedOperation,
    AuthFailure,
    RequestLimitExceeded,
};

pub const Params = struct {
    vpn_gateway_ids: []const []const u8 = &.{},
    filters: []const Filter = &.{},
};

pub const Options = struct {
    params: Params = .{},
};

pub const VpnGateway = struct {
    allocator: Allocator,
    /// Virtual private gateway ID.
    id: []u8,
    /// pending | available | deleting | deleted.
    state: []u8,
    /// VPC of the first attachment, or empty.
    vpc_id: []u8,
    /// attaching | attached | detaching | detached.
    attachment_state: []u8,
    /// Value of the `Name` tag, or empty.
    name: []u8,

    pub fn deinit(self: VpnGateway) void {
        const a = self.allocator;
        a.free(self.id);
        a.free(self.state);
        a.free(self.vpc_id);
        a.free(self.attachment_state);
        a.free(self.name);
    }
};

pub const Result = struct {
    allocator: Allocator,
    vpn_gateways: []VpnGateway,

    pub fn deinit(self: Result) void {
        for (self.vpn_gateways) |x| x.deinit();
        self.allocator.free(self.vpn_gateways);
    }
};

pub fn describeVpnGateways(client: anytype, options: Options) !Result {
    const body = try buildBody(client.allocator, options.params);
    defer client.allocator.free(body);

    const resp = try req.send(client, Ec2DescribeVpnGatewaysError, "DescribeVpnGateways", body);
    defer client.allocator.free(resp);

    return parseResponse(client.allocator, resp);
}

fn buildBody(allocator: Allocator, params: Params) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);

    try body.appendSlice(allocator, "Action=DescribeVpnGateways&Version=" ++ req.api_version);

    for (params.vpn_gateway_ids, 1..) |id, n| {
        const key = try allocator.print("VpnGatewayId.{d}", .{n});
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

    return body.toOwnedSlice(allocator);
}

fn parseResponse(allocator: Allocator, body: []const u8) !Result {
    const root = xml.child(body, "DescribeVpnGatewaysResponse") orelse return error.InvalidResponse;

    var items: std.ArrayList(VpnGateway) = .empty;
    errdefer {
        for (items.items) |x| x.deinit();
        items.deinit(allocator);
    }

    if (xml.child(root, "vpnGatewaySet")) |set| {
        var it: xml.ChildIterator = .{ .src = set, .name = "item" };
        while (it.next()) |src| {
            const parsed = try parseItem(allocator, src);
            errdefer parsed.deinit();
            try items.append(allocator, parsed);
        }
    }

    return .{
        .allocator = allocator,
        .vpn_gateways = try items.toOwnedSlice(allocator),
    };
}

fn parseItem(allocator: Allocator, src: []const u8) !VpnGateway {
    const id = try req.xmlStr(allocator, src, "vpnGatewayId");
    errdefer allocator.free(id);
    const state = try req.xmlStr(allocator, src, "state");
    errdefer allocator.free(state);
    const vpc_id = try req.xmlFirstItemStr(allocator, src, "attachments", "vpcId");
    errdefer allocator.free(vpc_id);
    const attachment_state = try req.xmlFirstItemStr(allocator, src, "attachments", "state");
    errdefer allocator.free(attachment_state);
    const name = try vpcs.parseNameTag(allocator, src);
    errdefer allocator.free(name);

    return .{
        .allocator = allocator,
        .id = id,
        .state = state,
        .vpc_id = vpc_id,
        .attachment_state = attachment_state,
        .name = name,
    };
}

// ============================================================================
// Tests
// ============================================================================

const sample =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<DescribeVpnGatewaysResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
    \\  <requestId>req-1</requestId>
    \\  <vpnGatewaySet>
    \\    <item>
    \\      <vpnGatewayId>vgw-1</vpnGatewayId>
    \\      <state>available</state>
    \\      <attachments><item><vpcId>vpc-1</vpcId><state>attached</state></item></attachments>
    \\      <tagSet><item><key>Name</key><value>dc</value></item></tagSet>
    \\    </item>
    \\    <item>
    \\      <vpnGatewayId>vgw-2</vpnGatewayId>
    \\      <state>available</state>
    \\      <attachments/>
    \\    </item>
    \\  </vpnGatewaySet>
    \\</DescribeVpnGatewaysResponse>
;

test "parseResponse vpn_gateways" {
    const result = try parseResponse(std.testing.allocator, sample);
    defer result.deinit();

    const items = result.vpn_gateways;
    try std.testing.expectEqual(@as(usize, 2), items.len);
    try std.testing.expectEqualStrings("vgw-1", items[0].id);
    try std.testing.expectEqualStrings("vpc-1", items[0].vpc_id);
    try std.testing.expectEqualStrings("attached", items[0].attachment_state);
    try std.testing.expectEqualStrings("dc", items[0].name);
    try std.testing.expectEqualStrings("", items[1].vpc_id);
    try std.testing.expectEqualStrings("", items[1].attachment_state);
}

test "parseResponse empty set" {
    const result = try parseResponse(
        std.testing.allocator,
        "<DescribeVpnGatewaysResponse><requestId>r</requestId><vpnGatewaySet/></DescribeVpnGatewaysResponse>",
    );
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 0), result.vpn_gateways.len);
}

test "buildBody action only" {
    const body = try buildBody(std.testing.allocator, .{});
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("Action=DescribeVpnGateways&Version=2016-11-15", body);
}

test "buildBody ids and filters" {
    const body = try buildBody(std.testing.allocator, .{
        .vpn_gateway_ids = &.{ "vgw-1", "x-2" },
        .filters = &.{.{ .name = "vpc-id", .values = &.{"vpc-1"} }},
    });
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings(
        "Action=DescribeVpnGateways&Version=2016-11-15&VpnGatewayId.1=vgw-1&VpnGatewayId.2=x-2" ++
            "&Filter.1.Name=vpc-id&Filter.1.Value.1=vpc-1",
        body,
    );
}
