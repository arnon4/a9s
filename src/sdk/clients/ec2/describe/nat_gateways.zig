const std = @import("std");
const Allocator = std.mem.Allocator;

const xml = @import("../../../utils/xml.zig");
const req = @import("../request.zig");
const vpcs = @import("vpcs.zig");

pub const Tag = vpcs.Tag;
pub const Filter = vpcs.Filter;

pub const Ec2DescribeNatGatewaysError = error{
    @"InvalidNatGatewayID.NotFound",
    NatGatewayMalformed,
    InvalidParameterValue,
    InvalidParameterCombination,
    UnauthorizedOperation,
    AuthFailure,
    RequestLimitExceeded,
};

pub const Params = struct {
    nat_gateway_ids: []const []const u8 = &.{},
    filters: []const Filter = &.{},
    /// 5..1000
    max_results: ?u32 = null,
    next_token: ?[]const u8 = null,
};

pub const Options = struct {
    params: Params = .{},
};

/// One address (elastic IP or private IP) of a NAT gateway.
pub const Address = struct {
    allocation_id: []u8,
    network_interface_id: []u8,
    private_ip: []u8,
    public_ip: []u8,
    association_id: []u8,
    is_primary: bool,
    /// assigning | unassigning | associating | disassociating | succeeded | failed
    status: []u8,
    failure_message: []u8,
};

pub const NatGateway = struct {
    allocator: Allocator,
    id: []u8,
    /// pending | failed | available | deleting | deleted.
    state: []u8,
    vpc_id: []u8,
    /// Subnet the gateway lives in.
    subnet_id: []u8,
    /// "public" or "private"; empty on older responses.
    connectivity_type: []u8,
    /// ISO 8601 timestamps as returned by EC2; empty when absent.
    create_time: []u8,
    delete_time: []u8,
    failure_code: []u8,
    failure_message: []u8,
    /// Value of the `Name` tag, or empty.
    name: []u8,
    tags: []Tag,
    addresses: []Address,

    pub fn deinit(self: NatGateway) void {
        const a = self.allocator;
        a.free(self.id);
        a.free(self.state);
        a.free(self.vpc_id);
        a.free(self.subnet_id);
        a.free(self.connectivity_type);
        a.free(self.create_time);
        a.free(self.delete_time);
        a.free(self.failure_code);
        a.free(self.failure_message);
        a.free(self.name);
        vpcs.freeTags(a, self.tags);
        freeAddresses(a, self.addresses);
    }
};

pub const Result = struct {
    allocator: Allocator,
    nat_gateways: []NatGateway,
    next_token: ?[]u8,

    pub fn deinit(self: Result) void {
        for (self.nat_gateways) |x| x.deinit();
        self.allocator.free(self.nat_gateways);
        if (self.next_token) |t| self.allocator.free(t);
    }
};

fn freeAddressFields(a: Allocator, x: Address) void {
    a.free(x.allocation_id);
    a.free(x.network_interface_id);
    a.free(x.private_ip);
    a.free(x.public_ip);
    a.free(x.association_id);
    a.free(x.status);
    a.free(x.failure_message);
}

fn freeAddresses(a: Allocator, items: []Address) void {
    for (items) |x| freeAddressFields(a, x);
    a.free(items);
}

pub fn describeNatGateways(client: anytype, options: Options) !Result {
    const body = try buildBody(client.allocator, options.params);
    defer client.allocator.free(body);

    const resp = try req.send(client, Ec2DescribeNatGatewaysError, "DescribeNatGateways", body);
    defer client.allocator.free(resp);

    return parseResponse(client.allocator, resp);
}

fn buildBody(allocator: Allocator, params: Params) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);

    try body.appendSlice(allocator, "Action=DescribeNatGateways&Version=" ++ req.api_version);

    for (params.nat_gateway_ids, 1..) |id, n| {
        const key = try allocator.print("NatGatewayId.{d}", .{n});
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
    const root = xml.child(body, "DescribeNatGatewaysResponse") orelse return error.InvalidResponse;

    var items: std.ArrayList(NatGateway) = .empty;
    errdefer {
        for (items.items) |x| x.deinit();
        items.deinit(allocator);
    }

    if (xml.child(root, "natGatewaySet")) |set| {
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
        .nat_gateways = try items.toOwnedSlice(allocator),
        .next_token = next_token,
    };
}

fn parseAddresses(allocator: Allocator, src: []const u8) ![]Address {
    var items: std.ArrayList(Address) = .empty;
    errdefer {
        for (items.items) |x| freeAddressFields(allocator, x);
        items.deinit(allocator);
    }

    const set = xml.child(src, "natGatewayAddressSet") orelse return items.toOwnedSlice(allocator);
    var it: xml.ChildIterator = .{ .src = set, .name = "item" };
    while (it.next()) |item| {
        const allocation_id = try req.xmlStr(allocator, item, "allocationId");
        errdefer allocator.free(allocation_id);
        const network_interface_id = try req.xmlStr(allocator, item, "networkInterfaceId");
        errdefer allocator.free(network_interface_id);
        const private_ip = try req.xmlStr(allocator, item, "privateIp");
        errdefer allocator.free(private_ip);
        const public_ip = try req.xmlStr(allocator, item, "publicIp");
        errdefer allocator.free(public_ip);
        const association_id = try req.xmlStr(allocator, item, "associationId");
        errdefer allocator.free(association_id);
        const status = try req.xmlStr(allocator, item, "status");
        errdefer allocator.free(status);
        const failure_message = try req.xmlStr(allocator, item, "failureMessage");
        errdefer allocator.free(failure_message);

        try items.append(allocator, .{
            .allocation_id = allocation_id,
            .network_interface_id = network_interface_id,
            .private_ip = private_ip,
            .public_ip = public_ip,
            .association_id = association_id,
            .is_primary = req.xmlBool(item, "isPrimary"),
            .status = status,
            .failure_message = failure_message,
        });
    }
    return items.toOwnedSlice(allocator);
}

fn parseItem(allocator: Allocator, src: []const u8) !NatGateway {
    const id = try req.xmlStr(allocator, src, "natGatewayId");
    errdefer allocator.free(id);
    const state = try req.xmlStr(allocator, src, "state");
    errdefer allocator.free(state);
    const vpc_id = try req.xmlStr(allocator, src, "vpcId");
    errdefer allocator.free(vpc_id);
    const subnet_id = try req.xmlStr(allocator, src, "subnetId");
    errdefer allocator.free(subnet_id);
    const connectivity_type = try req.xmlStr(allocator, src, "connectivityType");
    errdefer allocator.free(connectivity_type);
    const create_time = try req.xmlStr(allocator, src, "createTime");
    errdefer allocator.free(create_time);
    const delete_time = try req.xmlStr(allocator, src, "deleteTime");
    errdefer allocator.free(delete_time);
    const failure_code = try req.xmlStr(allocator, src, "failureCode");
    errdefer allocator.free(failure_code);
    const failure_message = try req.xmlStr(allocator, src, "failureMessage");
    errdefer allocator.free(failure_message);
    const name = try vpcs.parseNameTag(allocator, src);
    errdefer allocator.free(name);
    const tags = try vpcs.parseTags(allocator, src);
    errdefer vpcs.freeTags(allocator, tags);
    const addresses = try parseAddresses(allocator, src);
    errdefer freeAddresses(allocator, addresses);

    return .{
        .allocator = allocator,
        .id = id,
        .state = state,
        .vpc_id = vpc_id,
        .subnet_id = subnet_id,
        .connectivity_type = connectivity_type,
        .create_time = create_time,
        .delete_time = delete_time,
        .failure_code = failure_code,
        .failure_message = failure_message,
        .name = name,
        .tags = tags,
        .addresses = addresses,
    };
}

// ============================================================================
// Tests
// ============================================================================

const sample =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<DescribeNatGatewaysResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
    \\  <requestId>req-1</requestId>
    \\  <natGatewaySet>
    \\    <item>
    \\      <natGatewayId>nat-0abc</natGatewayId>
    \\      <vpcId>vpc-1</vpcId>
    \\      <subnetId>subnet-1</subnetId>
    \\      <state>available</state>
    \\      <createTime>2026-01-02T03:04:05.000Z</createTime>
    \\      <connectivityType>public</connectivityType>
    \\      <natGatewayAddressSet>
    \\        <item>
    \\          <allocationId>eipalloc-1</allocationId>
    \\          <networkInterfaceId>eni-1</networkInterfaceId>
    \\          <privateIp>10.0.1.10</privateIp>
    \\          <publicIp>203.0.113.7</publicIp>
    \\          <associationId>eipassoc-1</associationId>
    \\          <isPrimary>true</isPrimary>
    \\          <status>succeeded</status>
    \\        </item>
    \\        <item>
    \\          <privateIp>10.0.1.11</privateIp>
    \\          <isPrimary>false</isPrimary>
    \\          <status>failed</status>
    \\          <failureMessage>no capacity</failureMessage>
    \\        </item>
    \\      </natGatewayAddressSet>
    \\      <tagSet><item><key>Name</key><value>egress &amp; nat</value></item></tagSet>
    \\    </item>
    \\    <item>
    \\      <natGatewayId>nat-bare</natGatewayId>
    \\      <state>failed</state>
    \\      <failureCode>Gateway.NotAttached</failureCode>
    \\      <failureMessage>Network vpc-1 has no Internet gateway attached</failureMessage>
    \\      <deleteTime>2026-01-03T00:00:00.000Z</deleteTime>
    \\    </item>
    \\  </natGatewaySet>
    \\  <nextToken>TOKEN</nextToken>
    \\</DescribeNatGatewaysResponse>
;

test "parseResponse nat gateways" {
    const result = try parseResponse(std.testing.allocator, sample);
    defer result.deinit();

    const items = result.nat_gateways;
    try std.testing.expectEqual(@as(usize, 2), items.len);
    try std.testing.expectEqualStrings("nat-0abc", items[0].id);
    try std.testing.expectEqualStrings("vpc-1", items[0].vpc_id);
    try std.testing.expectEqualStrings("subnet-1", items[0].subnet_id);
    try std.testing.expectEqualStrings("available", items[0].state);
    try std.testing.expectEqualStrings("public", items[0].connectivity_type);
    try std.testing.expectEqualStrings("2026-01-02T03:04:05.000Z", items[0].create_time);
    try std.testing.expectEqualStrings("egress & nat", items[0].name);
    try std.testing.expectEqual(@as(usize, 1), items[0].tags.len);

    try std.testing.expectEqual(@as(usize, 2), items[0].addresses.len);
    const primary = items[0].addresses[0];
    try std.testing.expectEqualStrings("eipalloc-1", primary.allocation_id);
    try std.testing.expectEqualStrings("eni-1", primary.network_interface_id);
    try std.testing.expectEqualStrings("10.0.1.10", primary.private_ip);
    try std.testing.expectEqualStrings("203.0.113.7", primary.public_ip);
    try std.testing.expect(primary.is_primary);
    try std.testing.expectEqualStrings("succeeded", primary.status);
    const failed = items[0].addresses[1];
    try std.testing.expect(!failed.is_primary);
    try std.testing.expectEqualStrings("", failed.public_ip);
    try std.testing.expectEqualStrings("no capacity", failed.failure_message);

    try std.testing.expectEqualStrings("failed", items[1].state);
    try std.testing.expectEqualStrings("", items[1].subnet_id);
    try std.testing.expectEqualStrings("", items[1].name);
    try std.testing.expectEqualStrings("Gateway.NotAttached", items[1].failure_code);
    try std.testing.expectEqualStrings("Network vpc-1 has no Internet gateway attached", items[1].failure_message);
    try std.testing.expectEqualStrings("2026-01-03T00:00:00.000Z", items[1].delete_time);
    try std.testing.expectEqual(@as(usize, 0), items[1].addresses.len);
    try std.testing.expectEqualStrings("TOKEN", result.next_token.?);
}

test "parseResponse empty set" {
    const result = try parseResponse(
        std.testing.allocator,
        "<DescribeNatGatewaysResponse><requestId>r</requestId><natGatewaySet/></DescribeNatGatewaysResponse>",
    );
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 0), result.nat_gateways.len);
    try std.testing.expect(result.next_token == null);
}

test "buildBody action only" {
    const body = try buildBody(std.testing.allocator, .{});
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("Action=DescribeNatGateways&Version=2016-11-15", body);
}

test "buildBody ids filters and paging" {
    const body = try buildBody(std.testing.allocator, .{
        .nat_gateway_ids = &.{ "nat-1", "nat-2" },
        .filters = &.{.{ .name = "vpc-id", .values = &.{"vpc-1"} }},
        .max_results = 5,
        .next_token = "tok/en",
    });
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings(
        "Action=DescribeNatGateways&Version=2016-11-15&NatGatewayId.1=nat-1&NatGatewayId.2=nat-2" ++
            "&Filter.1.Name=vpc-id&Filter.1.Value.1=vpc-1" ++
            "&MaxResults=5&NextToken=tok%2Fen",
        body,
    );
}
