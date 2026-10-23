const std = @import("std");
const Allocator = std.mem.Allocator;

const xml = @import("../../../utils/xml.zig");
const req = @import("../request.zig");
const vpcs = @import("vpcs.zig");

pub const Tag = vpcs.Tag;
pub const CidrAssociation = vpcs.CidrAssociation;
pub const Filter = vpcs.Filter;

pub const Ec2DescribeSubnetsError = error{
    @"InvalidSubnetID.NotFound",
    @"InvalidSubnetID.Malformed",
    InvalidParameterValue,
    InvalidParameterCombination,
    UnauthorizedOperation,
    AuthFailure,
    RequestLimitExceeded,
};

pub const Params = struct {
    subnet_ids: []const []const u8 = &.{},
    filters: []const Filter = &.{},
    /// 5..1000
    max_results: ?u32 = null,
    next_token: ?[]const u8 = null,
};

pub const Options = struct {
    params: Params = .{},
};

pub const Subnet = struct {
    allocator: Allocator,
    subnet_id: []u8,
    subnet_arn: []u8,
    vpc_id: []u8,
    owner_id: []u8,
    state: []u8,
    cidr_block: []u8,
    availability_zone: []u8,
    availability_zone_id: []u8,
    available_ip_address_count: u32,
    default_for_az: bool,
    map_public_ip_on_launch: bool,
    assign_ipv6_address_on_creation: bool,
    ipv6_native: bool,
    enable_dns64: bool,
    outpost_arn: []u8,
    /// Value of the `Name` tag, or empty.
    name: []u8,
    tags: []Tag,
    ipv6_cidr_associations: []CidrAssociation,

    pub fn deinit(self: Subnet) void {
        const a = self.allocator;
        a.free(self.subnet_id);
        a.free(self.subnet_arn);
        a.free(self.vpc_id);
        a.free(self.owner_id);
        a.free(self.state);
        a.free(self.cidr_block);
        a.free(self.availability_zone);
        a.free(self.availability_zone_id);
        a.free(self.outpost_arn);
        a.free(self.name);
        vpcs.freeTags(a, self.tags);
        vpcs.freeAssociations(a, self.ipv6_cidr_associations);
    }
};

pub const Result = struct {
    allocator: Allocator,
    subnets: []Subnet,
    next_token: ?[]u8,

    pub fn deinit(self: Result) void {
        for (self.subnets) |s| s.deinit();
        self.allocator.free(self.subnets);
        if (self.next_token) |t| self.allocator.free(t);
    }
};

pub fn describeSubnets(client: anytype, options: Options) !Result {
    const body = try buildBody(client.allocator, options.params);
    defer client.allocator.free(body);

    const resp = try req.send(client, Ec2DescribeSubnetsError, "DescribeSubnets", body);
    defer client.allocator.free(resp);

    return parseResponse(client.allocator, resp);
}

fn buildBody(allocator: Allocator, params: Params) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);

    try body.appendSlice(allocator, "Action=DescribeSubnets&Version=" ++ req.api_version);

    for (params.subnet_ids, 1..) |id, n| {
        const key = try allocator.print("SubnetId.{d}", .{n});
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
    const root = xml.child(body, "DescribeSubnetsResponse") orelse return error.InvalidResponse;

    var subnets: std.ArrayList(Subnet) = .empty;
    errdefer {
        for (subnets.items) |s| s.deinit();
        subnets.deinit(allocator);
    }

    if (xml.child(root, "subnetSet")) |set| {
        var it: xml.ChildIterator = .{ .src = set, .name = "item" };
        while (it.next()) |item| {
            const subnet = try parseSubnet(allocator, item);
            errdefer subnet.deinit();
            try subnets.append(allocator, subnet);
        }
    }

    const next_token: ?[]u8 = if (xml.child(root, "nextToken")) |t|
        if (t.len > 0) try xml.unescape(allocator, t) else null
    else
        null;
    errdefer if (next_token) |t| allocator.free(t);

    return .{
        .allocator = allocator,
        .subnets = try subnets.toOwnedSlice(allocator),
        .next_token = next_token,
    };
}

fn parseSubnet(allocator: Allocator, src: []const u8) !Subnet {
    const subnet_id = try req.xmlStr(allocator, src, "subnetId");
    errdefer allocator.free(subnet_id);
    const subnet_arn = try req.xmlStr(allocator, src, "subnetArn");
    errdefer allocator.free(subnet_arn);
    const vpc_id = try req.xmlStr(allocator, src, "vpcId");
    errdefer allocator.free(vpc_id);
    const owner_id = try req.xmlStr(allocator, src, "ownerId");
    errdefer allocator.free(owner_id);
    const state = try req.xmlStr(allocator, src, "state");
    errdefer allocator.free(state);
    const cidr_block = try req.xmlStr(allocator, src, "cidrBlock");
    errdefer allocator.free(cidr_block);
    const availability_zone = try req.xmlStr(allocator, src, "availabilityZone");
    errdefer allocator.free(availability_zone);
    const availability_zone_id = try req.xmlStr(allocator, src, "availabilityZoneId");
    errdefer allocator.free(availability_zone_id);
    const outpost_arn = try req.xmlStr(allocator, src, "outpostArn");
    errdefer allocator.free(outpost_arn);

    const tags = try vpcs.parseTags(allocator, src);
    errdefer vpcs.freeTags(allocator, tags);

    var name: []u8 = undefined;
    for (tags) |t| {
        if (std.mem.eql(u8, t.key, "Name")) {
            name = try allocator.dupe(u8, t.value);
            break;
        }
    } else name = try allocator.dupe(u8, "");
    errdefer allocator.free(name);

    const ipv6 = try vpcs.parseAssociations(allocator, src, "ipv6CidrBlockAssociationSet", "associationId", "ipv6CidrBlock", "ipv6CidrBlockState");
    errdefer vpcs.freeAssociations(allocator, ipv6);

    const ip_count: u32 = if (xml.child(src, "availableIpAddressCount")) |c|
        std.fmt.parseInt(u32, c, 10) catch 0
    else
        0;

    return .{
        .allocator = allocator,
        .subnet_id = subnet_id,
        .subnet_arn = subnet_arn,
        .vpc_id = vpc_id,
        .owner_id = owner_id,
        .state = state,
        .cidr_block = cidr_block,
        .availability_zone = availability_zone,
        .availability_zone_id = availability_zone_id,
        .available_ip_address_count = ip_count,
        .default_for_az = req.xmlBool(src, "defaultForAz"),
        .map_public_ip_on_launch = req.xmlBool(src, "mapPublicIpOnLaunch"),
        .assign_ipv6_address_on_creation = req.xmlBool(src, "assignIpv6AddressOnCreation"),
        .ipv6_native = req.xmlBool(src, "ipv6Native"),
        .enable_dns64 = req.xmlBool(src, "enableDns64"),
        .outpost_arn = outpost_arn,
        .name = name,
        .tags = tags,
        .ipv6_cidr_associations = ipv6,
    };
}

// ============================================================================
// Tests
// ============================================================================

const sample =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<DescribeSubnetsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
    \\  <requestId>req-1</requestId>
    \\  <subnetSet>
    \\    <item>
    \\      <subnetId>subnet-0abc</subnetId>
    \\      <subnetArn>arn:aws:ec2:us-east-1:123456789012:subnet/subnet-0abc</subnetArn>
    \\      <state>available</state>
    \\      <ownerId>123456789012</ownerId>
    \\      <vpcId>vpc-0abc</vpcId>
    \\      <cidrBlock>10.0.1.0/24</cidrBlock>
    \\      <availableIpAddressCount>251</availableIpAddressCount>
    \\      <availabilityZone>us-east-1a</availabilityZone>
    \\      <availabilityZoneId>use1-az1</availabilityZoneId>
    \\      <defaultForAz>false</defaultForAz>
    \\      <mapPublicIpOnLaunch>true</mapPublicIpOnLaunch>
    \\      <assignIpv6AddressOnCreation>false</assignIpv6AddressOnCreation>
    \\      <ipv6CidrBlockAssociationSet>
    \\        <item>
    \\          <ipv6CidrBlock>2600:1f18::/64</ipv6CidrBlock>
    \\          <ipv6CidrBlockState><state>associated</state></ipv6CidrBlockState>
    \\          <associationId>subnet-cidr-assoc-1</associationId>
    \\        </item>
    \\      </ipv6CidrBlockAssociationSet>
    \\      <tagSet>
    \\        <item><key>Name</key><value>public &amp; a</value></item>
    \\      </tagSet>
    \\    </item>
    \\    <item>
    \\      <subnetId>subnet-default</subnetId>
    \\      <state>available</state>
    \\      <vpcId>vpc-default</vpcId>
    \\      <cidrBlock>172.31.0.0/20</cidrBlock>
    \\      <availableIpAddressCount>4091</availableIpAddressCount>
    \\      <availabilityZone>us-east-1b</availabilityZone>
    \\      <defaultForAz>true</defaultForAz>
    \\      <tagSet/>
    \\    </item>
    \\  </subnetSet>
    \\  <nextToken>TOKEN</nextToken>
    \\</DescribeSubnetsResponse>
;

test "parseResponse subnets" {
    const result = try parseResponse(std.testing.allocator, sample);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 2), result.subnets.len);
    const s = result.subnets[0];
    try std.testing.expectEqualStrings("subnet-0abc", s.subnet_id);
    try std.testing.expectEqualStrings("vpc-0abc", s.vpc_id);
    try std.testing.expectEqualStrings("10.0.1.0/24", s.cidr_block);
    try std.testing.expectEqualStrings("us-east-1a", s.availability_zone);
    try std.testing.expectEqualStrings("use1-az1", s.availability_zone_id);
    try std.testing.expectEqual(@as(u32, 251), s.available_ip_address_count);
    try std.testing.expect(s.map_public_ip_on_launch);
    try std.testing.expect(!s.default_for_az);
    try std.testing.expectEqualStrings("public & a", s.name);
    try std.testing.expectEqual(@as(usize, 1), s.ipv6_cidr_associations.len);
    try std.testing.expectEqualStrings("associated", s.ipv6_cidr_associations[0].state);

    const d = result.subnets[1];
    try std.testing.expect(d.default_for_az);
    try std.testing.expectEqualStrings("", d.name);
    try std.testing.expectEqualStrings("", d.outpost_arn);
    try std.testing.expectEqualStrings("TOKEN", result.next_token.?);
}

test "parseResponse empty set" {
    const result = try parseResponse(
        std.testing.allocator,
        "<DescribeSubnetsResponse><requestId>r</requestId><subnetSet/></DescribeSubnetsResponse>",
    );
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 0), result.subnets.len);
    try std.testing.expect(result.next_token == null);
}

test "buildBody action only" {
    const body = try buildBody(std.testing.allocator, .{});
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("Action=DescribeSubnets&Version=2016-11-15", body);
}

test "buildBody ids filters and paging" {
    const body = try buildBody(std.testing.allocator, .{
        .subnet_ids = &.{ "subnet-1", "subnet-2" },
        .filters = &.{.{ .name = "vpc-id", .values = &.{ "vpc-1", "vpc-2" } }},
        .max_results = 5,
        .next_token = "tok/en",
    });
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings(
        "Action=DescribeSubnets&Version=2016-11-15&SubnetId.1=subnet-1&SubnetId.2=subnet-2" ++
            "&Filter.1.Name=vpc-id&Filter.1.Value.1=vpc-1&Filter.1.Value.2=vpc-2" ++
            "&MaxResults=5&NextToken=tok%2Fen",
        body,
    );
}
