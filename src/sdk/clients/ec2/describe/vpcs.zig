const std = @import("std");
const Allocator = std.mem.Allocator;

const xml = @import("../../../utils/xml.zig");
const req = @import("../request.zig");

pub const Ec2DescribeVpcsError = error{
    @"InvalidVpcID.NotFound",
    @"InvalidVpcID.Malformed",
    InvalidParameterValue,
    InvalidParameterCombination,
    UnauthorizedOperation,
    AuthFailure,
    RequestLimitExceeded,
};

pub const Filter = struct {
    name: []const u8,
    values: []const []const u8,
};

pub const Params = struct {
    vpc_ids: []const []const u8 = &.{},
    filters: []const Filter = &.{},
    /// 5..1000
    max_results: ?u32 = null,
    next_token: ?[]const u8 = null,
};

pub const Options = struct {
    params: Params = .{},
};

pub const Tag = struct {
    key: []u8,
    value: []u8,
};

pub const CidrAssociation = struct {
    association_id: []u8,
    cidr_block: []u8,
    state: []u8,
};

pub const Vpc = struct {
    allocator: Allocator,
    vpc_id: []u8,
    owner_id: []u8,
    state: []u8,
    cidr_block: []u8,
    dhcp_options_id: []u8,
    instance_tenancy: []u8,
    is_default: bool,
    /// Value of the `Name` tag, or empty.
    name: []u8,
    tags: []Tag,
    cidr_associations: []CidrAssociation,
    ipv6_cidr_associations: []CidrAssociation,

    pub fn deinit(self: Vpc) void {
        const a = self.allocator;
        a.free(self.vpc_id);
        a.free(self.owner_id);
        a.free(self.state);
        a.free(self.cidr_block);
        a.free(self.dhcp_options_id);
        a.free(self.instance_tenancy);
        a.free(self.name);
        freeTags(a, self.tags);
        freeAssociations(a, self.cidr_associations);
        freeAssociations(a, self.ipv6_cidr_associations);
    }
};

pub const Result = struct {
    allocator: Allocator,
    vpcs: []Vpc,
    next_token: ?[]u8,

    pub fn deinit(self: Result) void {
        for (self.vpcs) |v| v.deinit();
        self.allocator.free(self.vpcs);
        if (self.next_token) |t| self.allocator.free(t);
    }
};

pub fn freeTags(a: Allocator, tags: []Tag) void {
    for (tags) |t| {
        a.free(t.key);
        a.free(t.value);
    }
    a.free(tags);
}

pub fn freeAssociations(a: Allocator, items: []CidrAssociation) void {
    for (items) |c| {
        a.free(c.association_id);
        a.free(c.cidr_block);
        a.free(c.state);
    }
    a.free(items);
}

pub fn describeVpcs(client: anytype, options: Options) !Result {
    const body = try buildBody(client.allocator, options.params);
    defer client.allocator.free(body);

    const resp = try req.send(client, Ec2DescribeVpcsError, "DescribeVpcs", body);
    defer client.allocator.free(resp);

    return parseResponse(client.allocator, resp);
}

fn buildBody(allocator: Allocator, params: Params) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);

    try body.appendSlice(allocator, "Action=DescribeVpcs&Version=" ++ req.api_version);

    for (params.vpc_ids, 1..) |id, n| {
        const key = try allocator.print("VpcId.{d}", .{n});
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
    const root = xml.child(body, "DescribeVpcsResponse") orelse return error.InvalidResponse;

    var vpcs: std.ArrayList(Vpc) = .empty;
    errdefer {
        for (vpcs.items) |v| v.deinit();
        vpcs.deinit(allocator);
    }

    if (xml.child(root, "vpcSet")) |set| {
        var it: xml.ChildIterator = .{ .src = set, .name = "item" };
        while (it.next()) |item| {
            const vpc = try parseVpc(allocator, item);
            errdefer vpc.deinit();
            try vpcs.append(allocator, vpc);
        }
    }

    const next_token: ?[]u8 = if (xml.child(root, "nextToken")) |t|
        if (t.len > 0) try xml.unescape(allocator, t) else null
    else
        null;
    errdefer if (next_token) |t| allocator.free(t);

    return .{
        .allocator = allocator,
        .vpcs = try vpcs.toOwnedSlice(allocator),
        .next_token = next_token,
    };
}

fn parseVpc(allocator: Allocator, src: []const u8) !Vpc {
    const vpc_id = try req.xmlStr(allocator, src, "vpcId");
    errdefer allocator.free(vpc_id);
    const owner_id = try req.xmlStr(allocator, src, "ownerId");
    errdefer allocator.free(owner_id);
    const state = try req.xmlStr(allocator, src, "state");
    errdefer allocator.free(state);
    const cidr_block = try req.xmlStr(allocator, src, "cidrBlock");
    errdefer allocator.free(cidr_block);
    const dhcp_options_id = try req.xmlStr(allocator, src, "dhcpOptionsId");
    errdefer allocator.free(dhcp_options_id);
    const instance_tenancy = try req.xmlStr(allocator, src, "instanceTenancy");
    errdefer allocator.free(instance_tenancy);

    const tags = try parseTags(allocator, src);
    errdefer freeTags(allocator, tags);

    var name: []u8 = undefined;
    for (tags) |t| {
        if (std.mem.eql(u8, t.key, "Name")) {
            name = try allocator.dupe(u8, t.value);
            break;
        }
    } else name = try allocator.dupe(u8, "");
    errdefer allocator.free(name);

    const cidrs = try parseAssociations(allocator, src, "cidrBlockAssociationSet", "associationId", "cidrBlock", "cidrBlockState");
    errdefer freeAssociations(allocator, cidrs);
    const ipv6 = try parseAssociations(allocator, src, "ipv6CidrBlockAssociationSet", "associationId", "ipv6CidrBlock", "ipv6CidrBlockState");
    errdefer freeAssociations(allocator, ipv6);

    return .{
        .allocator = allocator,
        .vpc_id = vpc_id,
        .owner_id = owner_id,
        .state = state,
        .cidr_block = cidr_block,
        .dhcp_options_id = dhcp_options_id,
        .instance_tenancy = instance_tenancy,
        .is_default = req.xmlBool(src, "isDefault"),
        .name = name,
        .tags = tags,
        .cidr_associations = cidrs,
        .ipv6_cidr_associations = ipv6,
    };
}

pub fn parseTags(allocator: Allocator, src: []const u8) ![]Tag {
    var tags: std.ArrayList(Tag) = .empty;
    errdefer {
        for (tags.items) |t| {
            allocator.free(t.key);
            allocator.free(t.value);
        }
        tags.deinit(allocator);
    }

    const set = xml.child(src, "tagSet") orelse return tags.toOwnedSlice(allocator);
    var it: xml.ChildIterator = .{ .src = set, .name = "item" };
    while (it.next()) |item| {
        const key = try req.xmlStr(allocator, item, "key");
        errdefer allocator.free(key);
        const value = try req.xmlStr(allocator, item, "value");
        errdefer allocator.free(value);
        try tags.append(allocator, .{ .key = key, .value = value });
    }
    return tags.toOwnedSlice(allocator);
}

pub fn parseAssociations(
    allocator: Allocator,
    src: []const u8,
    set_tag: []const u8,
    id_tag: []const u8,
    cidr_tag: []const u8,
    state_tag: []const u8,
) ![]CidrAssociation {
    var items: std.ArrayList(CidrAssociation) = .empty;
    errdefer {
        for (items.items) |c| {
            allocator.free(c.association_id);
            allocator.free(c.cidr_block);
            allocator.free(c.state);
        }
        items.deinit(allocator);
    }

    const set = xml.child(src, set_tag) orelse return items.toOwnedSlice(allocator);
    var it: xml.ChildIterator = .{ .src = set, .name = "item" };
    while (it.next()) |item| {
        const association_id = try req.xmlStr(allocator, item, id_tag);
        errdefer allocator.free(association_id);
        const cidr_block = try req.xmlStr(allocator, item, cidr_tag);
        errdefer allocator.free(cidr_block);
        const state_block = xml.child(item, state_tag) orelse "";
        const state = try req.xmlStr(allocator, state_block, "state");
        errdefer allocator.free(state);
        try items.append(allocator, .{ .association_id = association_id, .cidr_block = cidr_block, .state = state });
    }
    return items.toOwnedSlice(allocator);
}

// ============================================================================
// Tests
// ============================================================================

const sample =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<DescribeVpcsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
    \\  <requestId>req-1</requestId>
    \\  <vpcSet>
    \\    <item>
    \\      <ownerId>123456789012</ownerId>
    \\      <vpcId>vpc-0abc</vpcId>
    \\      <state>available</state>
    \\      <cidrBlock>10.0.0.0/16</cidrBlock>
    \\      <dhcpOptionsId>dopt-1</dhcpOptionsId>
    \\      <instanceTenancy>default</instanceTenancy>
    \\      <isDefault>false</isDefault>
    \\      <cidrBlockAssociationSet>
    \\        <item>
    \\          <cidrBlock>10.0.0.0/16</cidrBlock>
    \\          <cidrBlockState><state>associated</state></cidrBlockState>
    \\          <associationId>vpc-cidr-assoc-1</associationId>
    \\        </item>
    \\      </cidrBlockAssociationSet>
    \\      <ipv6CidrBlockAssociationSet/>
    \\      <tagSet>
    \\        <item><key>Env</key><value>prod</value></item>
    \\        <item><key>Name</key><value>main &amp; co</value></item>
    \\      </tagSet>
    \\    </item>
    \\    <item>
    \\      <ownerId>123456789012</ownerId>
    \\      <vpcId>vpc-default</vpcId>
    \\      <state>available</state>
    \\      <cidrBlock>172.31.0.0/16</cidrBlock>
    \\      <dhcpOptionsId>dopt-1</dhcpOptionsId>
    \\      <instanceTenancy>default</instanceTenancy>
    \\      <isDefault>true</isDefault>
    \\      <tagSet/>
    \\    </item>
    \\  </vpcSet>
    \\  <nextToken>TOKEN</nextToken>
    \\</DescribeVpcsResponse>
;

test "parseResponse vpcs" {
    const result = try parseResponse(std.testing.allocator, sample);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 2), result.vpcs.len);
    const v = result.vpcs[0];
    try std.testing.expectEqualStrings("vpc-0abc", v.vpc_id);
    try std.testing.expectEqualStrings("available", v.state);
    try std.testing.expectEqualStrings("10.0.0.0/16", v.cidr_block);
    try std.testing.expect(!v.is_default);
    try std.testing.expectEqualStrings("main & co", v.name);
    try std.testing.expectEqual(@as(usize, 2), v.tags.len);
    try std.testing.expectEqual(@as(usize, 1), v.cidr_associations.len);
    try std.testing.expectEqualStrings("associated", v.cidr_associations[0].state);
    try std.testing.expectEqualStrings("vpc-cidr-assoc-1", v.cidr_associations[0].association_id);
    try std.testing.expectEqual(@as(usize, 0), v.ipv6_cidr_associations.len);

    try std.testing.expect(result.vpcs[1].is_default);
    try std.testing.expectEqualStrings("", result.vpcs[1].name);
    try std.testing.expectEqualStrings("TOKEN", result.next_token.?);
}

test "parseResponse empty set" {
    const result = try parseResponse(
        std.testing.allocator,
        "<DescribeVpcsResponse><requestId>r</requestId><vpcSet/></DescribeVpcsResponse>",
    );
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 0), result.vpcs.len);
    try std.testing.expect(result.next_token == null);
}

test "buildBody action only" {
    const body = try buildBody(std.testing.allocator, .{});
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("Action=DescribeVpcs&Version=2016-11-15", body);
}

test "buildBody ids filters and paging" {
    const body = try buildBody(std.testing.allocator, .{
        .vpc_ids = &.{ "vpc-1", "vpc-2" },
        .filters = &.{.{ .name = "tag:Name", .values = &.{ "a b", "c" } }},
        .max_results = 5,
        .next_token = "tok/en",
    });
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings(
        "Action=DescribeVpcs&Version=2016-11-15&VpcId.1=vpc-1&VpcId.2=vpc-2" ++
            "&Filter.1.Name=tag%3AName&Filter.1.Value.1=a%20b&Filter.1.Value.2=c" ++
            "&MaxResults=5&NextToken=tok%2Fen",
        body,
    );
}
