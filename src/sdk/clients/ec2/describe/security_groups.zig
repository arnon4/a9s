const std = @import("std");
const Allocator = std.mem.Allocator;

const xml = @import("../../../utils/xml.zig");
const req = @import("../request.zig");
const vpcs = @import("vpcs.zig");
const paging = @import("paging.zig");

pub const Tag = vpcs.Tag;
pub const Filter = vpcs.Filter;

pub const Ec2DescribeSecurityGroupsError = error{
    @"InvalidGroup.NotFound",
    @"InvalidGroupId.Malformed",
    InvalidParameterValue,
    InvalidParameterCombination,
    UnauthorizedOperation,
    AuthFailure,
    RequestLimitExceeded,
};

pub const Params = struct {
    group_ids: []const []const u8 = &.{},
    group_names: []const []const u8 = &.{},
    filters: []const Filter = &.{},
    /// 5..1000
    max_results: ?u32 = null,
    next_token: ?[]const u8 = null,
};

pub const Options = struct {
    params: Params = .{},
};

/// A rule source/destination that is another security group.
pub const GroupPair = struct {
    group_id: []u8,
    /// Account owning the referenced group; empty when it is the caller's.
    user_id: []u8,
    /// Set when the group lives in a peer VPC.
    vpc_id: []u8,
    vpc_peering_connection_id: []u8,
};

/// A CIDR source/destination. Used for both IPv4 and IPv6 ranges.
pub const IpRange = struct {
    cidr: []u8,
    description: []u8,
};

pub const PrefixListRef = struct {
    prefix_list_id: []u8,
    description: []u8,
};

pub const IpPermission = struct {
    /// "tcp", "udp", "icmp", "icmpv6", a protocol number, or "-1" (all).
    protocol: []u8,
    /// Port range for TCP/UDP; for ICMP these are type and code. Null when the rule has none.
    from_port: ?i32,
    to_port: ?i32,
    groups: []GroupPair,
    ipv4_ranges: []IpRange,
    ipv6_ranges: []IpRange,
    prefix_lists: []PrefixListRef,
};

pub const SecurityGroup = struct {
    allocator: Allocator,
    group_id: []u8,
    group_name: []u8,
    description: []u8,
    vpc_id: []u8,
    owner_id: []u8,
    arn: []u8,
    /// Value of the `Name` tag, or empty.
    name: []u8,
    tags: []Tag,
    ingress: []IpPermission,
    egress: []IpPermission,

    pub fn deinit(self: SecurityGroup) void {
        const a = self.allocator;
        a.free(self.group_id);
        a.free(self.group_name);
        a.free(self.description);
        a.free(self.vpc_id);
        a.free(self.owner_id);
        a.free(self.arn);
        a.free(self.name);
        vpcs.freeTags(a, self.tags);
        freePermissions(a, self.ingress);
        freePermissions(a, self.egress);
    }
};

pub const Result = struct {
    allocator: Allocator,
    security_groups: []SecurityGroup,
    next_token: ?[]u8,

    pub fn deinit(self: Result) void {
        for (self.security_groups) |x| x.deinit();
        self.allocator.free(self.security_groups);
        if (self.next_token) |t| self.allocator.free(t);
    }
};

fn freeGroupPairs(a: Allocator, items: []GroupPair) void {
    for (items) |x| {
        a.free(x.group_id);
        a.free(x.user_id);
        a.free(x.vpc_id);
        a.free(x.vpc_peering_connection_id);
    }
    a.free(items);
}

fn freeRanges(a: Allocator, items: []IpRange) void {
    for (items) |x| {
        a.free(x.cidr);
        a.free(x.description);
    }
    a.free(items);
}

fn freePrefixLists(a: Allocator, items: []PrefixListRef) void {
    for (items) |x| {
        a.free(x.prefix_list_id);
        a.free(x.description);
    }
    a.free(items);
}

fn freePermission(a: Allocator, p: IpPermission) void {
    a.free(p.protocol);
    freeGroupPairs(a, p.groups);
    freeRanges(a, p.ipv4_ranges);
    freeRanges(a, p.ipv6_ranges);
    freePrefixLists(a, p.prefix_lists);
}

fn freePermissions(a: Allocator, items: []IpPermission) void {
    for (items) |p| freePermission(a, p);
    a.free(items);
}

pub fn describeSecurityGroups(client: anytype, options: Options) !Result {
    const body = try buildBody(client.allocator, options.params);
    defer client.allocator.free(body);

    const resp = try req.send(client, Ec2DescribeSecurityGroupsError, "DescribeSecurityGroups", body);
    defer client.allocator.free(resp);

    return parseResponse(client.allocator, resp);
}

/// Every page of results, fetched by following `NextToken`. The result has no `next_token`.
/// With explicit IDs or names EC2 forbids `MaxResults`, so the page size is only set without them.
pub fn describeAllSecurityGroups(client: anytype, options: Options) !Result {
    const Client = @TypeOf(client);
    const Fetch = struct {
        fn page(c: Client, params: Params) anyerror!Result {
            return describeSecurityGroups(c, .{ .params = params });
        }
    };
    var params = options.params;
    if (params.max_results == null and params.group_ids.len == 0 and params.group_names.len == 0) params.max_results = 1000;
    return paging.collect(SecurityGroup, Result, "security_groups", client.allocator, Client, client, params, Fetch.page);
}

fn appendList(allocator: Allocator, body: *std.ArrayList(u8), comptime prefix: []const u8, values: []const []const u8) !void {
    for (values, 1..) |v, n| {
        const key = try allocator.print(prefix ++ ".{d}", .{n});
        defer allocator.free(key);
        try req.appendParam(allocator, body, key, v);
    }
}

fn buildBody(allocator: Allocator, params: Params) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);

    try body.appendSlice(allocator, "Action=DescribeSecurityGroups&Version=" ++ req.api_version);

    try appendList(allocator, &body, "GroupId", params.group_ids);
    try appendList(allocator, &body, "GroupName", params.group_names);
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
    const root = xml.child(body, "DescribeSecurityGroupsResponse") orelse return error.InvalidResponse;

    var groups: std.ArrayList(SecurityGroup) = .empty;
    errdefer {
        for (groups.items) |x| x.deinit();
        groups.deinit(allocator);
    }

    if (xml.child(root, "securityGroupInfo")) |set| {
        var it: xml.ChildIterator = .{ .src = set, .name = "item" };
        while (it.next()) |src| {
            const group = try parseGroup(allocator, src);
            errdefer group.deinit();
            try groups.append(allocator, group);
        }
    }

    const next_token: ?[]u8 = if (xml.child(root, "nextToken")) |t|
        if (t.len > 0) try xml.unescape(allocator, t) else null
    else
        null;
    errdefer if (next_token) |t| allocator.free(t);

    return .{
        .allocator = allocator,
        .security_groups = try groups.toOwnedSlice(allocator),
        .next_token = next_token,
    };
}

fn parseGroupPairs(allocator: Allocator, src: []const u8) ![]GroupPair {
    var items: std.ArrayList(GroupPair) = .empty;
    errdefer {
        for (items.items) |x| {
            allocator.free(x.group_id);
            allocator.free(x.user_id);
            allocator.free(x.vpc_id);
            allocator.free(x.vpc_peering_connection_id);
        }
        items.deinit(allocator);
    }

    const set = xml.child(src, "groups") orelse return items.toOwnedSlice(allocator);
    var it: xml.ChildIterator = .{ .src = set, .name = "item" };
    while (it.next()) |item| {
        const group_id = try req.xmlStr(allocator, item, "groupId");
        errdefer allocator.free(group_id);
        const user_id = try req.xmlStr(allocator, item, "userId");
        errdefer allocator.free(user_id);
        const vpc_id = try req.xmlStr(allocator, item, "vpcId");
        errdefer allocator.free(vpc_id);
        const pcx = try req.xmlStr(allocator, item, "vpcPeeringConnectionId");
        errdefer allocator.free(pcx);
        try items.append(allocator, .{ .group_id = group_id, .user_id = user_id, .vpc_id = vpc_id, .vpc_peering_connection_id = pcx });
    }
    return items.toOwnedSlice(allocator);
}

fn parseRanges(allocator: Allocator, src: []const u8, set_tag: []const u8, cidr_tag: []const u8) ![]IpRange {
    var items: std.ArrayList(IpRange) = .empty;
    errdefer {
        for (items.items) |x| {
            allocator.free(x.cidr);
            allocator.free(x.description);
        }
        items.deinit(allocator);
    }

    const set = xml.child(src, set_tag) orelse return items.toOwnedSlice(allocator);
    var it: xml.ChildIterator = .{ .src = set, .name = "item" };
    while (it.next()) |item| {
        const cidr = try req.xmlStr(allocator, item, cidr_tag);
        errdefer allocator.free(cidr);
        const description = try req.xmlStr(allocator, item, "description");
        errdefer allocator.free(description);
        try items.append(allocator, .{ .cidr = cidr, .description = description });
    }
    return items.toOwnedSlice(allocator);
}

fn parsePrefixLists(allocator: Allocator, src: []const u8) ![]PrefixListRef {
    var items: std.ArrayList(PrefixListRef) = .empty;
    errdefer {
        for (items.items) |x| {
            allocator.free(x.prefix_list_id);
            allocator.free(x.description);
        }
        items.deinit(allocator);
    }

    const set = xml.child(src, "prefixListIds") orelse return items.toOwnedSlice(allocator);
    var it: xml.ChildIterator = .{ .src = set, .name = "item" };
    while (it.next()) |item| {
        const id = try req.xmlStr(allocator, item, "prefixListId");
        errdefer allocator.free(id);
        const description = try req.xmlStr(allocator, item, "description");
        errdefer allocator.free(description);
        try items.append(allocator, .{ .prefix_list_id = id, .description = description });
    }
    return items.toOwnedSlice(allocator);
}

fn parseOptionalInt(src: []const u8, tag: []const u8) ?i32 {
    const v = xml.child(src, tag) orelse return null;
    return std.fmt.parseInt(i32, v, 10) catch null;
}

fn parsePermissions(allocator: Allocator, src: []const u8, set_tag: []const u8) ![]IpPermission {
    var items: std.ArrayList(IpPermission) = .empty;
    errdefer {
        for (items.items) |p| freePermission(allocator, p);
        items.deinit(allocator);
    }

    const set = xml.child(src, set_tag) orelse return items.toOwnedSlice(allocator);
    var it: xml.ChildIterator = .{ .src = set, .name = "item" };
    while (it.next()) |item| {
        const protocol = try req.xmlStr(allocator, item, "ipProtocol");
        errdefer allocator.free(protocol);
        const groups = try parseGroupPairs(allocator, item);
        errdefer freeGroupPairs(allocator, groups);
        const v4 = try parseRanges(allocator, item, "ipRanges", "cidrIp");
        errdefer freeRanges(allocator, v4);
        const v6 = try parseRanges(allocator, item, "ipv6Ranges", "cidrIpv6");
        errdefer freeRanges(allocator, v6);
        const prefixes = try parsePrefixLists(allocator, item);
        errdefer freePrefixLists(allocator, prefixes);

        try items.append(allocator, .{
            .protocol = protocol,
            .from_port = parseOptionalInt(item, "fromPort"),
            .to_port = parseOptionalInt(item, "toPort"),
            .groups = groups,
            .ipv4_ranges = v4,
            .ipv6_ranges = v6,
            .prefix_lists = prefixes,
        });
    }
    return items.toOwnedSlice(allocator);
}

fn parseGroup(allocator: Allocator, src: []const u8) !SecurityGroup {
    const group_id = try req.xmlStr(allocator, src, "groupId");
    errdefer allocator.free(group_id);
    const group_name = try req.xmlStr(allocator, src, "groupName");
    errdefer allocator.free(group_name);
    const description = try req.xmlStr(allocator, src, "groupDescription");
    errdefer allocator.free(description);
    const vpc_id = try req.xmlStr(allocator, src, "vpcId");
    errdefer allocator.free(vpc_id);
    const owner_id = try req.xmlStr(allocator, src, "ownerId");
    errdefer allocator.free(owner_id);
    const arn = try req.xmlStr(allocator, src, "securityGroupArn");
    errdefer allocator.free(arn);
    const name = try vpcs.parseNameTag(allocator, src);
    errdefer allocator.free(name);
    const tags = try vpcs.parseTags(allocator, src);
    errdefer vpcs.freeTags(allocator, tags);
    const ingress = try parsePermissions(allocator, src, "ipPermissions");
    errdefer freePermissions(allocator, ingress);
    const egress = try parsePermissions(allocator, src, "ipPermissionsEgress");
    errdefer freePermissions(allocator, egress);

    return .{
        .allocator = allocator,
        .group_id = group_id,
        .group_name = group_name,
        .description = description,
        .vpc_id = vpc_id,
        .owner_id = owner_id,
        .arn = arn,
        .name = name,
        .tags = tags,
        .ingress = ingress,
        .egress = egress,
    };
}

// ============================================================================
// Tests
// ============================================================================

const sample =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<DescribeSecurityGroupsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
    \\  <requestId>req-1</requestId>
    \\  <securityGroupInfo>
    \\    <item>
    \\      <ownerId>123456789012</ownerId>
    \\      <groupId>sg-1</groupId>
    \\      <groupName>web</groupName>
    \\      <groupDescription>web &amp; api</groupDescription>
    \\      <vpcId>vpc-1</vpcId>
    \\      <securityGroupArn>arn:aws:ec2:us-east-1:123456789012:security-group/sg-1</securityGroupArn>
    \\      <ipPermissions>
    \\        <item>
    \\          <ipProtocol>tcp</ipProtocol>
    \\          <fromPort>443</fromPort>
    \\          <toPort>443</toPort>
    \\          <groups>
    \\            <item><groupId>sg-peer</groupId><userId>999</userId><vpcId>vpc-2</vpcId><vpcPeeringConnectionId>pcx-1</vpcPeeringConnectionId></item>
    \\          </groups>
    \\          <ipRanges><item><cidrIp>10.0.0.0/8</cidrIp><description>corp</description></item></ipRanges>
    \\          <ipv6Ranges><item><cidrIpv6>::/0</cidrIpv6></item></ipv6Ranges>
    \\          <prefixListIds><item><prefixListId>pl-1</prefixListId></item></prefixListIds>
    \\        </item>
    \\      </ipPermissions>
    \\      <ipPermissionsEgress>
    \\        <item>
    \\          <ipProtocol>-1</ipProtocol>
    \\          <groups/>
    \\          <ipRanges><item><cidrIp>0.0.0.0/0</cidrIp></item></ipRanges>
    \\          <ipv6Ranges/>
    \\          <prefixListIds/>
    \\        </item>
    \\      </ipPermissionsEgress>
    \\      <tagSet><item><key>Name</key><value>web-sg</value></item></tagSet>
    \\    </item>
    \\    <item>
    \\      <groupId>sg-2</groupId>
    \\      <groupName>default</groupName>
    \\    </item>
    \\  </securityGroupInfo>
    \\  <nextToken>TOKEN</nextToken>
    \\</DescribeSecurityGroupsResponse>
;

test "parseResponse security groups" {
    const result = try parseResponse(std.testing.allocator, sample);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 2), result.security_groups.len);
    const g = result.security_groups[0];
    try std.testing.expectEqualStrings("sg-1", g.group_id);
    try std.testing.expectEqualStrings("web", g.group_name);
    try std.testing.expectEqualStrings("web & api", g.description);
    try std.testing.expectEqualStrings("vpc-1", g.vpc_id);
    try std.testing.expectEqualStrings("web-sg", g.name);

    try std.testing.expectEqual(@as(usize, 1), g.ingress.len);
    const rule = g.ingress[0];
    try std.testing.expectEqualStrings("tcp", rule.protocol);
    try std.testing.expectEqual(@as(?i32, 443), rule.from_port);
    try std.testing.expectEqual(@as(?i32, 443), rule.to_port);
    try std.testing.expectEqual(@as(usize, 1), rule.groups.len);
    try std.testing.expectEqualStrings("sg-peer", rule.groups[0].group_id);
    try std.testing.expectEqualStrings("pcx-1", rule.groups[0].vpc_peering_connection_id);
    try std.testing.expectEqualStrings("10.0.0.0/8", rule.ipv4_ranges[0].cidr);
    try std.testing.expectEqualStrings("corp", rule.ipv4_ranges[0].description);
    try std.testing.expectEqualStrings("::/0", rule.ipv6_ranges[0].cidr);
    try std.testing.expectEqualStrings("pl-1", rule.prefix_lists[0].prefix_list_id);

    try std.testing.expectEqual(@as(usize, 1), g.egress.len);
    try std.testing.expectEqualStrings("-1", g.egress[0].protocol);
    try std.testing.expectEqual(@as(?i32, null), g.egress[0].from_port);
    try std.testing.expectEqualStrings("0.0.0.0/0", g.egress[0].ipv4_ranges[0].cidr);

    const d = result.security_groups[1];
    try std.testing.expectEqualStrings("", d.name);
    try std.testing.expectEqual(@as(usize, 0), d.ingress.len);
    try std.testing.expectEqualStrings("TOKEN", result.next_token.?);
}

test "parseResponse empty set" {
    const result = try parseResponse(
        std.testing.allocator,
        "<DescribeSecurityGroupsResponse><requestId>r</requestId><securityGroupInfo/></DescribeSecurityGroupsResponse>",
    );
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 0), result.security_groups.len);
    try std.testing.expect(result.next_token == null);
}

test "buildBody action only" {
    const body = try buildBody(std.testing.allocator, .{});
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("Action=DescribeSecurityGroups&Version=2016-11-15", body);
}

test "buildBody ids names filters and paging" {
    const body = try buildBody(std.testing.allocator, .{
        .group_ids = &.{ "sg-1", "sg-2" },
        .group_names = &.{"web"},
        .filters = &.{.{ .name = "vpc-id", .values = &.{"vpc-1"} }},
        .max_results = 5,
        .next_token = "tok/en",
    });
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings(
        "Action=DescribeSecurityGroups&Version=2016-11-15&GroupId.1=sg-1&GroupId.2=sg-2&GroupName.1=web" ++
            "&Filter.1.Name=vpc-id&Filter.1.Value.1=vpc-1" ++
            "&MaxResults=5&NextToken=tok%2Fen",
        body,
    );
}
