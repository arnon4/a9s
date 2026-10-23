const std = @import("std");
const Allocator = std.mem.Allocator;

const xml = @import("../../../utils/xml.zig");
const req = @import("../request.zig");
const vpcs = @import("vpcs.zig");

pub const Tag = vpcs.Tag;
pub const Filter = vpcs.Filter;

pub const Ec2DescribeNetworkAclsError = error{
    @"InvalidNetworkAclID.NotFound",
    @"InvalidNetworkAclId.Malformed",
    InvalidParameterValue,
    InvalidParameterCombination,
    UnauthorizedOperation,
    AuthFailure,
    RequestLimitExceeded,
};

pub const Params = struct {
    network_acl_ids: []const []const u8 = &.{},
    filters: []const Filter = &.{},
    /// 5..100
    max_results: ?u32 = null,
    next_token: ?[]const u8 = null,
};

pub const Options = struct {
    params: Params = .{},
};

pub const Association = struct {
    association_id: []u8,
    subnet_id: []u8,
};

pub const Entry = struct {
    rule_number: i32,
    /// "-1" (all), a protocol number such as "6" (TCP), "17" (UDP), "1" (ICMP), or a name.
    protocol: []u8,
    allow: bool,
    egress: bool,
    /// IPv4 CIDR; empty for IPv6 rules.
    cidr_block: []u8,
    /// IPv6 CIDR; empty for IPv4 rules.
    ipv6_cidr_block: []u8,
    /// Port range for TCP/UDP rules; null when the rule has none.
    port_from: ?u32,
    port_to: ?u32,
};

pub const NetworkAcl = struct {
    allocator: Allocator,
    network_acl_id: []u8,
    vpc_id: []u8,
    owner_id: []u8,
    is_default: bool,
    /// Value of the `Name` tag, or empty.
    name: []u8,
    tags: []Tag,
    associations: []Association,
    entries: []Entry,

    pub fn deinit(self: NetworkAcl) void {
        const a = self.allocator;
        a.free(self.network_acl_id);
        a.free(self.vpc_id);
        a.free(self.owner_id);
        a.free(self.name);
        vpcs.freeTags(a, self.tags);
        freeAssociations(a, self.associations);
        freeEntries(a, self.entries);
    }
};

pub const Result = struct {
    allocator: Allocator,
    network_acls: []NetworkAcl,
    next_token: ?[]u8,

    pub fn deinit(self: Result) void {
        for (self.network_acls) |x| x.deinit();
        self.allocator.free(self.network_acls);
        if (self.next_token) |t| self.allocator.free(t);
    }
};

fn freeAssociations(a: Allocator, items: []Association) void {
    for (items) |x| {
        a.free(x.association_id);
        a.free(x.subnet_id);
    }
    a.free(items);
}

fn freeEntryFields(a: Allocator, items: []const Entry) void {
    for (items) |x| {
        a.free(x.protocol);
        a.free(x.cidr_block);
        a.free(x.ipv6_cidr_block);
    }
}

fn freeEntries(a: Allocator, items: []Entry) void {
    freeEntryFields(a, items);
    a.free(items);
}

pub fn describeNetworkAcls(client: anytype, options: Options) !Result {
    const body = try buildBody(client.allocator, options.params);
    defer client.allocator.free(body);

    const resp = try req.send(client, Ec2DescribeNetworkAclsError, "DescribeNetworkAcls", body);
    defer client.allocator.free(resp);

    return parseResponse(client.allocator, resp);
}

fn buildBody(allocator: Allocator, params: Params) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);

    try body.appendSlice(allocator, "Action=DescribeNetworkAcls&Version=" ++ req.api_version);

    for (params.network_acl_ids, 1..) |id, n| {
        const key = try allocator.print("NetworkAclId.{d}", .{n});
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
    const root = xml.child(body, "DescribeNetworkAclsResponse") orelse return error.InvalidResponse;

    var acls: std.ArrayList(NetworkAcl) = .empty;
    errdefer {
        for (acls.items) |x| x.deinit();
        acls.deinit(allocator);
    }

    if (xml.child(root, "networkAclSet")) |set| {
        var it: xml.ChildIterator = .{ .src = set, .name = "item" };
        while (it.next()) |src| {
            const acl = try parseAcl(allocator, src);
            errdefer acl.deinit();
            try acls.append(allocator, acl);
        }
    }

    const next_token: ?[]u8 = if (xml.child(root, "nextToken")) |t|
        if (t.len > 0) try xml.unescape(allocator, t) else null
    else
        null;
    errdefer if (next_token) |t| allocator.free(t);

    return .{
        .allocator = allocator,
        .network_acls = try acls.toOwnedSlice(allocator),
        .next_token = next_token,
    };
}

fn parseAssociations(allocator: Allocator, src: []const u8) ![]Association {
    var items: std.ArrayList(Association) = .empty;
    errdefer {
        for (items.items) |x| {
            allocator.free(x.association_id);
            allocator.free(x.subnet_id);
        }
        items.deinit(allocator);
    }

    const set = xml.child(src, "associationSet") orelse return items.toOwnedSlice(allocator);
    var it: xml.ChildIterator = .{ .src = set, .name = "item" };
    while (it.next()) |item| {
        const association_id = try req.xmlStr(allocator, item, "networkAclAssociationId");
        errdefer allocator.free(association_id);
        const subnet_id = try req.xmlStr(allocator, item, "subnetId");
        errdefer allocator.free(subnet_id);
        try items.append(allocator, .{ .association_id = association_id, .subnet_id = subnet_id });
    }
    return items.toOwnedSlice(allocator);
}

fn parseOptionalUint(src: []const u8, tag: []const u8) ?u32 {
    const v = xml.child(src, tag) orelse return null;
    return std.fmt.parseInt(u32, v, 10) catch null;
}

fn parseEntries(allocator: Allocator, src: []const u8) ![]Entry {
    var items: std.ArrayList(Entry) = .empty;
    errdefer {
        freeEntryFields(allocator, items.items);
        items.deinit(allocator);
    }

    const set = xml.child(src, "entrySet") orelse return items.toOwnedSlice(allocator);
    var it: xml.ChildIterator = .{ .src = set, .name = "item" };
    while (it.next()) |item| {
        const protocol = try req.xmlStr(allocator, item, "protocol");
        errdefer allocator.free(protocol);
        const cidr_block = try req.xmlStr(allocator, item, "cidrBlock");
        errdefer allocator.free(cidr_block);
        const ipv6_cidr_block = try req.xmlStr(allocator, item, "ipv6CidrBlock");
        errdefer allocator.free(ipv6_cidr_block);

        const range = xml.child(item, "portRange") orelse "";
        const rule_number: i32 = if (xml.child(item, "ruleNumber")) |v| std.fmt.parseInt(i32, v, 10) catch 0 else 0;
        const action = xml.child(item, "ruleAction") orelse "";

        try items.append(allocator, .{
            .rule_number = rule_number,
            .protocol = protocol,
            .allow = std.mem.eql(u8, action, "allow"),
            .egress = req.xmlBool(item, "egress"),
            .cidr_block = cidr_block,
            .ipv6_cidr_block = ipv6_cidr_block,
            .port_from = parseOptionalUint(range, "from"),
            .port_to = parseOptionalUint(range, "to"),
        });
    }
    return items.toOwnedSlice(allocator);
}

fn parseAcl(allocator: Allocator, src: []const u8) !NetworkAcl {
    const network_acl_id = try req.xmlStr(allocator, src, "networkAclId");
    errdefer allocator.free(network_acl_id);
    const vpc_id = try req.xmlStr(allocator, src, "vpcId");
    errdefer allocator.free(vpc_id);
    const owner_id = try req.xmlStr(allocator, src, "ownerId");
    errdefer allocator.free(owner_id);
    const name = try vpcs.parseNameTag(allocator, src);
    errdefer allocator.free(name);
    const tags = try vpcs.parseTags(allocator, src);
    errdefer vpcs.freeTags(allocator, tags);
    const associations = try parseAssociations(allocator, src);
    errdefer freeAssociations(allocator, associations);
    const entries = try parseEntries(allocator, src);
    errdefer freeEntries(allocator, entries);

    return .{
        .allocator = allocator,
        .network_acl_id = network_acl_id,
        .vpc_id = vpc_id,
        .owner_id = owner_id,
        .is_default = req.xmlBool(src, "default"),
        .name = name,
        .tags = tags,
        .associations = associations,
        .entries = entries,
    };
}

// ============================================================================
// Tests
// ============================================================================

const sample =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<DescribeNetworkAclsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
    \\  <requestId>req-1</requestId>
    \\  <networkAclSet>
    \\    <item>
    \\      <networkAclId>acl-0abc</networkAclId>
    \\      <vpcId>vpc-1</vpcId>
    \\      <ownerId>123456789012</ownerId>
    \\      <default>false</default>
    \\      <entrySet>
    \\        <item>
    \\          <ruleNumber>100</ruleNumber>
    \\          <protocol>6</protocol>
    \\          <ruleAction>allow</ruleAction>
    \\          <egress>false</egress>
    \\          <cidrBlock>10.0.0.0/8</cidrBlock>
    \\          <portRange><from>443</from><to>443</to></portRange>
    \\        </item>
    \\        <item>
    \\          <ruleNumber>110</ruleNumber>
    \\          <protocol>-1</protocol>
    \\          <ruleAction>deny</ruleAction>
    \\          <egress>true</egress>
    \\          <cidrBlock>0.0.0.0/0</cidrBlock>
    \\        </item>
    \\        <item>
    \\          <ruleNumber>32767</ruleNumber>
    \\          <protocol>-1</protocol>
    \\          <ruleAction>deny</ruleAction>
    \\          <egress>false</egress>
    \\          <ipv6CidrBlock>::/0</ipv6CidrBlock>
    \\        </item>
    \\      </entrySet>
    \\      <associationSet>
    \\        <item>
    \\          <networkAclAssociationId>aclassoc-1</networkAclAssociationId>
    \\          <networkAclId>acl-0abc</networkAclId>
    \\          <subnetId>subnet-1</subnetId>
    \\        </item>
    \\      </associationSet>
    \\      <tagSet><item><key>Name</key><value>locked &amp; down</value></item></tagSet>
    \\    </item>
    \\    <item>
    \\      <networkAclId>acl-default</networkAclId>
    \\      <default>true</default>
    \\      <entrySet/>
    \\      <associationSet/>
    \\    </item>
    \\  </networkAclSet>
    \\  <nextToken>TOKEN</nextToken>
    \\</DescribeNetworkAclsResponse>
;

test "parseResponse network acls" {
    const result = try parseResponse(std.testing.allocator, sample);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 2), result.network_acls.len);
    const acl = result.network_acls[0];
    try std.testing.expectEqualStrings("acl-0abc", acl.network_acl_id);
    try std.testing.expectEqualStrings("vpc-1", acl.vpc_id);
    try std.testing.expectEqualStrings("locked & down", acl.name);
    try std.testing.expect(!acl.is_default);
    try std.testing.expectEqual(@as(usize, 1), acl.associations.len);
    try std.testing.expectEqualStrings("subnet-1", acl.associations[0].subnet_id);

    try std.testing.expectEqual(@as(usize, 3), acl.entries.len);
    const allow = acl.entries[0];
    try std.testing.expectEqual(@as(i32, 100), allow.rule_number);
    try std.testing.expectEqualStrings("6", allow.protocol);
    try std.testing.expect(allow.allow);
    try std.testing.expect(!allow.egress);
    try std.testing.expectEqualStrings("10.0.0.0/8", allow.cidr_block);
    try std.testing.expectEqual(@as(?u32, 443), allow.port_from);
    try std.testing.expectEqual(@as(?u32, 443), allow.port_to);

    const deny = acl.entries[1];
    try std.testing.expect(!deny.allow);
    try std.testing.expect(deny.egress);
    try std.testing.expectEqual(@as(?u32, null), deny.port_from);

    const v6 = acl.entries[2];
    try std.testing.expectEqualStrings("", v6.cidr_block);
    try std.testing.expectEqualStrings("::/0", v6.ipv6_cidr_block);

    try std.testing.expect(result.network_acls[1].is_default);
    try std.testing.expectEqualStrings("TOKEN", result.next_token.?);
}

test "parseResponse empty set" {
    const result = try parseResponse(
        std.testing.allocator,
        "<DescribeNetworkAclsResponse><requestId>r</requestId><networkAclSet/></DescribeNetworkAclsResponse>",
    );
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 0), result.network_acls.len);
    try std.testing.expect(result.next_token == null);
}

test "buildBody action only" {
    const body = try buildBody(std.testing.allocator, .{});
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("Action=DescribeNetworkAcls&Version=2016-11-15", body);
}

test "buildBody ids filters and paging" {
    const body = try buildBody(std.testing.allocator, .{
        .network_acl_ids = &.{ "acl-1", "acl-2" },
        .filters = &.{.{ .name = "vpc-id", .values = &.{"vpc-1"} }},
        .max_results = 5,
        .next_token = "tok/en",
    });
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings(
        "Action=DescribeNetworkAcls&Version=2016-11-15&NetworkAclId.1=acl-1&NetworkAclId.2=acl-2" ++
            "&Filter.1.Name=vpc-id&Filter.1.Value.1=vpc-1" ++
            "&MaxResults=5&NextToken=tok%2Fen",
        body,
    );
}
