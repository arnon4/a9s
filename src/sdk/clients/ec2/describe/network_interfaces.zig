const std = @import("std");
const Allocator = std.mem.Allocator;

const xml = @import("../../../utils/xml.zig");
const req = @import("../request.zig");
const vpcs = @import("vpcs.zig");
const paging = @import("paging.zig");

pub const Tag = vpcs.Tag;
pub const Filter = vpcs.Filter;

pub const Ec2DescribeNetworkInterfacesError = error{
    @"InvalidNetworkInterfaceID.NotFound",
    @"InvalidNetworkInterfaceId.Malformed",
    InvalidParameterValue,
    InvalidParameterCombination,
    UnauthorizedOperation,
    AuthFailure,
    RequestLimitExceeded,
};

pub const Params = struct {
    network_interface_ids: []const []const u8 = &.{},
    filters: []const Filter = &.{},
    /// 5..1000. EC2 rejects it together with `network_interface_ids`.
    max_results: ?u32 = null,
    next_token: ?[]const u8 = null,
};

pub const Options = struct {
    params: Params = .{},
};

pub const Group = struct {
    group_id: []u8,
    group_name: []u8,
};

pub const Attachment = struct {
    attachment_id: []u8,
    /// Empty when the interface is attached to something other than an instance.
    instance_id: []u8,
    instance_owner_id: []u8,
    device_index: ?i32,
    /// attaching | attached | detaching | detached
    status: []u8,
    attach_time: []u8,
    delete_on_termination: bool,

    pub fn deinit(self: Attachment, a: Allocator) void {
        a.free(self.attachment_id);
        a.free(self.instance_id);
        a.free(self.instance_owner_id);
        a.free(self.status);
        a.free(self.attach_time);
    }
};

pub const PrivateIp = struct {
    private_ip: []u8,
    private_dns_name: []u8,
    primary: bool,
    /// Elastic IP associated with this private address; empty when none.
    public_ip: []u8,
};

pub const NetworkInterface = struct {
    allocator: Allocator,
    id: []u8,
    subnet_id: []u8,
    vpc_id: []u8,
    availability_zone: []u8,
    description: []u8,
    owner_id: []u8,
    requester_id: []u8,
    /// True for interfaces created by an AWS service (load balancers, endpoints, Lambda, ...).
    requester_managed: bool,
    /// available | associated | attaching | in-use | detaching
    status: []u8,
    mac_address: []u8,
    private_ip: []u8,
    private_dns_name: []u8,
    /// Public IP of the interface's primary association; empty when none.
    public_ip: []u8,
    allocation_id: []u8,
    source_dest_check: bool,
    /// interface | natGateway | vpc_endpoint | network_load_balancer | lambda | ...
    interface_type: []u8,
    /// Value of the `Name` tag, or empty.
    name: []u8,
    tags: []Tag,
    groups: []Group,
    attachment: ?Attachment,
    private_ips: []PrivateIp,
    ipv6_addresses: [][]u8,

    pub fn deinit(self: NetworkInterface) void {
        const a = self.allocator;
        a.free(self.id);
        a.free(self.subnet_id);
        a.free(self.vpc_id);
        a.free(self.availability_zone);
        a.free(self.description);
        a.free(self.owner_id);
        a.free(self.requester_id);
        a.free(self.status);
        a.free(self.mac_address);
        a.free(self.private_ip);
        a.free(self.private_dns_name);
        a.free(self.public_ip);
        a.free(self.allocation_id);
        a.free(self.interface_type);
        a.free(self.name);
        vpcs.freeTags(a, self.tags);
        freeGroups(a, self.groups);
        if (self.attachment) |at| at.deinit(a);
        freePrivateIps(a, self.private_ips);
        for (self.ipv6_addresses) |x| a.free(x);
        a.free(self.ipv6_addresses);
    }
};

pub const Result = struct {
    allocator: Allocator,
    network_interfaces: []NetworkInterface,
    next_token: ?[]u8,

    pub fn deinit(self: Result) void {
        for (self.network_interfaces) |x| x.deinit();
        self.allocator.free(self.network_interfaces);
        if (self.next_token) |t| self.allocator.free(t);
    }
};

pub fn freeGroups(a: Allocator, items: []Group) void {
    for (items) |g| {
        a.free(g.group_id);
        a.free(g.group_name);
    }
    a.free(items);
}

fn freePrivateIpFields(a: Allocator, x: PrivateIp) void {
    a.free(x.private_ip);
    a.free(x.private_dns_name);
    a.free(x.public_ip);
}

fn freePrivateIps(a: Allocator, items: []PrivateIp) void {
    for (items) |x| freePrivateIpFields(a, x);
    a.free(items);
}

/// One page of results.
pub fn describeNetworkInterfaces(client: anytype, options: Options) !Result {
    const body = try buildBody(client.allocator, options.params);
    defer client.allocator.free(body);

    const resp = try req.send(client, Ec2DescribeNetworkInterfacesError, "DescribeNetworkInterfaces", body);
    defer client.allocator.free(resp);

    return parseResponse(client.allocator, resp);
}

/// Every page of results, fetched by following `NextToken`. The result has no `next_token`.
pub fn describeAllNetworkInterfaces(client: anytype, options: Options) !Result {
    const Client = @TypeOf(client);
    const Fetch = struct {
        fn page(c: Client, params: Params) anyerror!Result {
            return describeNetworkInterfaces(c, .{ .params = params });
        }
    };
    return collectPages(client.allocator, Client, client, options.params, Fetch.page);
}

/// Calls `fetch` until it stops returning a token and merges the pages.
/// With explicit IDs EC2 forbids `MaxResults`, so the page size is only set without them.
fn collectPages(
    allocator: Allocator,
    comptime Ctx: type,
    ctx: Ctx,
    params: Params,
    comptime fetch: fn (Ctx, Params) anyerror!Result,
) !Result {
    var page_params = params;
    if (page_params.max_results == null and page_params.network_interface_ids.len == 0) page_params.max_results = 1000;
    return paging.collect(NetworkInterface, Result, "network_interfaces", allocator, Ctx, ctx, page_params, fetch);
}

fn buildBody(allocator: Allocator, params: Params) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);

    try body.appendSlice(allocator, "Action=DescribeNetworkInterfaces&Version=" ++ req.api_version);

    for (params.network_interface_ids, 1..) |id, n| {
        const key = try allocator.print("NetworkInterfaceId.{d}", .{n});
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
    const root = xml.child(body, "DescribeNetworkInterfacesResponse") orelse return error.InvalidResponse;

    var items: std.ArrayList(NetworkInterface) = .empty;
    errdefer {
        for (items.items) |x| x.deinit();
        items.deinit(allocator);
    }

    if (xml.child(root, "networkInterfaceSet")) |set| {
        var it: xml.ChildIterator = .{ .src = set, .name = "item" };
        while (it.next()) |src| {
            const parsed = try parseInterface(allocator, src);
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
        .network_interfaces = try items.toOwnedSlice(allocator),
        .next_token = next_token,
    };
}

pub fn parseGroups(allocator: Allocator, src: []const u8) ![]Group {
    var items: std.ArrayList(Group) = .empty;
    errdefer {
        for (items.items) |g| {
            allocator.free(g.group_id);
            allocator.free(g.group_name);
        }
        items.deinit(allocator);
    }

    const set = xml.child(src, "groupSet") orelse return items.toOwnedSlice(allocator);
    var it: xml.ChildIterator = .{ .src = set, .name = "item" };
    while (it.next()) |item| {
        const group_id = try req.xmlStr(allocator, item, "groupId");
        errdefer allocator.free(group_id);
        const group_name = try req.xmlStr(allocator, item, "groupName");
        errdefer allocator.free(group_name);
        try items.append(allocator, .{ .group_id = group_id, .group_name = group_name });
    }
    return items.toOwnedSlice(allocator);
}

/// Parses an `<attachment>` element body.
pub fn parseAttachment(allocator: Allocator, src: []const u8) !Attachment {
    const attachment_id = try req.xmlStr(allocator, src, "attachmentId");
    errdefer allocator.free(attachment_id);
    const instance_id = try req.xmlStr(allocator, src, "instanceId");
    errdefer allocator.free(instance_id);
    const instance_owner_id = try req.xmlStr(allocator, src, "instanceOwnerId");
    errdefer allocator.free(instance_owner_id);
    const status = try req.xmlStr(allocator, src, "status");
    errdefer allocator.free(status);
    const attach_time = try req.xmlStr(allocator, src, "attachTime");
    errdefer allocator.free(attach_time);

    const device_index: ?i32 = if (xml.child(src, "deviceIndex")) |v| std.fmt.parseInt(i32, v, 10) catch null else null;

    return .{
        .attachment_id = attachment_id,
        .instance_id = instance_id,
        .instance_owner_id = instance_owner_id,
        .device_index = device_index,
        .status = status,
        .attach_time = attach_time,
        .delete_on_termination = req.xmlBool(src, "deleteOnTermination"),
    };
}

fn parsePrivateIps(allocator: Allocator, src: []const u8) ![]PrivateIp {
    var items: std.ArrayList(PrivateIp) = .empty;
    errdefer {
        for (items.items) |x| freePrivateIpFields(allocator, x);
        items.deinit(allocator);
    }

    const set = xml.child(src, "privateIpAddressesSet") orelse return items.toOwnedSlice(allocator);
    var it: xml.ChildIterator = .{ .src = set, .name = "item" };
    while (it.next()) |item| {
        const private_ip = try req.xmlStr(allocator, item, "privateIpAddress");
        errdefer allocator.free(private_ip);
        const dns = try req.xmlStr(allocator, item, "privateDnsName");
        errdefer allocator.free(dns);
        const public_ip = try req.xmlNested(allocator, item, "association", "publicIp");
        errdefer allocator.free(public_ip);
        try items.append(allocator, .{
            .private_ip = private_ip,
            .private_dns_name = dns,
            .primary = req.xmlBool(item, "primary"),
            .public_ip = public_ip,
        });
    }
    return items.toOwnedSlice(allocator);
}

fn parseIpv6(allocator: Allocator, src: []const u8) ![][]u8 {
    var items: std.ArrayList([]u8) = .empty;
    errdefer {
        for (items.items) |x| allocator.free(x);
        items.deinit(allocator);
    }

    const set = xml.child(src, "ipv6AddressesSet") orelse return items.toOwnedSlice(allocator);
    var it: xml.ChildIterator = .{ .src = set, .name = "item" };
    while (it.next()) |item| {
        const addr = try req.xmlStr(allocator, item, "ipv6Address");
        errdefer allocator.free(addr);
        try items.append(allocator, addr);
    }
    return items.toOwnedSlice(allocator);
}

fn parseInterface(allocator: Allocator, src: []const u8) !NetworkInterface {
    const id = try req.xmlStr(allocator, src, "networkInterfaceId");
    errdefer allocator.free(id);
    const subnet_id = try req.xmlStr(allocator, src, "subnetId");
    errdefer allocator.free(subnet_id);
    const vpc_id = try req.xmlStr(allocator, src, "vpcId");
    errdefer allocator.free(vpc_id);
    const availability_zone = try req.xmlStr(allocator, src, "availabilityZone");
    errdefer allocator.free(availability_zone);
    const description = try req.xmlStr(allocator, src, "description");
    errdefer allocator.free(description);
    const owner_id = try req.xmlStr(allocator, src, "ownerId");
    errdefer allocator.free(owner_id);
    const requester_id = try req.xmlStr(allocator, src, "requesterId");
    errdefer allocator.free(requester_id);
    const status = try req.xmlStr(allocator, src, "status");
    errdefer allocator.free(status);
    const mac_address = try req.xmlStr(allocator, src, "macAddress");
    errdefer allocator.free(mac_address);
    const private_ip = try req.xmlStr(allocator, src, "privateIpAddress");
    errdefer allocator.free(private_ip);
    const private_dns_name = try req.xmlStr(allocator, src, "privateDnsName");
    errdefer allocator.free(private_dns_name);
    const public_ip = try req.xmlNested(allocator, src, "association", "publicIp");
    errdefer allocator.free(public_ip);
    const allocation_id = try req.xmlNested(allocator, src, "association", "allocationId");
    errdefer allocator.free(allocation_id);
    const interface_type = try req.xmlStr(allocator, src, "interfaceType");
    errdefer allocator.free(interface_type);
    const name = try vpcs.parseNameTag(allocator, src);
    errdefer allocator.free(name);
    const tags = try vpcs.parseTags(allocator, src);
    errdefer vpcs.freeTags(allocator, tags);
    const groups = try parseGroups(allocator, src);
    errdefer freeGroups(allocator, groups);

    var attachment: ?Attachment = null;
    if (xml.child(src, "attachment")) |block| {
        if (block.len > 0) attachment = try parseAttachment(allocator, block);
    }
    errdefer if (attachment) |at| at.deinit(allocator);

    const private_ips = try parsePrivateIps(allocator, src);
    errdefer freePrivateIps(allocator, private_ips);
    const ipv6_addresses = try parseIpv6(allocator, src);
    errdefer {
        for (ipv6_addresses) |x| allocator.free(x);
        allocator.free(ipv6_addresses);
    }

    // sourceDestCheck defaults to true when the element is missing.
    const source_dest_check = if (xml.child(src, "sourceDestCheck")) |v| std.mem.eql(u8, v, "true") else true;

    return .{
        .allocator = allocator,
        .id = id,
        .subnet_id = subnet_id,
        .vpc_id = vpc_id,
        .availability_zone = availability_zone,
        .description = description,
        .owner_id = owner_id,
        .requester_id = requester_id,
        .requester_managed = req.xmlBool(src, "requesterManaged"),
        .status = status,
        .mac_address = mac_address,
        .private_ip = private_ip,
        .private_dns_name = private_dns_name,
        .public_ip = public_ip,
        .allocation_id = allocation_id,
        .source_dest_check = source_dest_check,
        .interface_type = interface_type,
        .name = name,
        .tags = tags,
        .groups = groups,
        .attachment = attachment,
        .private_ips = private_ips,
        .ipv6_addresses = ipv6_addresses,
    };
}

// ============================================================================
// Tests
// ============================================================================

const sample =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<DescribeNetworkInterfacesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
    \\  <requestId>req-1</requestId>
    \\  <networkInterfaceSet>
    \\    <item>
    \\      <networkInterfaceId>eni-0abc</networkInterfaceId>
    \\      <subnetId>subnet-1</subnetId>
    \\      <vpcId>vpc-1</vpcId>
    \\      <availabilityZone>us-east-1a</availabilityZone>
    \\      <description>Primary &amp; only</description>
    \\      <ownerId>123456789012</ownerId>
    \\      <requesterManaged>false</requesterManaged>
    \\      <status>in-use</status>
    \\      <macAddress>0a:1b:2c:3d:4e:5f</macAddress>
    \\      <privateIpAddress>10.0.1.10</privateIpAddress>
    \\      <privateDnsName>ip-10-0-1-10.ec2.internal</privateDnsName>
    \\      <sourceDestCheck>false</sourceDestCheck>
    \\      <interfaceType>interface</interfaceType>
    \\      <groupSet>
    \\        <item><groupId>sg-1</groupId><groupName>web</groupName></item>
    \\        <item><groupId>sg-2</groupId><groupName>ssh</groupName></item>
    \\      </groupSet>
    \\      <attachment>
    \\        <attachmentId>eni-attach-1</attachmentId>
    \\        <instanceId>i-0123</instanceId>
    \\        <instanceOwnerId>123456789012</instanceOwnerId>
    \\        <deviceIndex>0</deviceIndex>
    \\        <status>attached</status>
    \\        <attachTime>2026-01-02T03:04:05.000Z</attachTime>
    \\        <deleteOnTermination>true</deleteOnTermination>
    \\      </attachment>
    \\      <association>
    \\        <publicIp>203.0.113.7</publicIp>
    \\        <allocationId>eipalloc-1</allocationId>
    \\      </association>
    \\      <privateIpAddressesSet>
    \\        <item>
    \\          <privateIpAddress>10.0.1.10</privateIpAddress>
    \\          <primary>true</primary>
    \\          <association><publicIp>203.0.113.7</publicIp></association>
    \\        </item>
    \\        <item><privateIpAddress>10.0.1.11</privateIpAddress><primary>false</primary></item>
    \\      </privateIpAddressesSet>
    \\      <ipv6AddressesSet><item><ipv6Address>2600:1f18::10</ipv6Address></item></ipv6AddressesSet>
    \\      <tagSet><item><key>Name</key><value>web-eni</value></item></tagSet>
    \\    </item>
    \\    <item>
    \\      <networkInterfaceId>eni-bare</networkInterfaceId>
    \\      <status>available</status>
    \\      <requesterManaged>true</requesterManaged>
    \\      <interfaceType>natGateway</interfaceType>
    \\    </item>
    \\  </networkInterfaceSet>
    \\  <nextToken>TOKEN</nextToken>
    \\</DescribeNetworkInterfacesResponse>
;

test "parseResponse network interfaces" {
    const result = try parseResponse(std.testing.allocator, sample);
    defer result.deinit();

    const items = result.network_interfaces;
    try std.testing.expectEqual(@as(usize, 2), items.len);
    const e = items[0];
    try std.testing.expectEqualStrings("eni-0abc", e.id);
    try std.testing.expectEqualStrings("subnet-1", e.subnet_id);
    try std.testing.expectEqualStrings("vpc-1", e.vpc_id);
    try std.testing.expectEqualStrings("us-east-1a", e.availability_zone);
    try std.testing.expectEqualStrings("Primary & only", e.description);
    try std.testing.expectEqualStrings("in-use", e.status);
    try std.testing.expectEqualStrings("10.0.1.10", e.private_ip);
    try std.testing.expectEqualStrings("203.0.113.7", e.public_ip);
    try std.testing.expectEqualStrings("eipalloc-1", e.allocation_id);
    try std.testing.expect(!e.source_dest_check);
    try std.testing.expect(!e.requester_managed);
    try std.testing.expectEqualStrings("web-eni", e.name);

    try std.testing.expectEqual(@as(usize, 2), e.groups.len);
    try std.testing.expectEqualStrings("sg-1", e.groups[0].group_id);
    try std.testing.expectEqualStrings("ssh", e.groups[1].group_name);

    const at = e.attachment.?;
    try std.testing.expectEqualStrings("i-0123", at.instance_id);
    try std.testing.expectEqual(@as(?i32, 0), at.device_index);
    try std.testing.expectEqualStrings("attached", at.status);
    try std.testing.expect(at.delete_on_termination);

    try std.testing.expectEqual(@as(usize, 2), e.private_ips.len);
    try std.testing.expect(e.private_ips[0].primary);
    try std.testing.expectEqualStrings("203.0.113.7", e.private_ips[0].public_ip);
    try std.testing.expectEqualStrings("", e.private_ips[1].public_ip);
    try std.testing.expectEqual(@as(usize, 1), e.ipv6_addresses.len);
    try std.testing.expectEqualStrings("2600:1f18::10", e.ipv6_addresses[0]);

    const b = items[1];
    try std.testing.expectEqualStrings("available", b.status);
    try std.testing.expect(b.requester_managed);
    try std.testing.expectEqualStrings("natGateway", b.interface_type);
    try std.testing.expect(b.attachment == null);
    try std.testing.expect(b.source_dest_check);
    try std.testing.expectEqual(@as(usize, 0), b.groups.len);
    try std.testing.expectEqualStrings("TOKEN", result.next_token.?);
}

test "parseResponse empty set" {
    const result = try parseResponse(
        std.testing.allocator,
        "<DescribeNetworkInterfacesResponse><requestId>r</requestId><networkInterfaceSet/></DescribeNetworkInterfacesResponse>",
    );
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 0), result.network_interfaces.len);
    try std.testing.expect(result.next_token == null);
}

test "buildBody action only" {
    const body = try buildBody(std.testing.allocator, .{});
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("Action=DescribeNetworkInterfaces&Version=2016-11-15", body);
}

test "buildBody ids filters and paging" {
    const body = try buildBody(std.testing.allocator, .{
        .network_interface_ids = &.{ "eni-1", "eni-2" },
        .filters = &.{.{ .name = "vpc-id", .values = &.{"vpc-1"} }},
        .max_results = 5,
        .next_token = "tok/en",
    });
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings(
        "Action=DescribeNetworkInterfaces&Version=2016-11-15&NetworkInterfaceId.1=eni-1&NetworkInterfaceId.2=eni-2" ++
            "&Filter.1.Name=vpc-id&Filter.1.Value.1=vpc-1" ++
            "&MaxResults=5&NextToken=tok%2Fen",
        body,
    );
}

/// Serves canned pages and records the parameters it was called with.
const FakePages = struct {
    pages: []const []const u8,
    calls: usize = 0,
    /// Tokens are copied: the SDK frees each one as soon as the next page arrives.
    token_bufs: [4][16]u8 = undefined,
    token_lens: [4]?usize = @splat(null),
    seen_max: [4]?u32 = @splat(null),

    fn seenToken(self: *const FakePages, call: usize) ?[]const u8 {
        const n = self.token_lens[call] orelse return null;
        return self.token_bufs[call][0..n];
    }

    fn fetch(self: *FakePages, params: Params) anyerror!Result {
        if (params.next_token) |t| {
            @memcpy(self.token_bufs[self.calls][0..t.len], t);
            self.token_lens[self.calls] = t.len;
        }
        self.seen_max[self.calls] = params.max_results;
        const body = self.pages[self.calls];
        self.calls += 1;
        return parseResponse(std.testing.allocator, body);
    }
};

fn pageXml(comptime id: []const u8, comptime token: ?[]const u8) []const u8 {
    return "<DescribeNetworkInterfacesResponse><networkInterfaceSet><item><networkInterfaceId>" ++ id ++
        "</networkInterfaceId></item></networkInterfaceSet>" ++
        (if (token) |t| "<nextToken>" ++ t ++ "</nextToken>" else "") ++
        "</DescribeNetworkInterfacesResponse>";
}

test "collectPages follows tokens, merges pages and sets the page size" {
    var fake: FakePages = .{ .pages = &.{ pageXml("eni-1", "T1"), pageXml("eni-2", "T2"), pageXml("eni-3", null) } };
    const result = try collectPages(std.testing.allocator, *FakePages, &fake, .{}, FakePages.fetch);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 3), fake.calls);
    try std.testing.expectEqual(@as(usize, 3), result.network_interfaces.len);
    try std.testing.expectEqualStrings("eni-1", result.network_interfaces[0].id);
    try std.testing.expectEqualStrings("eni-2", result.network_interfaces[1].id);
    try std.testing.expectEqualStrings("eni-3", result.network_interfaces[2].id);
    try std.testing.expect(result.next_token == null);

    try std.testing.expect(fake.seenToken(0) == null);
    try std.testing.expectEqual(@as(?u32, 1000), fake.seen_max[0]);
    try std.testing.expectEqualStrings("T1", fake.seenToken(1).?);
    try std.testing.expectEqualStrings("T2", fake.seenToken(2).?);
}

test "collectPages omits the page size when IDs are given" {
    var fake: FakePages = .{ .pages = &.{pageXml("eni-1", null)} };
    const result = try collectPages(std.testing.allocator, *FakePages, &fake, .{ .network_interface_ids = &.{"eni-1"} }, FakePages.fetch);
    defer result.deinit();
    try std.testing.expectEqual(@as(?u32, null), fake.seen_max[0]);
}

test "collectPages stops on an error without leaking earlier pages" {
    const Failing = struct {
        calls: usize = 0,

        fn fetch(self: *@This(), _: Params) anyerror!Result {
            self.calls += 1;
            if (self.calls == 2) return error.RequestLimitExceeded;
            return parseResponse(std.testing.allocator, pageXml("eni-1", "T1"));
        }
    };
    var failing: Failing = .{};
    try std.testing.expectError(
        error.RequestLimitExceeded,
        collectPages(std.testing.allocator, *Failing, &failing, .{}, Failing.fetch),
    );
}
