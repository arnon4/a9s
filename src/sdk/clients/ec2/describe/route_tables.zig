const std = @import("std");
const Allocator = std.mem.Allocator;

const xml = @import("../../../utils/xml.zig");
const req = @import("../request.zig");
const vpcs = @import("vpcs.zig");

pub const Tag = vpcs.Tag;
pub const Filter = vpcs.Filter;

pub const Ec2DescribeRouteTablesError = error{
    @"InvalidRouteTableID.NotFound",
    @"InvalidRouteTableId.Malformed",
    InvalidParameterValue,
    InvalidParameterCombination,
    UnauthorizedOperation,
    AuthFailure,
    RequestLimitExceeded,
};

pub const Params = struct {
    route_table_ids: []const []const u8 = &.{},
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
    /// True for the VPC's main route table association.
    main: bool,
    /// Empty unless associated with a subnet.
    subnet_id: []u8,
    /// Empty unless associated with a gateway.
    gateway_id: []u8,
    state: []u8,
};

pub const Route = struct {
    /// IPv4 CIDR, IPv6 CIDR or prefix list ID.
    destination: []u8,
    /// First populated target field (gateway, NAT, peering, ...); empty when none.
    target: []u8,
    state: []u8,
    origin: []u8,
};

pub const RouteTable = struct {
    allocator: Allocator,
    route_table_id: []u8,
    vpc_id: []u8,
    owner_id: []u8,
    /// Value of the `Name` tag, or empty.
    name: []u8,
    tags: []Tag,
    associations: []Association,
    routes: []Route,
    /// Virtual private gateways propagating routes into this table.
    propagating_vgws: [][]u8,

    pub fn deinit(self: RouteTable) void {
        const a = self.allocator;
        a.free(self.route_table_id);
        a.free(self.vpc_id);
        a.free(self.owner_id);
        a.free(self.name);
        vpcs.freeTags(a, self.tags);
        freeAssociations(a, self.associations);
        freeRoutes(a, self.routes);
        for (self.propagating_vgws) |g| a.free(g);
        a.free(self.propagating_vgws);
    }

    /// True when the table is the VPC's main route table.
    pub fn isMain(self: RouteTable) bool {
        for (self.associations) |assoc| if (assoc.main) return true;
        return false;
    }
};

pub const Result = struct {
    allocator: Allocator,
    route_tables: []RouteTable,
    next_token: ?[]u8,

    pub fn deinit(self: Result) void {
        for (self.route_tables) |t| t.deinit();
        self.allocator.free(self.route_tables);
        if (self.next_token) |t| self.allocator.free(t);
    }
};

fn freeAssociations(a: Allocator, items: []Association) void {
    for (items) |x| {
        a.free(x.association_id);
        a.free(x.subnet_id);
        a.free(x.gateway_id);
        a.free(x.state);
    }
    a.free(items);
}

fn freeRoutes(a: Allocator, items: []Route) void {
    for (items) |x| {
        a.free(x.destination);
        a.free(x.target);
        a.free(x.state);
        a.free(x.origin);
    }
    a.free(items);
}

pub fn describeRouteTables(client: anytype, options: Options) !Result {
    const body = try buildBody(client.allocator, options.params);
    defer client.allocator.free(body);

    const resp = try req.send(client, Ec2DescribeRouteTablesError, "DescribeRouteTables", body);
    defer client.allocator.free(resp);

    return parseResponse(client.allocator, resp);
}

fn buildBody(allocator: Allocator, params: Params) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);

    try body.appendSlice(allocator, "Action=DescribeRouteTables&Version=" ++ req.api_version);

    for (params.route_table_ids, 1..) |id, n| {
        const key = try allocator.print("RouteTableId.{d}", .{n});
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
    const root = xml.child(body, "DescribeRouteTablesResponse") orelse return error.InvalidResponse;

    var tables: std.ArrayList(RouteTable) = .empty;
    errdefer {
        for (tables.items) |t| t.deinit();
        tables.deinit(allocator);
    }

    if (xml.child(root, "routeTableSet")) |set| {
        var it: xml.ChildIterator = .{ .src = set, .name = "item" };
        while (it.next()) |item| {
            const table = try parseRouteTable(allocator, item);
            errdefer table.deinit();
            try tables.append(allocator, table);
        }
    }

    const next_token: ?[]u8 = if (xml.child(root, "nextToken")) |t|
        if (t.len > 0) try xml.unescape(allocator, t) else null
    else
        null;
    errdefer if (next_token) |t| allocator.free(t);

    return .{
        .allocator = allocator,
        .route_tables = try tables.toOwnedSlice(allocator),
        .next_token = next_token,
    };
}

const target_tags = [_][]const u8{
    "gatewayId",
    "natGatewayId",
    "transitGatewayId",
    "vpcPeeringConnectionId",
    "networkInterfaceId",
    "instanceId",
    "egressOnlyInternetGatewayId",
    "carrierGatewayId",
    "localGatewayId",
    "coreNetworkArn",
};

const destination_tags = [_][]const u8{
    "destinationCidrBlock",
    "destinationIpv6CidrBlock",
    "destinationPrefixListId",
};

/// Unescaped copy of the first non-empty child among `tags`, or an empty string.
fn firstOf(allocator: Allocator, src: []const u8, tags: []const []const u8) ![]u8 {
    for (tags) |tag| {
        if (xml.child(src, tag)) |v| {
            if (v.len > 0) return xml.unescape(allocator, v);
        }
    }
    return allocator.dupe(u8, "");
}

fn parseRoutes(allocator: Allocator, src: []const u8) ![]Route {
    var routes: std.ArrayList(Route) = .empty;
    errdefer {
        freeRoutesList(allocator, routes.items);
        routes.deinit(allocator);
    }

    const set = xml.child(src, "routeSet") orelse return routes.toOwnedSlice(allocator);
    var it: xml.ChildIterator = .{ .src = set, .name = "item" };
    while (it.next()) |item| {
        const destination = try firstOf(allocator, item, &destination_tags);
        errdefer allocator.free(destination);
        const target = try firstOf(allocator, item, &target_tags);
        errdefer allocator.free(target);
        const state = try req.xmlStr(allocator, item, "state");
        errdefer allocator.free(state);
        const origin = try req.xmlStr(allocator, item, "origin");
        errdefer allocator.free(origin);
        try routes.append(allocator, .{ .destination = destination, .target = target, .state = state, .origin = origin });
    }
    return routes.toOwnedSlice(allocator);
}

fn freeRoutesList(a: Allocator, items: []Route) void {
    for (items) |x| {
        a.free(x.destination);
        a.free(x.target);
        a.free(x.state);
        a.free(x.origin);
    }
}

fn parseAssociations(allocator: Allocator, src: []const u8) ![]Association {
    var items: std.ArrayList(Association) = .empty;
    errdefer {
        for (items.items) |x| {
            allocator.free(x.association_id);
            allocator.free(x.subnet_id);
            allocator.free(x.gateway_id);
            allocator.free(x.state);
        }
        items.deinit(allocator);
    }

    const set = xml.child(src, "associationSet") orelse return items.toOwnedSlice(allocator);
    var it: xml.ChildIterator = .{ .src = set, .name = "item" };
    while (it.next()) |item| {
        const association_id = try req.xmlStr(allocator, item, "routeTableAssociationId");
        errdefer allocator.free(association_id);
        const subnet_id = try req.xmlStr(allocator, item, "subnetId");
        errdefer allocator.free(subnet_id);
        const gateway_id = try req.xmlStr(allocator, item, "gatewayId");
        errdefer allocator.free(gateway_id);
        const state_block = xml.child(item, "associationState") orelse "";
        const state = try req.xmlStr(allocator, state_block, "state");
        errdefer allocator.free(state);
        try items.append(allocator, .{
            .association_id = association_id,
            .main = req.xmlBool(item, "main"),
            .subnet_id = subnet_id,
            .gateway_id = gateway_id,
            .state = state,
        });
    }
    return items.toOwnedSlice(allocator);
}

fn parsePropagatingVgws(allocator: Allocator, src: []const u8) ![][]u8 {
    var items: std.ArrayList([]u8) = .empty;
    errdefer {
        for (items.items) |g| allocator.free(g);
        items.deinit(allocator);
    }

    const set = xml.child(src, "propagatingVgwSet") orelse return items.toOwnedSlice(allocator);
    var it: xml.ChildIterator = .{ .src = set, .name = "item" };
    while (it.next()) |item| {
        const id = try req.xmlStr(allocator, item, "gatewayId");
        errdefer allocator.free(id);
        try items.append(allocator, id);
    }
    return items.toOwnedSlice(allocator);
}

fn parseRouteTable(allocator: Allocator, src: []const u8) !RouteTable {
    const route_table_id = try req.xmlStr(allocator, src, "routeTableId");
    errdefer allocator.free(route_table_id);
    const vpc_id = try req.xmlStr(allocator, src, "vpcId");
    errdefer allocator.free(vpc_id);
    const owner_id = try req.xmlStr(allocator, src, "ownerId");
    errdefer allocator.free(owner_id);

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

    const associations = try parseAssociations(allocator, src);
    errdefer freeAssociations(allocator, associations);
    const routes = try parseRoutes(allocator, src);
    errdefer freeRoutes(allocator, routes);
    const vgws = try parsePropagatingVgws(allocator, src);
    errdefer {
        for (vgws) |g| allocator.free(g);
        allocator.free(vgws);
    }

    return .{
        .allocator = allocator,
        .route_table_id = route_table_id,
        .vpc_id = vpc_id,
        .owner_id = owner_id,
        .name = name,
        .tags = tags,
        .associations = associations,
        .routes = routes,
        .propagating_vgws = vgws,
    };
}

// ============================================================================
// Tests
// ============================================================================

const sample =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<DescribeRouteTablesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
    \\  <requestId>req-1</requestId>
    \\  <routeTableSet>
    \\    <item>
    \\      <routeTableId>rtb-0abc</routeTableId>
    \\      <vpcId>vpc-0abc</vpcId>
    \\      <ownerId>123456789012</ownerId>
    \\      <routeSet>
    \\        <item>
    \\          <destinationCidrBlock>10.0.0.0/16</destinationCidrBlock>
    \\          <gatewayId>local</gatewayId>
    \\          <state>active</state>
    \\          <origin>CreateRouteTable</origin>
    \\        </item>
    \\        <item>
    \\          <destinationCidrBlock>0.0.0.0/0</destinationCidrBlock>
    \\          <natGatewayId>nat-0123</natGatewayId>
    \\          <state>active</state>
    \\          <origin>CreateRoute</origin>
    \\        </item>
    \\        <item>
    \\          <destinationPrefixListId>pl-123</destinationPrefixListId>
    \\          <vpcPeeringConnectionId>pcx-1</vpcPeeringConnectionId>
    \\          <state>blackhole</state>
    \\          <origin>CreateRoute</origin>
    \\        </item>
    \\      </routeSet>
    \\      <associationSet>
    \\        <item>
    \\          <routeTableAssociationId>rtbassoc-1</routeTableAssociationId>
    \\          <routeTableId>rtb-0abc</routeTableId>
    \\          <subnetId>subnet-1</subnetId>
    \\          <main>false</main>
    \\          <associationState><state>associated</state></associationState>
    \\        </item>
    \\        <item>
    \\          <routeTableAssociationId>rtbassoc-2</routeTableAssociationId>
    \\          <routeTableId>rtb-0abc</routeTableId>
    \\          <main>true</main>
    \\          <associationState><state>associated</state></associationState>
    \\        </item>
    \\      </associationSet>
    \\      <propagatingVgwSet>
    \\        <item><gatewayId>vgw-1</gatewayId></item>
    \\      </propagatingVgwSet>
    \\      <tagSet>
    \\        <item><key>Name</key><value>private &amp; a</value></item>
    \\      </tagSet>
    \\    </item>
    \\    <item>
    \\      <routeTableId>rtb-empty</routeTableId>
    \\      <vpcId>vpc-0abc</vpcId>
    \\      <routeSet/>
    \\      <associationSet/>
    \\      <tagSet/>
    \\    </item>
    \\  </routeTableSet>
    \\  <nextToken>TOKEN</nextToken>
    \\</DescribeRouteTablesResponse>
;

test "parseResponse route tables" {
    const result = try parseResponse(std.testing.allocator, sample);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 2), result.route_tables.len);
    const t = result.route_tables[0];
    try std.testing.expectEqualStrings("rtb-0abc", t.route_table_id);
    try std.testing.expectEqualStrings("vpc-0abc", t.vpc_id);
    try std.testing.expectEqualStrings("private & a", t.name);
    try std.testing.expect(t.isMain());

    try std.testing.expectEqual(@as(usize, 3), t.routes.len);
    try std.testing.expectEqualStrings("10.0.0.0/16", t.routes[0].destination);
    try std.testing.expectEqualStrings("local", t.routes[0].target);
    try std.testing.expectEqualStrings("nat-0123", t.routes[1].target);
    try std.testing.expectEqualStrings("pl-123", t.routes[2].destination);
    try std.testing.expectEqualStrings("pcx-1", t.routes[2].target);
    try std.testing.expectEqualStrings("blackhole", t.routes[2].state);

    try std.testing.expectEqual(@as(usize, 2), t.associations.len);
    try std.testing.expectEqualStrings("subnet-1", t.associations[0].subnet_id);
    try std.testing.expect(!t.associations[0].main);
    try std.testing.expect(t.associations[1].main);
    try std.testing.expectEqualStrings("associated", t.associations[1].state);

    try std.testing.expectEqual(@as(usize, 1), t.propagating_vgws.len);
    try std.testing.expectEqualStrings("vgw-1", t.propagating_vgws[0]);

    const e = result.route_tables[1];
    try std.testing.expectEqualStrings("", e.name);
    try std.testing.expectEqual(@as(usize, 0), e.routes.len);
    try std.testing.expect(!e.isMain());
    try std.testing.expectEqualStrings("TOKEN", result.next_token.?);
}

test "parseResponse empty set" {
    const result = try parseResponse(
        std.testing.allocator,
        "<DescribeRouteTablesResponse><requestId>r</requestId><routeTableSet/></DescribeRouteTablesResponse>",
    );
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 0), result.route_tables.len);
    try std.testing.expect(result.next_token == null);
}

test "buildBody action only" {
    const body = try buildBody(std.testing.allocator, .{});
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("Action=DescribeRouteTables&Version=2016-11-15", body);
}

test "buildBody ids filters and paging" {
    const body = try buildBody(std.testing.allocator, .{
        .route_table_ids = &.{ "rtb-1", "rtb-2" },
        .filters = &.{.{ .name = "association.subnet-id", .values = &.{"subnet-1"} }},
        .max_results = 5,
        .next_token = "tok/en",
    });
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings(
        "Action=DescribeRouteTables&Version=2016-11-15&RouteTableId.1=rtb-1&RouteTableId.2=rtb-2" ++
            "&Filter.1.Name=association.subnet-id&Filter.1.Value.1=subnet-1" ++
            "&MaxResults=5&NextToken=tok%2Fen",
        body,
    );
}
