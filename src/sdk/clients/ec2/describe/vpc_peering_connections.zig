const std = @import("std");
const Allocator = std.mem.Allocator;

const xml = @import("../../../utils/xml.zig");
const req = @import("../request.zig");
const vpcs = @import("vpcs.zig");

pub const Filter = vpcs.Filter;

pub const Ec2DescribeVpcPeeringConnectionsError = error{
    @"InvalidVpcPeeringConnectionID.NotFound",
    @"InvalidVpcPeeringConnectionId.Malformed",
    InvalidParameterValue,
    InvalidParameterCombination,
    UnauthorizedOperation,
    AuthFailure,
    RequestLimitExceeded,
};

pub const Params = struct {
    vpc_peering_connection_ids: []const []const u8 = &.{},
    filters: []const Filter = &.{},
    /// 5..1000
    max_results: ?u32 = null,
    next_token: ?[]const u8 = null,
};

pub const Options = struct {
    params: Params = .{},
};

pub const VpcPeeringConnection = struct {
    allocator: Allocator,
    /// Peering connection ID.
    id: []u8,
    /// initiating-request | pending-acceptance | active | deleted | rejected | failed | expired | provisioning | deleting.
    state: []u8,
    status_message: []u8,
    requester_vpc_id: []u8,
    accepter_vpc_id: []u8,
    /// Value of the `Name` tag, or empty.
    name: []u8,

    pub fn deinit(self: VpcPeeringConnection) void {
        const a = self.allocator;
        a.free(self.id);
        a.free(self.state);
        a.free(self.status_message);
        a.free(self.requester_vpc_id);
        a.free(self.accepter_vpc_id);
        a.free(self.name);
    }
};

pub const Result = struct {
    allocator: Allocator,
    vpc_peering_connections: []VpcPeeringConnection,
    next_token: ?[]u8,

    pub fn deinit(self: Result) void {
        for (self.vpc_peering_connections) |x| x.deinit();
        self.allocator.free(self.vpc_peering_connections);
        if (self.next_token) |t| self.allocator.free(t);
    }
};

pub fn describeVpcPeeringConnections(client: anytype, options: Options) !Result {
    const body = try buildBody(client.allocator, options.params);
    defer client.allocator.free(body);

    const resp = try req.send(client, Ec2DescribeVpcPeeringConnectionsError, "DescribeVpcPeeringConnections", body);
    defer client.allocator.free(resp);

    return parseResponse(client.allocator, resp);
}

fn buildBody(allocator: Allocator, params: Params) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);

    try body.appendSlice(allocator, "Action=DescribeVpcPeeringConnections&Version=" ++ req.api_version);

    for (params.vpc_peering_connection_ids, 1..) |id, n| {
        const key = try allocator.print("VpcPeeringConnectionId.{d}", .{n});
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
    const root = xml.child(body, "DescribeVpcPeeringConnectionsResponse") orelse return error.InvalidResponse;

    var items: std.ArrayList(VpcPeeringConnection) = .empty;
    errdefer {
        for (items.items) |x| x.deinit();
        items.deinit(allocator);
    }

    if (xml.child(root, "vpcPeeringConnectionSet")) |set| {
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
        .vpc_peering_connections = try items.toOwnedSlice(allocator),
        .next_token = next_token,
    };
}

fn parseItem(allocator: Allocator, src: []const u8) !VpcPeeringConnection {
    const id = try req.xmlStr(allocator, src, "vpcPeeringConnectionId");
    errdefer allocator.free(id);
    const state = try req.xmlNested(allocator, src, "status", "code");
    errdefer allocator.free(state);
    const status_message = try req.xmlNested(allocator, src, "status", "message");
    errdefer allocator.free(status_message);
    const requester_vpc_id = try req.xmlNested(allocator, src, "requesterVpcInfo", "vpcId");
    errdefer allocator.free(requester_vpc_id);
    const accepter_vpc_id = try req.xmlNested(allocator, src, "accepterVpcInfo", "vpcId");
    errdefer allocator.free(accepter_vpc_id);
    const name = try vpcs.parseNameTag(allocator, src);
    errdefer allocator.free(name);

    return .{
        .allocator = allocator,
        .id = id,
        .state = state,
        .status_message = status_message,
        .requester_vpc_id = requester_vpc_id,
        .accepter_vpc_id = accepter_vpc_id,
        .name = name,
    };
}

// ============================================================================
// Tests
// ============================================================================

const sample =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<DescribeVpcPeeringConnectionsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
    \\  <requestId>req-1</requestId>
    \\  <vpcPeeringConnectionSet>
    \\    <item>
    \\      <vpcPeeringConnectionId>pcx-1</vpcPeeringConnectionId>
    \\      <status><code>active</code><message>Active</message></status>
    \\      <requesterVpcInfo><vpcId>vpc-a</vpcId><ownerId>1</ownerId></requesterVpcInfo>
    \\      <accepterVpcInfo><vpcId>vpc-b</vpcId><ownerId>2</ownerId></accepterVpcInfo>
    \\      <tagSet><item><key>Name</key><value>a-to-b</value></item></tagSet>
    \\    </item>
    \\    <item>
    \\      <vpcPeeringConnectionId>pcx-2</vpcPeeringConnectionId>
    \\      <status><code>pending-acceptance</code></status>
    \\    </item>
    \\  </vpcPeeringConnectionSet>
    \\  <nextToken>TOKEN</nextToken>
    \\</DescribeVpcPeeringConnectionsResponse>
;

test "parseResponse vpc_peering_connections" {
    const result = try parseResponse(std.testing.allocator, sample);
    defer result.deinit();

    const items = result.vpc_peering_connections;
    try std.testing.expectEqual(@as(usize, 2), items.len);
    try std.testing.expectEqualStrings("pcx-1", items[0].id);
    try std.testing.expectEqualStrings("active", items[0].state);
    try std.testing.expectEqualStrings("Active", items[0].status_message);
    try std.testing.expectEqualStrings("vpc-a", items[0].requester_vpc_id);
    try std.testing.expectEqualStrings("vpc-b", items[0].accepter_vpc_id);
    try std.testing.expectEqualStrings("a-to-b", items[0].name);
    try std.testing.expectEqualStrings("pending-acceptance", items[1].state);
    try std.testing.expectEqualStrings("", items[1].accepter_vpc_id);
    try std.testing.expectEqualStrings("TOKEN", result.next_token.?);
}

test "parseResponse empty set" {
    const result = try parseResponse(
        std.testing.allocator,
        "<DescribeVpcPeeringConnectionsResponse><requestId>r</requestId><vpcPeeringConnectionSet/></DescribeVpcPeeringConnectionsResponse>",
    );
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 0), result.vpc_peering_connections.len);
    try std.testing.expect(result.next_token == null);
}

test "buildBody action only" {
    const body = try buildBody(std.testing.allocator, .{});
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("Action=DescribeVpcPeeringConnections&Version=2016-11-15", body);
}

test "buildBody ids and filters" {
    const body = try buildBody(std.testing.allocator, .{
        .vpc_peering_connection_ids = &.{ "pcx-1", "x-2" },
        .filters = &.{.{ .name = "vpc-id", .values = &.{"vpc-1"} }},
        .max_results = 5,
        .next_token = "tok/en",
    });
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings(
        "Action=DescribeVpcPeeringConnections&Version=2016-11-15&VpcPeeringConnectionId.1=pcx-1&VpcPeeringConnectionId.2=x-2" ++
            "&Filter.1.Name=vpc-id&Filter.1.Value.1=vpc-1&MaxResults=5&NextToken=tok%2Fen",
        body,
    );
}
