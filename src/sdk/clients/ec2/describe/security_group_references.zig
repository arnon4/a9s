const std = @import("std");
const Allocator = std.mem.Allocator;

const xml = @import("../../../utils/xml.zig");
const req = @import("../request.zig");
const vpcs = @import("vpcs.zig");

pub const Filter = vpcs.Filter;

pub const Ec2DescribeSecurityGroupReferencesError = error{
    @"InvalidGroup.NotFound",
    InvalidParameterValue,
    InvalidParameterCombination,
    UnauthorizedOperation,
    AuthFailure,
    RequestLimitExceeded,
};

pub const Params = struct {
    group_ids: []const []const u8 = &.{},
};

pub const Options = struct {
    params: Params = .{},
};

pub const SecurityGroupReference = struct {
    allocator: Allocator,
    /// The referenced security group.
    group_id: []u8,
    /// VPC holding the rule that references the group.
    referencing_vpc_id: []u8,
    /// Peering connection the reference crosses, or empty.
    vpc_peering_connection_id: []u8,
    /// Transit gateway the reference crosses, or empty.
    transit_gateway_id: []u8,

    pub fn deinit(self: SecurityGroupReference) void {
        const a = self.allocator;
        a.free(self.group_id);
        a.free(self.referencing_vpc_id);
        a.free(self.vpc_peering_connection_id);
        a.free(self.transit_gateway_id);
    }
};

pub const Result = struct {
    allocator: Allocator,
    references: []SecurityGroupReference,

    pub fn deinit(self: Result) void {
        for (self.references) |x| x.deinit();
        self.allocator.free(self.references);
    }
};

pub fn describeSecurityGroupReferences(client: anytype, options: Options) !Result {
    const body = try buildBody(client.allocator, options.params);
    defer client.allocator.free(body);

    const resp = try req.send(client, Ec2DescribeSecurityGroupReferencesError, "DescribeSecurityGroupReferences", body);
    defer client.allocator.free(resp);

    return parseResponse(client.allocator, resp);
}

fn buildBody(allocator: Allocator, params: Params) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);

    try body.appendSlice(allocator, "Action=DescribeSecurityGroupReferences&Version=" ++ req.api_version);

    for (params.group_ids, 1..) |id, n| {
        const key = try allocator.print("GroupId.{d}", .{n});
        defer allocator.free(key);
        try req.appendParam(allocator, &body, key, id);
    }

    return body.toOwnedSlice(allocator);
}

fn parseResponse(allocator: Allocator, body: []const u8) !Result {
    const root = xml.child(body, "DescribeSecurityGroupReferencesResponse") orelse return error.InvalidResponse;

    var items: std.ArrayList(SecurityGroupReference) = .empty;
    errdefer {
        for (items.items) |x| x.deinit();
        items.deinit(allocator);
    }

    if (xml.child(root, "securityGroupReferenceSet")) |set| {
        var it: xml.ChildIterator = .{ .src = set, .name = "item" };
        while (it.next()) |src| {
            const parsed = try parseItem(allocator, src);
            errdefer parsed.deinit();
            try items.append(allocator, parsed);
        }
    }

    return .{
        .allocator = allocator,
        .references = try items.toOwnedSlice(allocator),
    };
}

fn parseItem(allocator: Allocator, src: []const u8) !SecurityGroupReference {
    const group_id = try req.xmlStr(allocator, src, "groupId");
    errdefer allocator.free(group_id);
    const referencing_vpc_id = try req.xmlStr(allocator, src, "referencingVpcId");
    errdefer allocator.free(referencing_vpc_id);
    const vpc_peering_connection_id = try req.xmlStr(allocator, src, "vpcPeeringConnectionId");
    errdefer allocator.free(vpc_peering_connection_id);
    const transit_gateway_id = try req.xmlStr(allocator, src, "transitGatewayId");
    errdefer allocator.free(transit_gateway_id);

    return .{
        .allocator = allocator,
        .group_id = group_id,
        .referencing_vpc_id = referencing_vpc_id,
        .vpc_peering_connection_id = vpc_peering_connection_id,
        .transit_gateway_id = transit_gateway_id,
    };
}

// ============================================================================
// Tests
// ============================================================================

const sample =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<DescribeSecurityGroupReferencesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
    \\  <requestId>req-1</requestId>
    \\  <securityGroupReferenceSet>
    \\    <item>
    \\      <groupId>sg-1</groupId>
    \\      <referencingVpcId>vpc-peer</referencingVpcId>
    \\      <vpcPeeringConnectionId>pcx-1</vpcPeeringConnectionId>
    \\    </item>
    \\    <item>
    \\      <groupId>sg-1</groupId>
    \\      <referencingVpcId>vpc-tgw</referencingVpcId>
    \\      <transitGatewayId>tgw-1</transitGatewayId>
    \\    </item>
    \\  </securityGroupReferenceSet>
    \\</DescribeSecurityGroupReferencesResponse>
;

test "parseResponse security_group_references" {
    const result = try parseResponse(std.testing.allocator, sample);
    defer result.deinit();

    const items = result.references;
    try std.testing.expectEqual(@as(usize, 2), items.len);
    try std.testing.expectEqualStrings("sg-1", items[0].group_id);
    try std.testing.expectEqualStrings("vpc-peer", items[0].referencing_vpc_id);
    try std.testing.expectEqualStrings("pcx-1", items[0].vpc_peering_connection_id);
    try std.testing.expectEqualStrings("", items[0].transit_gateway_id);
    try std.testing.expectEqualStrings("tgw-1", items[1].transit_gateway_id);
    try std.testing.expectEqualStrings("", items[1].vpc_peering_connection_id);
}

test "parseResponse empty set" {
    const result = try parseResponse(
        std.testing.allocator,
        "<DescribeSecurityGroupReferencesResponse><requestId>r</requestId><securityGroupReferenceSet/></DescribeSecurityGroupReferencesResponse>",
    );
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 0), result.references.len);
}

test "buildBody action only" {
    const body = try buildBody(std.testing.allocator, .{});
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("Action=DescribeSecurityGroupReferences&Version=2016-11-15", body);
}

test "buildBody full params" {
    const body = try buildBody(std.testing.allocator, .{
        .group_ids = &.{ "sg-1", "x-2" },
    });
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("Action=DescribeSecurityGroupReferences&Version=2016-11-15&GroupId.1=sg-1&GroupId.2=x-2", body);
}
