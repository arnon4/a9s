const std = @import("std");
const Allocator = std.mem.Allocator;

const xml = @import("../../../utils/xml.zig");
const req = @import("../request.zig");
const vpcs = @import("vpcs.zig");

pub const Filter = vpcs.Filter;

pub const Ec2GetSecurityGroupsForVpcError = error{
    @"InvalidVpcID.NotFound",
    InvalidParameterValue,
    InvalidParameterCombination,
    UnauthorizedOperation,
    AuthFailure,
    RequestLimitExceeded,
};

pub const Params = struct {
    vpc_id: []const u8,
    filters: []const Filter = &.{},
    /// 5..1000
    max_results: ?u32 = null,
    next_token: ?[]const u8 = null,
};

pub const Options = struct {
    params: Params = .{},
};

pub const SecurityGroupForVpc = struct {
    allocator: Allocator,
    group_id: []u8,
    group_name: []u8,
    description: []u8,
    owner_id: []u8,
    primary_vpc_id: []u8,
    /// Value of the `Name` tag, or empty.
    name: []u8,

    pub fn deinit(self: SecurityGroupForVpc) void {
        const a = self.allocator;
        a.free(self.group_id);
        a.free(self.group_name);
        a.free(self.description);
        a.free(self.owner_id);
        a.free(self.primary_vpc_id);
        a.free(self.name);
    }
};

pub const Result = struct {
    allocator: Allocator,
    security_groups: []SecurityGroupForVpc,
    next_token: ?[]u8,

    pub fn deinit(self: Result) void {
        for (self.security_groups) |x| x.deinit();
        self.allocator.free(self.security_groups);
        if (self.next_token) |t| self.allocator.free(t);
    }
};

pub fn getSecurityGroupsForVpc(client: anytype, options: Options) !Result {
    const body = try buildBody(client.allocator, options.params);
    defer client.allocator.free(body);

    const resp = try req.send(client, Ec2GetSecurityGroupsForVpcError, "GetSecurityGroupsForVpc", body);
    defer client.allocator.free(resp);

    return parseResponse(client.allocator, resp);
}

fn buildBody(allocator: Allocator, params: Params) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);

    try body.appendSlice(allocator, "Action=GetSecurityGroupsForVpc&Version=" ++ req.api_version);

    try req.appendParam(allocator, &body, "VpcId", params.vpc_id);
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
    const root = xml.child(body, "GetSecurityGroupsForVpcResponse") orelse return error.InvalidResponse;

    var items: std.ArrayList(SecurityGroupForVpc) = .empty;
    errdefer {
        for (items.items) |x| x.deinit();
        items.deinit(allocator);
    }

    if (xml.child(root, "securityGroupForVpcSet")) |set| {
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
        .security_groups = try items.toOwnedSlice(allocator),
        .next_token = next_token,
    };
}

fn parseItem(allocator: Allocator, src: []const u8) !SecurityGroupForVpc {
    const group_id = try req.xmlStr(allocator, src, "groupId");
    errdefer allocator.free(group_id);
    const group_name = try req.xmlStr(allocator, src, "groupName");
    errdefer allocator.free(group_name);
    const description = try req.xmlStr(allocator, src, "description");
    errdefer allocator.free(description);
    const owner_id = try req.xmlStr(allocator, src, "ownerId");
    errdefer allocator.free(owner_id);
    const primary_vpc_id = try req.xmlStr(allocator, src, "primaryVpcId");
    errdefer allocator.free(primary_vpc_id);
    const name = try vpcs.parseNameTag(allocator, src);
    errdefer allocator.free(name);

    return .{
        .allocator = allocator,
        .group_id = group_id,
        .group_name = group_name,
        .description = description,
        .owner_id = owner_id,
        .primary_vpc_id = primary_vpc_id,
        .name = name,
    };
}

// ============================================================================
// Tests
// ============================================================================

const sample =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<GetSecurityGroupsForVpcResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
    \\  <requestId>req-1</requestId>
    \\  <securityGroupForVpcSet>
    \\    <item>
    \\      <groupId>sg-1</groupId>
    \\      <groupName>web</groupName>
    \\      <description>web tier</description>
    \\      <ownerId>123456789012</ownerId>
    \\      <primaryVpcId>vpc-1</primaryVpcId>
    \\      <tagSet><item><key>Name</key><value>web-sg</value></item></tagSet>
    \\    </item>
    \\    <item>
    \\      <groupId>sg-2</groupId>
    \\      <groupName>default</groupName>
    \\    </item>
    \\  </securityGroupForVpcSet>
    \\  <nextToken>TOKEN</nextToken>
    \\</GetSecurityGroupsForVpcResponse>
;

test "parseResponse security_groups_for_vpc" {
    const result = try parseResponse(std.testing.allocator, sample);
    defer result.deinit();

    const items = result.security_groups;
    try std.testing.expectEqual(@as(usize, 2), items.len);
    try std.testing.expectEqualStrings("sg-1", items[0].group_id);
    try std.testing.expectEqualStrings("web", items[0].group_name);
    try std.testing.expectEqualStrings("web tier", items[0].description);
    try std.testing.expectEqualStrings("123456789012", items[0].owner_id);
    try std.testing.expectEqualStrings("vpc-1", items[0].primary_vpc_id);
    try std.testing.expectEqualStrings("web-sg", items[0].name);
    try std.testing.expectEqualStrings("sg-2", items[1].group_id);
    try std.testing.expectEqualStrings("", items[1].description);
    try std.testing.expectEqualStrings("", items[1].name);
    try std.testing.expectEqualStrings("TOKEN", result.next_token.?);
}

test "parseResponse empty set" {
    const result = try parseResponse(
        std.testing.allocator,
        "<GetSecurityGroupsForVpcResponse><requestId>r</requestId><securityGroupForVpcSet/></GetSecurityGroupsForVpcResponse>",
    );
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 0), result.security_groups.len);
    try std.testing.expect(result.next_token == null);
}

test "buildBody action only" {
    const body = try buildBody(std.testing.allocator, .{ .vpc_id = "vpc-1" });
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("Action=GetSecurityGroupsForVpc&Version=2016-11-15&VpcId=vpc-1", body);
}

test "buildBody full params" {
    const body = try buildBody(std.testing.allocator, .{
        .vpc_id = "vpc-1",
        .filters = &.{.{ .name = "group-name", .values = &.{"web"} }},
        .max_results = 5,
        .next_token = "tok/en",
    });
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings(
        "Action=GetSecurityGroupsForVpc&Version=2016-11-15&VpcId=vpc-1" ++
            "&Filter.1.Name=group-name&Filter.1.Value.1=web&MaxResults=5&NextToken=tok%2Fen",
        body,
    );
}
