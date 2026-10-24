const std = @import("std");
const Allocator = std.mem.Allocator;

const xml = @import("../../../utils/xml.zig");
const req = @import("../request.zig");
const vpcs = @import("vpcs.zig");

pub const Filter = vpcs.Filter;

pub const Ec2DescribeNetworkInterfacePermissionsError = error{
    @"InvalidNetworkInterfacePermissionID.NotFound",
    @"InvalidNetworkInterfaceID.NotFound",
    InvalidParameterValue,
    InvalidParameterCombination,
    UnauthorizedOperation,
    AuthFailure,
    RequestLimitExceeded,
};

pub const Params = struct {
    permission_ids: []const []const u8 = &.{},
    filters: []const Filter = &.{},
    /// 5..255
    max_results: ?u32 = null,
    next_token: ?[]const u8 = null,
};

pub const Options = struct {
    params: Params = .{},
};

pub const NetworkInterfacePermission = struct {
    allocator: Allocator,
    /// Permission ID.
    id: []u8,
    network_interface_id: []u8,
    /// Account the permission was granted to.
    aws_account_id: []u8,
    /// AWS service the permission was granted to, when it is not an account.
    aws_service: []u8,
    /// INSTANCE-ATTACH | EIP-ASSOCIATE
    permission: []u8,
    /// pending | granted | revoking | revoked
    state: []u8,
    status_message: []u8,

    pub fn deinit(self: NetworkInterfacePermission) void {
        const a = self.allocator;
        a.free(self.id);
        a.free(self.network_interface_id);
        a.free(self.aws_account_id);
        a.free(self.aws_service);
        a.free(self.permission);
        a.free(self.state);
        a.free(self.status_message);
    }
};

pub const Result = struct {
    allocator: Allocator,
    permissions: []NetworkInterfacePermission,
    next_token: ?[]u8,

    pub fn deinit(self: Result) void {
        for (self.permissions) |x| x.deinit();
        self.allocator.free(self.permissions);
        if (self.next_token) |t| self.allocator.free(t);
    }
};

pub fn describeNetworkInterfacePermissions(client: anytype, options: Options) !Result {
    const body = try buildBody(client.allocator, options.params);
    defer client.allocator.free(body);

    const resp = try req.send(client, Ec2DescribeNetworkInterfacePermissionsError, "DescribeNetworkInterfacePermissions", body);
    defer client.allocator.free(resp);

    return parseResponse(client.allocator, resp);
}

fn buildBody(allocator: Allocator, params: Params) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);

    try body.appendSlice(allocator, "Action=DescribeNetworkInterfacePermissions&Version=" ++ req.api_version);

    for (params.permission_ids, 1..) |id, n| {
        const key = try allocator.print("NetworkInterfacePermissionId.{d}", .{n});
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
    const root = xml.child(body, "DescribeNetworkInterfacePermissionsResponse") orelse return error.InvalidResponse;

    var items: std.ArrayList(NetworkInterfacePermission) = .empty;
    errdefer {
        for (items.items) |x| x.deinit();
        items.deinit(allocator);
    }

    if (xml.child(root, "networkInterfacePermissions")) |set| {
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
        .permissions = try items.toOwnedSlice(allocator),
        .next_token = next_token,
    };
}

fn parseItem(allocator: Allocator, src: []const u8) !NetworkInterfacePermission {
    const id = try req.xmlStr(allocator, src, "networkInterfacePermissionId");
    errdefer allocator.free(id);
    const network_interface_id = try req.xmlStr(allocator, src, "networkInterfaceId");
    errdefer allocator.free(network_interface_id);
    const aws_account_id = try req.xmlStr(allocator, src, "awsAccountId");
    errdefer allocator.free(aws_account_id);
    const aws_service = try req.xmlStr(allocator, src, "awsService");
    errdefer allocator.free(aws_service);
    const permission = try req.xmlStr(allocator, src, "permission");
    errdefer allocator.free(permission);
    const state = try req.xmlNested(allocator, src, "permissionState", "state");
    errdefer allocator.free(state);
    const status_message = try req.xmlNested(allocator, src, "permissionState", "statusMessage");
    errdefer allocator.free(status_message);

    return .{
        .allocator = allocator,
        .id = id,
        .network_interface_id = network_interface_id,
        .aws_account_id = aws_account_id,
        .aws_service = aws_service,
        .permission = permission,
        .state = state,
        .status_message = status_message,
    };
}

// ============================================================================
// Tests
// ============================================================================

const sample =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<DescribeNetworkInterfacePermissionsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
    \\  <requestId>req-1</requestId>
    \\  <networkInterfacePermissions>
    \\    <item>
    \\      <networkInterfacePermissionId>eni-perm-1</networkInterfacePermissionId>
    \\      <networkInterfaceId>eni-1</networkInterfaceId>
    \\      <awsAccountId>999999999999</awsAccountId>
    \\      <permission>INSTANCE-ATTACH</permission>
    \\      <permissionState><state>granted</state></permissionState>
    \\    </item>
    \\    <item>
    \\      <networkInterfacePermissionId>eni-perm-2</networkInterfacePermissionId>
    \\      <networkInterfaceId>eni-1</networkInterfaceId>
    \\      <awsService>lambda.amazonaws.com</awsService>
    \\      <permission>EIP-ASSOCIATE</permission>
    \\      <permissionState><state>revoked</state><statusMessage>expired</statusMessage></permissionState>
    \\    </item>
    \\  </networkInterfacePermissions>
    \\  <nextToken>TOKEN</nextToken>
    \\</DescribeNetworkInterfacePermissionsResponse>
;

test "parseResponse network_interface_permissions" {
    const result = try parseResponse(std.testing.allocator, sample);
    defer result.deinit();

    const items = result.permissions;
    try std.testing.expectEqual(@as(usize, 2), items.len);
    try std.testing.expectEqualStrings("eni-perm-1", items[0].id);
    try std.testing.expectEqualStrings("eni-1", items[0].network_interface_id);
    try std.testing.expectEqualStrings("999999999999", items[0].aws_account_id);
    try std.testing.expectEqualStrings("", items[0].aws_service);
    try std.testing.expectEqualStrings("INSTANCE-ATTACH", items[0].permission);
    try std.testing.expectEqualStrings("granted", items[0].state);
    try std.testing.expectEqualStrings("", items[0].status_message);
    try std.testing.expectEqualStrings("lambda.amazonaws.com", items[1].aws_service);
    try std.testing.expectEqualStrings("EIP-ASSOCIATE", items[1].permission);
    try std.testing.expectEqualStrings("revoked", items[1].state);
    try std.testing.expectEqualStrings("expired", items[1].status_message);
    try std.testing.expectEqualStrings("TOKEN", result.next_token.?);
}

test "parseResponse empty set" {
    const result = try parseResponse(
        std.testing.allocator,
        "<DescribeNetworkInterfacePermissionsResponse><requestId>r</requestId><networkInterfacePermissions/></DescribeNetworkInterfacePermissionsResponse>",
    );
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 0), result.permissions.len);
    try std.testing.expect(result.next_token == null);
}

test "buildBody action only" {
    const body = try buildBody(std.testing.allocator, .{});
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("Action=DescribeNetworkInterfacePermissions&Version=2016-11-15", body);
}

test "buildBody full params" {
    const body = try buildBody(std.testing.allocator, .{
        .permission_ids = &.{ "eni-perm-1", "x-2" },
        .filters = &.{.{ .name = "group-name", .values = &.{"web"} }},
        .max_results = 5,
        .next_token = "tok/en",
    });
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings(
        "Action=DescribeNetworkInterfacePermissions&Version=2016-11-15&NetworkInterfacePermissionId.1=eni-perm-1&NetworkInterfacePermissionId.2=x-2" ++
            "&Filter.1.Name=group-name&Filter.1.Value.1=web&MaxResults=5&NextToken=tok%2Fen",
        body,
    );
}
