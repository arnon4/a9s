const std = @import("std");
const Allocator = std.mem.Allocator;

const xml = @import("../../../utils/xml.zig");
const req = @import("../request.zig");
const vpcs = @import("vpcs.zig");

pub const Filter = vpcs.Filter;

pub const Ec2DescribeTransitGatewayVpcAttachmentsError = error{
    @"InvalidTransitGatewayAttachmentID.NotFound",
    @"InvalidTransitGatewayID.NotFound",
    InvalidParameterValue,
    InvalidParameterCombination,
    UnauthorizedOperation,
    AuthFailure,
    RequestLimitExceeded,
};

pub const Params = struct {
    transit_gateway_attachment_ids: []const []const u8 = &.{},
    filters: []const Filter = &.{},
    /// 5..1000
    max_results: ?u32 = null,
    next_token: ?[]const u8 = null,
};

pub const Options = struct {
    params: Params = .{},
};

pub const TransitGatewayVpcAttachment = struct {
    allocator: Allocator,
    /// Attachment ID.
    id: []u8,
    transit_gateway_id: []u8,
    vpc_id: []u8,
    /// initiating | pendingAcceptance | available | modifying | deleting | deleted | failed | rejected ...
    state: []u8,
    /// Value of the `Name` tag, or empty.
    name: []u8,

    pub fn deinit(self: TransitGatewayVpcAttachment) void {
        const a = self.allocator;
        a.free(self.id);
        a.free(self.transit_gateway_id);
        a.free(self.vpc_id);
        a.free(self.state);
        a.free(self.name);
    }
};

pub const Result = struct {
    allocator: Allocator,
    transit_gateway_vpc_attachments: []TransitGatewayVpcAttachment,
    next_token: ?[]u8,

    pub fn deinit(self: Result) void {
        for (self.transit_gateway_vpc_attachments) |x| x.deinit();
        self.allocator.free(self.transit_gateway_vpc_attachments);
        if (self.next_token) |t| self.allocator.free(t);
    }
};

pub fn describeTransitGatewayVpcAttachments(client: anytype, options: Options) !Result {
    const body = try buildBody(client.allocator, options.params);
    defer client.allocator.free(body);

    const resp = try req.send(client, Ec2DescribeTransitGatewayVpcAttachmentsError, "DescribeTransitGatewayVpcAttachments", body);
    defer client.allocator.free(resp);

    return parseResponse(client.allocator, resp);
}

fn buildBody(allocator: Allocator, params: Params) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);

    try body.appendSlice(allocator, "Action=DescribeTransitGatewayVpcAttachments&Version=" ++ req.api_version);

    for (params.transit_gateway_attachment_ids, 1..) |id, n| {
        const key = try allocator.print("TransitGatewayAttachmentIds.{d}", .{n});
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
    const root = xml.child(body, "DescribeTransitGatewayVpcAttachmentsResponse") orelse return error.InvalidResponse;

    var items: std.ArrayList(TransitGatewayVpcAttachment) = .empty;
    errdefer {
        for (items.items) |x| x.deinit();
        items.deinit(allocator);
    }

    if (xml.child(root, "transitGatewayVpcAttachments")) |set| {
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
        .transit_gateway_vpc_attachments = try items.toOwnedSlice(allocator),
        .next_token = next_token,
    };
}

fn parseItem(allocator: Allocator, src: []const u8) !TransitGatewayVpcAttachment {
    const id = try req.xmlStr(allocator, src, "transitGatewayAttachmentId");
    errdefer allocator.free(id);
    const transit_gateway_id = try req.xmlStr(allocator, src, "transitGatewayId");
    errdefer allocator.free(transit_gateway_id);
    const vpc_id = try req.xmlStr(allocator, src, "vpcId");
    errdefer allocator.free(vpc_id);
    const state = try req.xmlStr(allocator, src, "state");
    errdefer allocator.free(state);
    const name = try vpcs.parseNameTag(allocator, src);
    errdefer allocator.free(name);

    return .{
        .allocator = allocator,
        .id = id,
        .transit_gateway_id = transit_gateway_id,
        .vpc_id = vpc_id,
        .state = state,
        .name = name,
    };
}

// ============================================================================
// Tests
// ============================================================================

const sample =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<DescribeTransitGatewayVpcAttachmentsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
    \\  <requestId>req-1</requestId>
    \\  <transitGatewayVpcAttachments>
    \\    <item>
    \\      <transitGatewayAttachmentId>tgw-attach-1</transitGatewayAttachmentId>
    \\      <transitGatewayId>tgw-1</transitGatewayId>
    \\      <vpcId>vpc-1</vpcId>
    \\      <state>available</state>
    \\      <tagSet><item><key>Name</key><value>core</value></item></tagSet>
    \\    </item>
    \\    <item>
    \\      <transitGatewayAttachmentId>tgw-attach-2</transitGatewayAttachmentId>
    \\      <transitGatewayId>tgw-2</transitGatewayId>
    \\      <state>pendingAcceptance</state>
    \\    </item>
    \\  </transitGatewayVpcAttachments>
    \\  <nextToken>TOKEN</nextToken>
    \\</DescribeTransitGatewayVpcAttachmentsResponse>
;

test "parseResponse transit_gateway_vpc_attachments" {
    const result = try parseResponse(std.testing.allocator, sample);
    defer result.deinit();

    const items = result.transit_gateway_vpc_attachments;
    try std.testing.expectEqual(@as(usize, 2), items.len);
    try std.testing.expectEqualStrings("tgw-attach-1", items[0].id);
    try std.testing.expectEqualStrings("tgw-1", items[0].transit_gateway_id);
    try std.testing.expectEqualStrings("vpc-1", items[0].vpc_id);
    try std.testing.expectEqualStrings("available", items[0].state);
    try std.testing.expectEqualStrings("core", items[0].name);
    try std.testing.expectEqualStrings("pendingAcceptance", items[1].state);
    try std.testing.expectEqualStrings("", items[1].vpc_id);
    try std.testing.expectEqualStrings("TOKEN", result.next_token.?);
}

test "parseResponse empty set" {
    const result = try parseResponse(
        std.testing.allocator,
        "<DescribeTransitGatewayVpcAttachmentsResponse><requestId>r</requestId><transitGatewayVpcAttachments/></DescribeTransitGatewayVpcAttachmentsResponse>",
    );
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 0), result.transit_gateway_vpc_attachments.len);
    try std.testing.expect(result.next_token == null);
}

test "buildBody action only" {
    const body = try buildBody(std.testing.allocator, .{});
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("Action=DescribeTransitGatewayVpcAttachments&Version=2016-11-15", body);
}

test "buildBody ids and filters" {
    const body = try buildBody(std.testing.allocator, .{
        .transit_gateway_attachment_ids = &.{ "tgw-attach-1", "x-2" },
        .filters = &.{.{ .name = "vpc-id", .values = &.{"vpc-1"} }},
        .max_results = 5,
        .next_token = "tok/en",
    });
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings(
        "Action=DescribeTransitGatewayVpcAttachments&Version=2016-11-15&TransitGatewayAttachmentIds.1=tgw-attach-1&TransitGatewayAttachmentIds.2=x-2" ++
            "&Filter.1.Name=vpc-id&Filter.1.Value.1=vpc-1&MaxResults=5&NextToken=tok%2Fen",
        body,
    );
}
