const std = @import("std");
const Allocator = std.mem.Allocator;

const xml = @import("../../../utils/xml.zig");
const req = @import("../request.zig");
const vpcs = @import("vpcs.zig");

pub const Tag = vpcs.Tag;
pub const Filter = vpcs.Filter;

pub const Ec2DescribeInternetGatewaysError = error{
    @"InvalidInternetGatewayID.NotFound",
    @"InvalidInternetGatewayId.Malformed",
    InvalidParameterValue,
    InvalidParameterCombination,
    UnauthorizedOperation,
    AuthFailure,
    RequestLimitExceeded,
};

pub const Params = struct {
    internet_gateway_ids: []const []const u8 = &.{},
    filters: []const Filter = &.{},
    /// 5..1000
    max_results: ?u32 = null,
    next_token: ?[]const u8 = null,
};

pub const Options = struct {
    params: Params = .{},
};

pub const Attachment = struct {
    vpc_id: []u8,
    state: []u8,
};

pub const InternetGateway = struct {
    allocator: Allocator,
    internet_gateway_id: []u8,
    owner_id: []u8,
    /// Value of the `Name` tag, or empty.
    name: []u8,
    tags: []Tag,
    attachments: []Attachment,

    pub fn deinit(self: InternetGateway) void {
        const a = self.allocator;
        a.free(self.internet_gateway_id);
        a.free(self.owner_id);
        a.free(self.name);
        vpcs.freeTags(a, self.tags);
        freeAttachments(a, self.attachments);
    }
};

pub const Result = struct {
    allocator: Allocator,
    internet_gateways: []InternetGateway,
    next_token: ?[]u8,

    pub fn deinit(self: Result) void {
        for (self.internet_gateways) |g| g.deinit();
        self.allocator.free(self.internet_gateways);
        if (self.next_token) |t| self.allocator.free(t);
    }
};

fn freeAttachments(a: Allocator, items: []Attachment) void {
    for (items) |x| {
        a.free(x.vpc_id);
        a.free(x.state);
    }
    a.free(items);
}

pub fn describeInternetGateways(client: anytype, options: Options) !Result {
    const body = try buildBody(client.allocator, options.params);
    defer client.allocator.free(body);

    const resp = try req.send(client, Ec2DescribeInternetGatewaysError, "DescribeInternetGateways", body);
    defer client.allocator.free(resp);

    return parseResponse(client.allocator, resp);
}

fn buildBody(allocator: Allocator, params: Params) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);

    try body.appendSlice(allocator, "Action=DescribeInternetGateways&Version=" ++ req.api_version);

    for (params.internet_gateway_ids, 1..) |id, n| {
        const key = try allocator.print("InternetGatewayId.{d}", .{n});
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
    const root = xml.child(body, "DescribeInternetGatewaysResponse") orelse return error.InvalidResponse;

    var gateways: std.ArrayList(InternetGateway) = .empty;
    errdefer {
        for (gateways.items) |g| g.deinit();
        gateways.deinit(allocator);
    }

    if (xml.child(root, "internetGatewaySet")) |set| {
        var it: xml.ChildIterator = .{ .src = set, .name = "item" };
        while (it.next()) |item| {
            const gateway = try parseGateway(allocator, item);
            errdefer gateway.deinit();
            try gateways.append(allocator, gateway);
        }
    }

    const next_token: ?[]u8 = if (xml.child(root, "nextToken")) |t|
        if (t.len > 0) try xml.unescape(allocator, t) else null
    else
        null;
    errdefer if (next_token) |t| allocator.free(t);

    return .{
        .allocator = allocator,
        .internet_gateways = try gateways.toOwnedSlice(allocator),
        .next_token = next_token,
    };
}

fn parseAttachments(allocator: Allocator, src: []const u8) ![]Attachment {
    var items: std.ArrayList(Attachment) = .empty;
    errdefer {
        for (items.items) |x| {
            allocator.free(x.vpc_id);
            allocator.free(x.state);
        }
        items.deinit(allocator);
    }

    const set = xml.child(src, "attachmentSet") orelse return items.toOwnedSlice(allocator);
    var it: xml.ChildIterator = .{ .src = set, .name = "item" };
    while (it.next()) |item| {
        const vpc_id = try req.xmlStr(allocator, item, "vpcId");
        errdefer allocator.free(vpc_id);
        const state = try req.xmlStr(allocator, item, "state");
        errdefer allocator.free(state);
        try items.append(allocator, .{ .vpc_id = vpc_id, .state = state });
    }
    return items.toOwnedSlice(allocator);
}

fn parseGateway(allocator: Allocator, src: []const u8) !InternetGateway {
    const internet_gateway_id = try req.xmlStr(allocator, src, "internetGatewayId");
    errdefer allocator.free(internet_gateway_id);
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

    const attachments = try parseAttachments(allocator, src);
    errdefer freeAttachments(allocator, attachments);

    return .{
        .allocator = allocator,
        .internet_gateway_id = internet_gateway_id,
        .owner_id = owner_id,
        .name = name,
        .tags = tags,
        .attachments = attachments,
    };
}

// ============================================================================
// Tests
// ============================================================================

const sample =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<DescribeInternetGatewaysResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
    \\  <requestId>req-1</requestId>
    \\  <internetGatewaySet>
    \\    <item>
    \\      <internetGatewayId>igw-0abc</internetGatewayId>
    \\      <ownerId>123456789012</ownerId>
    \\      <attachmentSet>
    \\        <item>
    \\          <vpcId>vpc-0abc</vpcId>
    \\          <state>available</state>
    \\        </item>
    \\      </attachmentSet>
    \\      <tagSet>
    \\        <item><key>Name</key><value>main &amp; igw</value></item>
    \\      </tagSet>
    \\    </item>
    \\    <item>
    \\      <internetGatewayId>igw-detached</internetGatewayId>
    \\      <attachmentSet/>
    \\      <tagSet/>
    \\    </item>
    \\  </internetGatewaySet>
    \\  <nextToken>TOKEN</nextToken>
    \\</DescribeInternetGatewaysResponse>
;

test "parseResponse internet gateways" {
    const result = try parseResponse(std.testing.allocator, sample);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 2), result.internet_gateways.len);
    const g = result.internet_gateways[0];
    try std.testing.expectEqualStrings("igw-0abc", g.internet_gateway_id);
    try std.testing.expectEqualStrings("123456789012", g.owner_id);
    try std.testing.expectEqualStrings("main & igw", g.name);
    try std.testing.expectEqual(@as(usize, 1), g.attachments.len);
    try std.testing.expectEqualStrings("vpc-0abc", g.attachments[0].vpc_id);
    try std.testing.expectEqualStrings("available", g.attachments[0].state);

    const d = result.internet_gateways[1];
    try std.testing.expectEqualStrings("", d.name);
    try std.testing.expectEqual(@as(usize, 0), d.attachments.len);
    try std.testing.expectEqualStrings("TOKEN", result.next_token.?);
}

test "parseResponse empty set" {
    const result = try parseResponse(
        std.testing.allocator,
        "<DescribeInternetGatewaysResponse><requestId>r</requestId><internetGatewaySet/></DescribeInternetGatewaysResponse>",
    );
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 0), result.internet_gateways.len);
    try std.testing.expect(result.next_token == null);
}

test "buildBody action only" {
    const body = try buildBody(std.testing.allocator, .{});
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("Action=DescribeInternetGateways&Version=2016-11-15", body);
}

test "buildBody ids filters and paging" {
    const body = try buildBody(std.testing.allocator, .{
        .internet_gateway_ids = &.{ "igw-1", "igw-2" },
        .filters = &.{.{ .name = "attachment.vpc-id", .values = &.{"vpc-1"} }},
        .max_results = 5,
        .next_token = "tok/en",
    });
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings(
        "Action=DescribeInternetGateways&Version=2016-11-15&InternetGatewayId.1=igw-1&InternetGatewayId.2=igw-2" ++
            "&Filter.1.Name=attachment.vpc-id&Filter.1.Value.1=vpc-1" ++
            "&MaxResults=5&NextToken=tok%2Fen",
        body,
    );
}
