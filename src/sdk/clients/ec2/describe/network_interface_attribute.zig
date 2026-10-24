const std = @import("std");
const Allocator = std.mem.Allocator;

const xml = @import("../../../utils/xml.zig");
const req = @import("../request.zig");
const nis = @import("network_interfaces.zig");

pub const Group = nis.Group;
pub const Attachment = nis.Attachment;

pub const Ec2DescribeNetworkInterfaceAttributeError = error{
    @"InvalidNetworkInterfaceID.NotFound",
    @"InvalidNetworkInterfaceId.Malformed",
    InvalidParameterValue,
    MissingParameter,
    UnauthorizedOperation,
    AuthFailure,
    RequestLimitExceeded,
};

pub const Attribute = enum {
    description,
    group_set,
    source_dest_check,
    attachment,

    /// Wire name, also the response element holding the value.
    pub fn apiName(self: Attribute) []const u8 {
        return switch (self) {
            .description => "description",
            .group_set => "groupSet",
            .source_dest_check => "sourceDestCheck",
            .attachment => "attachment",
        };
    }
};

pub const Params = struct {
    network_interface_id: []const u8,
    attribute: Attribute,
};

pub const Options = struct {
    params: Params,
};

/// Only the field matching the requested attribute is populated.
pub const Result = struct {
    allocator: Allocator,
    network_interface_id: []u8,
    attribute: Attribute,
    description: []u8,
    source_dest_check: ?bool,
    groups: []Group,
    attachment: ?Attachment,

    pub fn deinit(self: Result) void {
        const a = self.allocator;
        a.free(self.network_interface_id);
        a.free(self.description);
        nis.freeGroups(a, self.groups);
        if (self.attachment) |at| at.deinit(a);
    }
};

pub fn describeNetworkInterfaceAttribute(client: anytype, options: Options) !Result {
    const body = try buildBody(client.allocator, options.params);
    defer client.allocator.free(body);

    const resp = try req.send(client, Ec2DescribeNetworkInterfaceAttributeError, "DescribeNetworkInterfaceAttribute", body);
    defer client.allocator.free(resp);

    return parseResponse(client.allocator, resp, options.params.attribute);
}

fn buildBody(allocator: Allocator, params: Params) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);

    try body.appendSlice(allocator, "Action=DescribeNetworkInterfaceAttribute&Version=" ++ req.api_version);
    try req.appendParam(allocator, &body, "NetworkInterfaceId", params.network_interface_id);
    try req.appendParam(allocator, &body, "Attribute", params.attribute.apiName());

    return body.toOwnedSlice(allocator);
}

fn parseResponse(allocator: Allocator, body: []const u8, attribute: Attribute) !Result {
    const root = xml.child(body, "DescribeNetworkInterfaceAttributeResponse") orelse return error.InvalidResponse;

    const network_interface_id = try req.xmlStr(allocator, root, "networkInterfaceId");
    errdefer allocator.free(network_interface_id);

    var description = try allocator.dupe(u8, "");
    errdefer allocator.free(description);
    var source_dest_check: ?bool = null;
    var groups: []Group = try allocator.alloc(Group, 0);
    errdefer nis.freeGroups(allocator, groups);
    var attachment: ?Attachment = null;
    errdefer if (attachment) |at| at.deinit(allocator);

    switch (attribute) {
        .description => {
            const block = xml.child(root, "description") orelse return error.InvalidResponse;
            const value = try req.xmlStr(allocator, block, "value");
            allocator.free(description);
            description = value;
        },
        .source_dest_check => {
            const block = xml.child(root, "sourceDestCheck") orelse return error.InvalidResponse;
            source_dest_check = req.xmlBool(block, "value");
        },
        .group_set => {
            const parsed = try nis.parseGroups(allocator, root);
            nis.freeGroups(allocator, groups);
            groups = parsed;
        },
        .attachment => {
            if (xml.child(root, "attachment")) |block| {
                if (block.len > 0) attachment = try nis.parseAttachment(allocator, block);
            }
        },
    }

    return .{
        .allocator = allocator,
        .network_interface_id = network_interface_id,
        .attribute = attribute,
        .description = description,
        .source_dest_check = source_dest_check,
        .groups = groups,
        .attachment = attachment,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "parseResponse description" {
    const body =
        \\<DescribeNetworkInterfaceAttributeResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
        \\  <requestId>r</requestId>
        \\  <networkInterfaceId>eni-1</networkInterfaceId>
        \\  <description><value>primary &amp; only</value></description>
        \\</DescribeNetworkInterfaceAttributeResponse>
    ;
    const r = try parseResponse(std.testing.allocator, body, .description);
    defer r.deinit();
    try std.testing.expectEqualStrings("eni-1", r.network_interface_id);
    try std.testing.expectEqualStrings("primary & only", r.description);
    try std.testing.expect(r.source_dest_check == null);
}

test "parseResponse source dest check" {
    const body =
        \\<DescribeNetworkInterfaceAttributeResponse>
        \\  <networkInterfaceId>eni-1</networkInterfaceId>
        \\  <sourceDestCheck><value>false</value></sourceDestCheck>
        \\</DescribeNetworkInterfaceAttributeResponse>
    ;
    const r = try parseResponse(std.testing.allocator, body, .source_dest_check);
    defer r.deinit();
    try std.testing.expectEqual(@as(?bool, false), r.source_dest_check);
}

test "parseResponse group set" {
    const body =
        \\<DescribeNetworkInterfaceAttributeResponse>
        \\  <networkInterfaceId>eni-1</networkInterfaceId>
        \\  <groupSet>
        \\    <item><groupId>sg-1</groupId><groupName>web</groupName></item>
        \\    <item><groupId>sg-2</groupId><groupName>ssh</groupName></item>
        \\  </groupSet>
        \\</DescribeNetworkInterfaceAttributeResponse>
    ;
    const r = try parseResponse(std.testing.allocator, body, .group_set);
    defer r.deinit();
    try std.testing.expectEqual(@as(usize, 2), r.groups.len);
    try std.testing.expectEqualStrings("sg-2", r.groups[1].group_id);
    try std.testing.expectEqualStrings("ssh", r.groups[1].group_name);
}

test "parseResponse attachment" {
    const body =
        \\<DescribeNetworkInterfaceAttributeResponse>
        \\  <networkInterfaceId>eni-1</networkInterfaceId>
        \\  <attachment>
        \\    <attachmentId>eni-attach-1</attachmentId>
        \\    <instanceId>i-0123</instanceId>
        \\    <deviceIndex>1</deviceIndex>
        \\    <status>attached</status>
        \\    <deleteOnTermination>false</deleteOnTermination>
        \\  </attachment>
        \\</DescribeNetworkInterfaceAttributeResponse>
    ;
    const r = try parseResponse(std.testing.allocator, body, .attachment);
    defer r.deinit();
    const at = r.attachment.?;
    try std.testing.expectEqualStrings("i-0123", at.instance_id);
    try std.testing.expectEqual(@as(?i32, 1), at.device_index);
    try std.testing.expect(!at.delete_on_termination);
}

test "parseResponse detached interface has no attachment" {
    const r = try parseResponse(
        std.testing.allocator,
        "<DescribeNetworkInterfaceAttributeResponse><networkInterfaceId>eni-1</networkInterfaceId><attachment/></DescribeNetworkInterfaceAttributeResponse>",
        .attachment,
    );
    defer r.deinit();
    try std.testing.expect(r.attachment == null);
}

test "parseResponse missing attribute" {
    try std.testing.expectError(
        error.InvalidResponse,
        parseResponse(std.testing.allocator, "<DescribeNetworkInterfaceAttributeResponse><networkInterfaceId>e</networkInterfaceId></DescribeNetworkInterfaceAttributeResponse>", .description),
    );
}

test "buildBody" {
    const body = try buildBody(std.testing.allocator, .{ .network_interface_id = "eni-1", .attribute = .source_dest_check });
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings(
        "Action=DescribeNetworkInterfaceAttribute&Version=2016-11-15&NetworkInterfaceId=eni-1&Attribute=sourceDestCheck",
        body,
    );
}
