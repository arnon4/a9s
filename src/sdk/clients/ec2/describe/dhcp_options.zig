const std = @import("std");
const Allocator = std.mem.Allocator;

const xml = @import("../../../utils/xml.zig");
const req = @import("../request.zig");
const vpcs = @import("vpcs.zig");

pub const Tag = vpcs.Tag;
pub const Filter = vpcs.Filter;

pub const Ec2DescribeDhcpOptionsError = error{
    @"InvalidDhcpOptionID.NotFound",
    @"InvalidDhcpOptionsID.NotFound",
    @"InvalidDhcpOptionID.Malformed",
    InvalidParameterValue,
    InvalidParameterCombination,
    UnauthorizedOperation,
    AuthFailure,
    RequestLimitExceeded,
};

pub const Params = struct {
    dhcp_options_ids: []const []const u8 = &.{},
    filters: []const Filter = &.{},
    /// 5..1000
    max_results: ?u32 = null,
    next_token: ?[]const u8 = null,
};

pub const Options = struct {
    params: Params = .{},
};

/// One DHCP option, e.g. `domain-name-servers` with its values.
pub const Configuration = struct {
    key: []u8,
    values: [][]u8,
};

pub const DhcpOptions = struct {
    allocator: Allocator,
    dhcp_options_id: []u8,
    owner_id: []u8,
    /// Value of the `Name` tag, or empty.
    name: []u8,
    tags: []Tag,
    configurations: []Configuration,

    pub fn deinit(self: DhcpOptions) void {
        const a = self.allocator;
        a.free(self.dhcp_options_id);
        a.free(self.owner_id);
        a.free(self.name);
        vpcs.freeTags(a, self.tags);
        freeConfigurations(a, self.configurations);
    }
};

pub const Result = struct {
    allocator: Allocator,
    dhcp_options: []DhcpOptions,
    next_token: ?[]u8,

    pub fn deinit(self: Result) void {
        for (self.dhcp_options) |d| d.deinit();
        self.allocator.free(self.dhcp_options);
        if (self.next_token) |t| self.allocator.free(t);
    }
};

fn freeValues(a: Allocator, values: [][]u8) void {
    for (values) |v| a.free(v);
    a.free(values);
}

fn freeConfigurations(a: Allocator, items: []Configuration) void {
    for (items) |c| {
        a.free(c.key);
        freeValues(a, c.values);
    }
    a.free(items);
}

pub fn describeDhcpOptions(client: anytype, options: Options) !Result {
    const body = try buildBody(client.allocator, options.params);
    defer client.allocator.free(body);

    const resp = try req.send(client, Ec2DescribeDhcpOptionsError, "DescribeDhcpOptions", body);
    defer client.allocator.free(resp);

    return parseResponse(client.allocator, resp);
}

fn buildBody(allocator: Allocator, params: Params) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);

    try body.appendSlice(allocator, "Action=DescribeDhcpOptions&Version=" ++ req.api_version);

    for (params.dhcp_options_ids, 1..) |id, n| {
        const key = try allocator.print("DhcpOptionsId.{d}", .{n});
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
    const root = xml.child(body, "DescribeDhcpOptionsResponse") orelse return error.InvalidResponse;

    var sets: std.ArrayList(DhcpOptions) = .empty;
    errdefer {
        for (sets.items) |d| d.deinit();
        sets.deinit(allocator);
    }

    if (xml.child(root, "dhcpOptionsSet")) |set| {
        var it: xml.ChildIterator = .{ .src = set, .name = "item" };
        while (it.next()) |item| {
            const d = try parseDhcpOptions(allocator, item);
            errdefer d.deinit();
            try sets.append(allocator, d);
        }
    }

    const next_token: ?[]u8 = if (xml.child(root, "nextToken")) |t|
        if (t.len > 0) try xml.unescape(allocator, t) else null
    else
        null;
    errdefer if (next_token) |t| allocator.free(t);

    return .{
        .allocator = allocator,
        .dhcp_options = try sets.toOwnedSlice(allocator),
        .next_token = next_token,
    };
}

fn parseDhcpOptions(allocator: Allocator, src: []const u8) !DhcpOptions {
    const dhcp_options_id = try req.xmlStr(allocator, src, "dhcpOptionsId");
    errdefer allocator.free(dhcp_options_id);
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

    const configurations = try parseConfigurations(allocator, src);
    errdefer freeConfigurations(allocator, configurations);

    return .{
        .allocator = allocator,
        .dhcp_options_id = dhcp_options_id,
        .owner_id = owner_id,
        .name = name,
        .tags = tags,
        .configurations = configurations,
    };
}

fn parseConfigurations(allocator: Allocator, src: []const u8) ![]Configuration {
    var items: std.ArrayList(Configuration) = .empty;
    errdefer {
        for (items.items) |c| {
            allocator.free(c.key);
            freeValues(allocator, c.values);
        }
        items.deinit(allocator);
    }

    const set = xml.child(src, "dhcpConfigurationSet") orelse return items.toOwnedSlice(allocator);
    var it: xml.ChildIterator = .{ .src = set, .name = "item" };
    while (it.next()) |item| {
        const key = try req.xmlStr(allocator, item, "key");
        errdefer allocator.free(key);
        const values = try parseValues(allocator, item);
        errdefer freeValues(allocator, values);
        try items.append(allocator, .{ .key = key, .values = values });
    }
    return items.toOwnedSlice(allocator);
}

fn parseValues(allocator: Allocator, src: []const u8) ![][]u8 {
    var values: std.ArrayList([]u8) = .empty;
    errdefer {
        for (values.items) |v| allocator.free(v);
        values.deinit(allocator);
    }

    const set = xml.child(src, "valueSet") orelse return values.toOwnedSlice(allocator);
    var it: xml.ChildIterator = .{ .src = set, .name = "item" };
    while (it.next()) |item| {
        const value = try req.xmlStr(allocator, item, "value");
        errdefer allocator.free(value);
        try values.append(allocator, value);
    }
    return values.toOwnedSlice(allocator);
}

// ============================================================================
// Tests
// ============================================================================

const sample =
    \\<?xml version="1.0" encoding="UTF-8"?>
    \\<DescribeDhcpOptionsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
    \\  <requestId>req-1</requestId>
    \\  <dhcpOptionsSet>
    \\    <item>
    \\      <dhcpOptionsId>dopt-0abc</dhcpOptionsId>
    \\      <ownerId>123456789012</ownerId>
    \\      <dhcpConfigurationSet>
    \\        <item>
    \\          <key>domain-name</key>
    \\          <valueSet><item><value>example.com</value></item></valueSet>
    \\        </item>
    \\        <item>
    \\          <key>domain-name-servers</key>
    \\          <valueSet>
    \\            <item><value>10.0.0.2</value></item>
    \\            <item><value>AmazonProvidedDNS</value></item>
    \\          </valueSet>
    \\        </item>
    \\      </dhcpConfigurationSet>
    \\      <tagSet>
    \\        <item><key>Name</key><value>corp &amp; co</value></item>
    \\      </tagSet>
    \\    </item>
    \\    <item>
    \\      <dhcpOptionsId>dopt-bare</dhcpOptionsId>
    \\      <dhcpConfigurationSet/>
    \\      <tagSet/>
    \\    </item>
    \\  </dhcpOptionsSet>
    \\  <nextToken>TOKEN</nextToken>
    \\</DescribeDhcpOptionsResponse>
;

test "parseResponse dhcp options" {
    const result = try parseResponse(std.testing.allocator, sample);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 2), result.dhcp_options.len);
    const d = result.dhcp_options[0];
    try std.testing.expectEqualStrings("dopt-0abc", d.dhcp_options_id);
    try std.testing.expectEqualStrings("123456789012", d.owner_id);
    try std.testing.expectEqualStrings("corp & co", d.name);
    try std.testing.expectEqual(@as(usize, 1), d.tags.len);
    try std.testing.expectEqual(@as(usize, 2), d.configurations.len);
    try std.testing.expectEqualStrings("domain-name", d.configurations[0].key);
    try std.testing.expectEqual(@as(usize, 1), d.configurations[0].values.len);
    try std.testing.expectEqualStrings("example.com", d.configurations[0].values[0]);
    try std.testing.expectEqualStrings("domain-name-servers", d.configurations[1].key);
    try std.testing.expectEqual(@as(usize, 2), d.configurations[1].values.len);
    try std.testing.expectEqualStrings("AmazonProvidedDNS", d.configurations[1].values[1]);

    const bare = result.dhcp_options[1];
    try std.testing.expectEqualStrings("", bare.name);
    try std.testing.expectEqual(@as(usize, 0), bare.configurations.len);
    try std.testing.expectEqualStrings("TOKEN", result.next_token.?);
}

test "parseResponse empty set" {
    const result = try parseResponse(
        std.testing.allocator,
        "<DescribeDhcpOptionsResponse><requestId>r</requestId><dhcpOptionsSet/></DescribeDhcpOptionsResponse>",
    );
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 0), result.dhcp_options.len);
    try std.testing.expect(result.next_token == null);
}

test "buildBody action only" {
    const body = try buildBody(std.testing.allocator, .{});
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("Action=DescribeDhcpOptions&Version=2016-11-15", body);
}

test "buildBody ids filters and paging" {
    const body = try buildBody(std.testing.allocator, .{
        .dhcp_options_ids = &.{ "dopt-1", "dopt-2" },
        .filters = &.{.{ .name = "key", .values = &.{ "domain-name", "ntp-servers" } }},
        .max_results = 5,
        .next_token = "tok/en",
    });
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings(
        "Action=DescribeDhcpOptions&Version=2016-11-15&DhcpOptionsId.1=dopt-1&DhcpOptionsId.2=dopt-2" ++
            "&Filter.1.Name=key&Filter.1.Value.1=domain-name&Filter.1.Value.2=ntp-servers" ++
            "&MaxResults=5&NextToken=tok%2Fen",
        body,
    );
}
