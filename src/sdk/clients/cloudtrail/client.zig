const std = @import("std");
const Allocator = std.mem.Allocator;

const Credentials = @import("../../credentials/fetcher.zig").Credentials;

const listTrailsMod = @import("list/trails.zig");
const listTrailsImpl = listTrailsMod.listTrails;

pub const ListTrailsOptions = listTrailsMod.Options;
pub const ListTrailsResult = listTrailsMod.Result;
pub const TrailInfo = listTrailsMod.TrailInfo;

const getTrailStatusMod = @import("get/trail_status.zig");
const getTrailStatusImpl = getTrailStatusMod.getTrailStatus;

pub const GetTrailStatusOptions = getTrailStatusMod.Options;
pub const GetTrailStatusResult = getTrailStatusMod.Result;

const describeTrailsMod = @import("describe/trails.zig");
const describeTrailsImpl = describeTrailsMod.describeTrails;

pub const DescribeTrailsOptions = describeTrailsMod.Options;
pub const DescribeTrailsResult = describeTrailsMod.Result;
pub const TrailDetail = describeTrailsMod.TrailDetail;

const lookupEventsMod = @import("lookup/events.zig");
const lookupEventsImpl = lookupEventsMod.lookupEvents;

pub const LookupEventsOptions = lookupEventsMod.Options;
pub const LookupEventsResult = lookupEventsMod.Result;
pub const LookupAttribute = lookupEventsMod.LookupAttribute;
pub const CloudTrailEvent = lookupEventsMod.Event;
pub const CloudTrailEventResource = lookupEventsMod.Resource;

pub const ClientOptions = struct {
    region: []const u8 = "us-east-1",
    io: std.Io,
    credentials: Credentials,
    endpoint_url: ?[]const u8 = null,
};

pub const Client = struct {
    allocator: Allocator,
    io: std.Io,
    region: []const u8,
    credentials: Credentials,
    endpoint: []const u8,

    pub fn init(allocator: Allocator, options: ClientOptions) !Client {
        const endpoint = if (options.endpoint_url) |ep|
            try allocator.dupe(u8, ep)
        else
            try std.fmt.allocPrint(allocator, "https://cloudtrail.{s}.amazonaws.com", .{options.region});

        return .{
            .allocator = allocator,
            .io = options.io,
            .region = options.region,
            .credentials = options.credentials,
            .endpoint = endpoint,
        };
    }

    pub fn deinit(self: *Client) void {
        self.allocator.free(self.endpoint);
    }

    pub fn listTrails(self: *Client, options: ListTrailsOptions) !ListTrailsResult {
        return listTrailsImpl(self, options);
    }

    pub fn getTrailStatus(self: *Client, options: GetTrailStatusOptions) !GetTrailStatusResult {
        return getTrailStatusImpl(self, options);
    }

    pub fn describeTrails(self: *Client, options: DescribeTrailsOptions) !DescribeTrailsResult {
        return describeTrailsImpl(self, options);
    }

    pub fn lookupEvents(self: *Client, options: LookupEventsOptions) !LookupEventsResult {
        return lookupEventsImpl(self, options);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "Client init regional endpoint" {
    const allocator = std.testing.allocator;
    var c = try Client.init(allocator, .{
        .region = "eu-west-1",
        .io = std.testing.io,
        .credentials = .{
            .access_key_id = "AKID",
            .secret_access_key = "SECRET",
            .session_token = null,
            .source = "test",
        },
    });
    defer c.deinit();
    try std.testing.expectEqualStrings("https://cloudtrail.eu-west-1.amazonaws.com", c.endpoint);
}

test "Client init custom endpoint" {
    const allocator = std.testing.allocator;
    var c = try Client.init(allocator, .{
        .region = "us-east-1",
        .io = std.testing.io,
        .credentials = .{
            .access_key_id = "AKID",
            .secret_access_key = "SECRET",
            .session_token = null,
            .source = "test",
        },
        .endpoint_url = "http://localhost:4566",
    });
    defer c.deinit();
    try std.testing.expectEqualStrings("http://localhost:4566", c.endpoint);
}
