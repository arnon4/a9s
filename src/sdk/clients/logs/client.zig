const std = @import("std");
const Allocator = std.mem.Allocator;

const Credentials = @import("../../credentials/fetcher.zig").Credentials;

const describeLogGroupsMod = @import("describe/log_groups.zig");
const describeLogGroupsImpl = describeLogGroupsMod.describeLogGroups;

pub const DescribeLogGroupsOptions = describeLogGroupsMod.Options;
pub const DescribeLogGroupsResult = describeLogGroupsMod.Result;
pub const LogGroup = describeLogGroupsMod.LogGroup;
pub const LogGroupClass = describeLogGroupsMod.LogGroupClass;
pub const DataProtectionStatus = describeLogGroupsMod.DataProtectionStatus;

const describeLogStreamsMod = @import("describe/log_streams.zig");
const describeLogStreamsImpl = describeLogStreamsMod.describeLogStreams;

pub const DescribeLogStreamsOptions = describeLogStreamsMod.Options;
pub const DescribeLogStreamsResult = describeLogStreamsMod.Result;
pub const LogStream = describeLogStreamsMod.LogStream;
pub const OrderBy = describeLogStreamsMod.OrderBy;

const getLogEventsMod = @import("get/log_events.zig");
const getLogEventsImpl = getLogEventsMod.getLogEvents;

pub const GetLogEventsOptions = getLogEventsMod.Options;
pub const GetLogEventsResult = getLogEventsMod.Result;
pub const OutputLogEvent = getLogEventsMod.OutputLogEvent;

const getLogGroupFieldsMod = @import("get/log_group_fields.zig");
const getLogGroupFieldsImpl = getLogGroupFieldsMod.getLogGroupFields;

pub const GetLogGroupFieldsOptions = getLogGroupFieldsMod.Options;
pub const GetLogGroupFieldsResult = getLogGroupFieldsMod.Result;
pub const LogGroupField = getLogGroupFieldsMod.LogGroupField;

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
            try std.fmt.allocPrint(allocator, "https://logs.{s}.amazonaws.com", .{options.region});

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

    pub fn describeLogGroups(self: *Client, options: DescribeLogGroupsOptions) !DescribeLogGroupsResult {
        return describeLogGroupsImpl(self, options);
    }

    pub fn describeLogStreams(self: *Client, options: DescribeLogStreamsOptions) !DescribeLogStreamsResult {
        return describeLogStreamsImpl(self, options);
    }

    pub fn getLogEvents(self: *Client, options: GetLogEventsOptions) !GetLogEventsResult {
        return getLogEventsImpl(self, options);
    }

    pub fn getLogGroupFields(self: *Client, options: GetLogGroupFieldsOptions) !GetLogGroupFieldsResult {
        return getLogGroupFieldsImpl(self, options);
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
    try std.testing.expectEqualStrings("https://logs.eu-west-1.amazonaws.com", c.endpoint);
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
