const std = @import("std");
const Allocator = std.mem.Allocator;

const xml = @import("../../utils/xml.zig");
const Credentials = @import("../../credentials/fetcher.zig").Credentials;
const getMetricDataImpl = @import("get/metric_data.zig").getMetricData;

pub const GetMetricDataOptions = @import("get/metric_data.zig").Options;
pub const GetMetricDataResult = @import("get/metric_data.zig").Result;
pub const MetricDataResult = @import("get/metric_data.zig").MetricDataResult;
pub const MetricDataQuery = @import("get/metric_data.zig").MetricDataQuery;
pub const MetricStat = @import("get/metric_data.zig").MetricStat;
pub const Metric = @import("get/metric_data.zig").Metric;
pub const Dimension = @import("get/metric_data.zig").Dimension;
pub const MessageData = @import("get/metric_data.zig").MessageData;

pub const ClientOptions = struct {
    region: []const u8 = "us-east-1",
    io: std.Io,
    credentials: Credentials,
    endpoint_url: ?[]const u8 = null,
};

pub const CloudWatchError = struct {
    code: []const u8,
    message: []const u8,

    fn deinit(self: CloudWatchError, allocator: Allocator) void {
        allocator.free(self.code);
        allocator.free(self.message);
    }
};

pub const Client = struct {
    allocator: Allocator,
    io: std.Io,
    region: []const u8,
    credentials: Credentials,
    endpoint: []const u8,
    last_error: ?CloudWatchError = null,

    pub fn init(allocator: Allocator, options: ClientOptions) !Client {
        const endpoint = if (options.endpoint_url) |ep|
            try allocator.dupe(u8, ep)
        else
            try std.fmt.allocPrint(allocator, "https://monitoring.{s}.amazonaws.com/", .{options.region});

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
        if (self.last_error) |e| e.deinit(self.allocator);
    }

    pub fn clearLastError(self: *Client) void {
        if (self.last_error) |e| e.deinit(self.allocator);
        self.last_error = null;
    }

    pub fn setErrorFromBody(self: *Client, _: std.http.Status, body: []const u8) void {
        const code = xml.extractTagContent(self.allocator, body, "Code") catch {
            self.last_error = .{
                .code = self.allocator.dupe(u8, "(no xml)") catch return,
                .message = self.allocator.dupe(u8, body) catch return,
            };
            return;
        };
        const message = xml.extractTagContent(self.allocator, body, "Message") catch {
            self.allocator.free(code);
            return;
        };
        self.last_error = .{ .code = code, .message = message };
    }

    pub fn getMetricData(self: *Client, options: GetMetricDataOptions) !GetMetricDataResult {
        return getMetricDataImpl(self, options);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "Client init constructs regional endpoint" {
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
    try std.testing.expectEqualStrings("https://monitoring.eu-west-1.amazonaws.com/", c.endpoint);
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
        .endpoint_url = "http://localhost:4566/",
    });
    defer c.deinit();
    try std.testing.expectEqualStrings("http://localhost:4566/", c.endpoint);
}
