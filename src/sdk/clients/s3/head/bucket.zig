const std = @import("std");
const Allocator = std.mem.Allocator;

const sigv4 = @import("../../../sig/sigv4.zig");
const Credentials = @import("../../../credentials/fetcher.zig").Credentials;
const aws_errors = @import("../../aws_errors.zig");

pub const headBucketError = error{NoSuchBucket};

pub const Result = struct {
    allocator: Allocator,
    access_point_alias: bool,
    region: []u8,

    pub fn deinit(self: Result) void {
        self.allocator.free(self.region);
    }
};

pub fn HeadBucket(
    allocator: Allocator,
    io: std.Io,
    name: []const u8,
    region: ?[]const u8,
    credentials: Credentials,
) !Result {
    var extra_headers = std.StringHashMap([]const u8).init(allocator);
    defer extra_headers.deinit();
    if (credentials.session_token) |token| {
        try extra_headers.put("X-Amz-Security-Token", token);
    }

    var http_client = std.http.Client{ .allocator = allocator, .io = io };
    defer http_client.deinit();

    const initial_region = region orelse "us-east-1";

    // First attempt: global endpoint, sign with initial region.
    var request_url = try std.fmt.allocPrint(allocator, "https://{s}.s3.amazonaws.com/", .{name});
    errdefer allocator.free(request_url);

    var signed = try sigv4.sign(allocator, io, .{
        .access_key = credentials.access_key_id,
        .secret_key = credentials.secret_access_key,
        .region = initial_region,
        .service = "s3",
    }, .HEAD, request_url, extra_headers, "", null);

    var header_list: std.ArrayList(std.http.Header) = .empty;
    {
        var iter = signed.headers.iterator();
        while (iter.next()) |entry| {
            if (std.ascii.eqlIgnoreCase(entry.key_ptr.*, "host")) continue;
            try header_list.append(allocator, .{ .name = entry.key_ptr.*, .value = entry.value_ptr.* });
        }
    }

    var uri = try std.Uri.parse(request_url);
    var req = try http_client.request(.HEAD, uri, .{ .extra_headers = header_list.items });
    try req.sendBodiless();

    var redirect_buf: [4096]u8 = undefined;
    var response = try req.receiveHead(&redirect_buf);

    // S3 returns 301 or 400 with x-amz-bucket-region when bucket is in a
    // different region than the endpoint. Retry against the regional endpoint.
    if (response.head.status == .moved_permanently or response.head.status == .temporary_redirect or response.head.status == .bad_request) {
        const raw_region = extractHeader(response.head.bytes, "x-amz-bucket-region") orelse {
            std.log.err("HeadBucket {s}: HTTP {d} missing x-amz-bucket-region header", .{
                name, @intFromEnum(response.head.status),
            });
            req.deinit();
            signed.deinit();
            header_list.deinit(allocator);
            allocator.free(request_url);
            request_url = ""; // prevent errdefer double-free
            return error.MissingRegionHeader;
        };

        // Dupe before redirect_buf is overwritten by the retry receiveHead.
        const actual_region = try allocator.dupe(u8, raw_region);
        errdefer allocator.free(actual_region);

        req.deinit();
        signed.deinit();
        header_list.clearRetainingCapacity();
        allocator.free(request_url);
        request_url = "";

        const regional_url = try std.fmt.allocPrint(allocator, "https://{s}.s3.{s}.amazonaws.com/", .{ name, actual_region });
        request_url = regional_url;

        signed = try sigv4.sign(allocator, io, .{
            .access_key = credentials.access_key_id,
            .secret_key = credentials.secret_access_key,
            .region = actual_region,
            .service = "s3",
        }, .HEAD, regional_url, extra_headers, "", null);

        var iter = signed.headers.iterator();
        while (iter.next()) |entry| {
            if (std.ascii.eqlIgnoreCase(entry.key_ptr.*, "host")) continue;
            try header_list.append(allocator, .{ .name = entry.key_ptr.*, .value = entry.value_ptr.* });
        }

        uri = try std.Uri.parse(regional_url);
        req = try http_client.request(.HEAD, uri, .{ .extra_headers = header_list.items });
        try req.sendBodiless();
        response = try req.receiveHead(&redirect_buf);

        defer req.deinit();
        defer signed.deinit();
        defer header_list.deinit(allocator);

        switch (response.head.status) {
            .ok => {},
            .not_found => return error.NoSuchBucket,
            else => return aws_errors.fromStatus(response.head.status),
        }

        const bytes = response.head.bytes;
        const alias_raw = extractHeader(bytes, "x-amz-access-point-alias");
        const access_point_alias = if (alias_raw) |v| std.mem.eql(u8, v, "true") else false;

        return .{
            .allocator = allocator,
            .access_point_alias = access_point_alias,
            .region = actual_region,
        };
    }

    defer req.deinit();
    defer signed.deinit();
    defer header_list.deinit(allocator);

    switch (response.head.status) {
        .ok => {},
        .not_found => return error.NoSuchBucket,
        else => return aws_errors.fromStatus(response.head.status),
    }

    const bytes = response.head.bytes;
    const alias_raw = extractHeader(bytes, "x-amz-access-point-alias");
    const access_point_alias = if (alias_raw) |v| std.mem.eql(u8, v, "true") else false;

    const result_region = try allocator.dupe(u8, initial_region);
    errdefer allocator.free(result_region);

    return .{
        .allocator = allocator,
        .access_point_alias = access_point_alias,
        .region = result_region,
    };
}

fn extractHeader(bytes: []const u8, header_name: []const u8) ?[]const u8 {
    var it = std.mem.splitSequence(u8, bytes, "\r\n");
    _ = it.next(); // skip status line
    while (it.next()) |line| {
        if (line.len == 0) break;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = std.mem.trim(u8, line[0..colon], " \t");
        if (std.ascii.eqlIgnoreCase(name, header_name)) {
            return std.mem.trim(u8, line[colon + 1 ..], " \t");
        }
    }
    return null;
}
