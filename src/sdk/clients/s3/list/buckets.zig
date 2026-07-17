const std = @import("std");
const Allocator = std.mem.Allocator;

const sigv4 = @import("../../../sig/sigv4.zig");
const xml = @import("../../../utils/xml.zig");
const aws_errors = @import("../../aws_errors.zig");

pub const Options = struct {
    bucket_region: ?[]const u8 = null,
    continuation_token: ?[]const u8 = null,
    max_buckets: ?[]const u8 = null,
    prefix: ?[]const u8 = null,
};

pub const Bucket = struct {
    allocator: Allocator,
    name: []u8,
    creation_date: []u8,
    region: []u8,
    profile_name: []u8 = "",

    pub fn deinit(self: Bucket) void {
        self.allocator.free(self.name);
        self.allocator.free(self.creation_date);
        self.allocator.free(self.region);
        if (self.profile_name.len > 0) self.allocator.free(self.profile_name);
    }

    pub fn clone(self: Bucket, allocator: Allocator) !Bucket {
        const name = try allocator.dupe(u8, self.name);
        errdefer allocator.free(name);
        const creation_date = try allocator.dupe(u8, self.creation_date);
        errdefer allocator.free(creation_date);
        const region = try allocator.dupe(u8, self.region);
        errdefer allocator.free(region);
        const profile_name = if (self.profile_name.len > 0)
            try allocator.dupe(u8, self.profile_name)
        else
            @as([]u8, &.{});
        return .{
            .allocator = allocator,
            .name = name,
            .creation_date = creation_date,
            .region = region,
            .profile_name = profile_name,
        };
    }
};

pub const Result = struct {
    allocator: Allocator,
    buckets: []Bucket,
    is_truncated: bool,
    next_continuation_token: ?[]u8,

    pub fn deinit(self: Result) void {
        for (self.buckets) |b| b.deinit();
        self.allocator.free(self.buckets);
        if (self.next_continuation_token) |t| self.allocator.free(t);
    }
};

/// ListBuckets
pub fn listBuckets(client: anytype, options: Options) !Result {
    var query = std.ArrayList(u8).empty;
    defer query.deinit(client.allocator);
    var first = true;
    inline for (@typeInfo(Options).@"struct".fields) |field| {
        if (@field(options, field.name)) |v| {
            const param_name: []const u8 = comptime blk: {
                var buf: [field.name.len]u8 = undefined;
                for (field.name, 0..) |c, i| buf[i] = if (c == '_') '-' else c;
                const frozen = buf;
                break :blk &frozen;
            };
            try query.appendSlice(client.allocator, if (first) "?" else "&");
            first = false;
            try query.appendSlice(client.allocator, param_name);
            try query.append(client.allocator, '=');
            try query.appendSlice(client.allocator, v);
        }
    }
    const base_url = if (options.bucket_region) |region|
        try std.fmt.allocPrint(client.allocator, "https://s3.{s}.amazonaws.com", .{region})
    else
        try std.fmt.allocPrint(client.allocator, "{s}", .{client.endpoint});
    defer client.allocator.free(base_url);

    const request_url = try std.fmt.allocPrint(client.allocator, "{s}/{s}", .{ base_url, query.items });
    defer client.allocator.free(request_url);

    var extra_headers = std.StringHashMap([]const u8).init(client.allocator);
    defer extra_headers.deinit();
    if (client.credentials.session_token) |token| {
        try extra_headers.put("X-Amz-Security-Token", token);
    }

    var signed = try sigv4.sign(
        client.allocator,
        client.io,
        .{
            .access_key = client.credentials.access_key_id,
            .secret_key = client.credentials.secret_access_key,
            .region = client.region,
            .service = "s3",
        },
        .GET,
        request_url,
        extra_headers,
        "",
        "/",
    );
    defer signed.deinit();

    var header_list: std.ArrayList(std.http.Header) = .empty;
    defer header_list.deinit(client.allocator);
    var iter = signed.headers.iterator();
    while (iter.next()) |entry| {
        if (std.ascii.eqlIgnoreCase(entry.key_ptr.*, "host")) continue;
        try header_list.append(client.allocator, .{ .name = entry.key_ptr.*, .value = entry.value_ptr.* });
    }

    var http_client = std.http.Client{ .allocator = client.allocator, .io = client.io };
    defer http_client.deinit();

    var resp_writer: std.Io.Writer.Allocating = .init(client.allocator);
    defer resp_writer.deinit();

    const result = try http_client.fetch(.{
        .method = .GET,
        .location = .{ .url = request_url },
        .extra_headers = header_list.items,
        .response_writer = &resp_writer.writer,
    });

    const resp_body = resp_writer.writer.buffer[0..resp_writer.writer.end];

    if (result.status != .ok) {
        const code_str = xml.extractTagContent(client.allocator, resp_body, "Code") catch null;
        defer if (code_str) |c| client.allocator.free(c);
        if (code_str) |c| {
            std.log.err("S3 ListBuckets error: {s} (status {d})", .{ c, @intFromEnum(result.status) });
            return aws_errors.fromCode(c) orelse aws_errors.fromStatus(result.status);
        }
        return aws_errors.fromStatus(result.status);
    }

    return parseBuckets(client.allocator, resp_body);
}

fn parseBuckets(allocator: Allocator, body: []const u8) !Result {
    var buckets: std.ArrayList(Bucket) = .empty;
    errdefer {
        for (buckets.items) |b| b.deinit();
        buckets.deinit(allocator);
    }

    const open_tag = "<Bucket>";
    const close_tag = "</Bucket>";
    var search = body;

    while (std.mem.indexOf(u8, search, open_tag)) |start| {
        const content_start = start + open_tag.len;
        const end = std.mem.indexOf(u8, search[content_start..], close_tag) orelse break;
        const block = search[content_start .. content_start + end];

        const name = try xml.extractTagContent(allocator, block, "Name");
        errdefer allocator.free(name);
        const creation_date = try xml.extractTagContent(allocator, block, "CreationDate");
        errdefer allocator.free(creation_date);
        const bucket_region = xml.extractTagContent(allocator, block, "BucketRegion") catch |e| switch (e) {
            error.XmlTagNotFound => try allocator.dupe(u8, "-"),
            else => return e,
        };
        errdefer allocator.free(bucket_region);

        try buckets.append(allocator, .{
            .allocator = allocator,
            .name = name,
            .creation_date = creation_date,
            .region = bucket_region,
        });

        search = search[content_start + end + close_tag.len ..];
    }

    const is_truncated: bool = blk: {
        const s = xml.extractTagContent(allocator, body, "IsTruncated") catch break :blk false;
        defer allocator.free(s);
        break :blk std.mem.eql(u8, s, "true");
    };

    const next_continuation_token = xml.extractTagContent(allocator, body, "NextContinuationToken") catch |e| switch (e) {
        error.XmlTagNotFound => null,
        else => return e,
    };
    errdefer if (next_continuation_token) |t| allocator.free(t);

    return .{
        .allocator = allocator,
        .buckets = try buckets.toOwnedSlice(allocator),
        .is_truncated = is_truncated,
        .next_continuation_token = next_continuation_token,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "parseBuckets empty" {
    const body = "<?xml version=\"1.0\"?><ListAllMyBucketsResult><Buckets></Buckets></ListAllMyBucketsResult>";
    const result = try parseBuckets(std.testing.allocator, body);
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 0), result.buckets.len);
}

test "parseBuckets multiple" {
    const body =
        \\<ListAllMyBucketsResult><Buckets>
        \\<Bucket><Name>foo</Name><CreationDate>2024-01-01T00:00:00.000Z</CreationDate></Bucket>
        \\<Bucket><Name>bar</Name><CreationDate>2024-06-15T12:00:00.000Z</CreationDate></Bucket>
        \\</Buckets></ListAllMyBucketsResult>
    ;
    const result = try parseBuckets(std.testing.allocator, body);
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 2), result.buckets.len);
    try std.testing.expectEqualStrings("foo", result.buckets[0].name);
    try std.testing.expectEqualStrings("bar", result.buckets[1].name);
    try std.testing.expectEqualStrings("2024-01-01T00:00:00.000Z", result.buckets[0].creation_date);
}
