const std = @import("std");
const Allocator = std.mem.Allocator;

const sigv4 = @import("../../../sig/sigv4.zig");
const Credentials = @import("../../../credentials/fetcher.zig").Credentials;
const uri_utils = @import("../../../utils/uri.zig");
const aws_errors = @import("../../aws_errors.zig");
const xml = @import("../../../utils/xml.zig");

pub const getObjectError = error{
    InvalidObjectState, // 403
    NoSuchKey, // 404
};

pub const Options = struct {
    bucket: []const u8,
    key: []const u8,
    version_id: ?[]const u8 = null,
    /// Byte range, e.g. "bytes=0-5242879". Omit for the whole object.
    range: ?[]const u8 = null,
};

pub const Result = struct {
    allocator: Allocator,
    body: []u8,
    content_type: []u8,

    pub fn deinit(self: Result) void {
        self.allocator.free(self.body);
        self.allocator.free(self.content_type);
    }
};

pub fn getObject(client: anytype, options: Options) !Result {
    return getObjectWithIo(
        client.allocator,
        client.io,
        client.virtual_hosted,
        client.endpoint,
        client.region,
        client.credentials,
        options,
    );
}

pub fn getObjectWithIo(
    allocator: Allocator,
    io: std.Io,
    virtual_hosted: bool,
    endpoint: []const u8,
    region: []const u8,
    credentials: Credentials,
    options: Options,
) !Result {
    const encoded_key = try uri_utils.encodeS3Path(allocator, options.key);
    defer allocator.free(encoded_key);

    const request_url = if (virtual_hosted) blk: {
        if (options.version_id) |vid|
            break :blk try std.fmt.allocPrint(allocator, "https://{s}.s3.{s}.amazonaws.com/{s}?versionId={s}", .{ options.bucket, region, encoded_key, vid })
        else
            break :blk try std.fmt.allocPrint(allocator, "https://{s}.s3.{s}.amazonaws.com/{s}", .{ options.bucket, region, encoded_key });
    } else blk: {
        if (options.version_id) |vid|
            break :blk try std.fmt.allocPrint(allocator, "{s}/{s}/{s}?versionId={s}", .{ endpoint, options.bucket, encoded_key, vid })
        else
            break :blk try std.fmt.allocPrint(allocator, "{s}/{s}/{s}", .{ endpoint, options.bucket, encoded_key });
    };
    defer allocator.free(request_url);

    var extra_headers = std.StringHashMap([]const u8).init(allocator);
    defer extra_headers.deinit();
    if (credentials.session_token) |token| {
        try extra_headers.put("X-Amz-Security-Token", token);
    }
    if (options.range) |r| {
        try extra_headers.put("Range", r);
    }

    var signed = try sigv4.sign(
        allocator,
        io,
        .{
            .access_key = credentials.access_key_id,
            .secret_key = credentials.secret_access_key,
            .region = region,
            .service = "s3",
        },
        .GET,
        request_url,
        extra_headers,
        "",
        null,
    );
    defer signed.deinit();

    var header_list: std.ArrayList(std.http.Header) = .empty;
    defer header_list.deinit(allocator);
    var iter = signed.headers.iterator();
    while (iter.next()) |entry| {
        if (std.ascii.eqlIgnoreCase(entry.key_ptr.*, "host")) continue;
        try header_list.append(allocator, .{ .name = entry.key_ptr.*, .value = entry.value_ptr.* });
    }

    var http_client = std.http.Client{ .allocator = allocator, .io = io };
    defer http_client.deinit();

    const uri = try std.Uri.parse(request_url);
    var req = try http_client.request(.GET, uri, .{
        .extra_headers = header_list.items,
    });
    defer req.deinit();
    try req.sendBodiless();

    var redirect_buf: [4096]u8 = undefined;
    const response = try req.receiveHead(&redirect_buf);

    if (response.head.status != .ok and response.head.status != .partial_content) {
        const err_body_reader = req.reader.bodyReader(&.{}, response.head.transfer_encoding, response.head.content_length);
        var err_buf: [4096]u8 = undefined;
        const err_n = err_body_reader.readSliceShort(&err_buf) catch 0;
        const body = err_buf[0..err_n];
        const code_str = xml.extractTagContent(allocator, body, "Code") catch null;
        defer if (code_str) |c| allocator.free(c);
        if (code_str) |c| {
            std.log.err("S3 GetObject error: {s} (status {d})", .{ c, @intFromEnum(response.head.status) });
            inline for (@typeInfo(getObjectError).error_set.?) |entry| {
                if (std.mem.eql(u8, entry.name, c)) return @field(getObjectError, entry.name);
            }
            return aws_errors.fromCode(c) orelse aws_errors.fromStatus(response.head.status);
        }
        std.log.err("S3 GetObject error: status {d}", .{@intFromEnum(response.head.status)});
        return aws_errors.fromStatus(response.head.status);
    }

    const content_type_raw = response.head.content_type orelse "";
    const content_type = try allocator.dupe(u8, content_type_raw);
    errdefer allocator.free(content_type);

    const body_reader = req.reader.bodyReader(&.{}, response.head.transfer_encoding, response.head.content_length);
    const body = try body_reader.allocRemaining(allocator, .unlimited);
    errdefer allocator.free(body);

    return .{
        .allocator = allocator,
        .body = body,
        .content_type = content_type,
    };
}
