const std = @import("std");
const Allocator = std.mem.Allocator;

const sigv4 = @import("../../../sig/sigv4.zig");
const Credentials = @import("../../../credentials/fetcher.zig").Credentials;
const uri_utils = @import("../../../utils/uri.zig");
const aws_errors = @import("../../aws_errors.zig");

pub const headObjectError = error{NoSuchKey};

pub const Options = struct {
    bucket: []const u8,
    key: []const u8,
    version_id: ?[]const u8 = null,
    /// Set to true to include x-amz-checksum-mode: ENABLED, which causes S3
    /// to return the stored checksum value in the response headers.
    checksum_mode: bool = false,
};

pub const Result = struct {
    allocator: Allocator,
    content_type: []u8,
    server_side_encryption: ?[]u8,
    object_lock_mode: ?[]u8,
    object_lock_legal_hold: ?[]u8,
    checksum_value: ?[]u8,

    pub fn deinit(self: Result) void {
        self.allocator.free(self.content_type);
        if (self.server_side_encryption) |s| self.allocator.free(s);
        if (self.object_lock_mode) |s| self.allocator.free(s);
        if (self.object_lock_legal_hold) |s| self.allocator.free(s);
        if (self.checksum_value) |s| self.allocator.free(s);
    }
};

pub fn headObject(client: anytype, options: Options) !Result {
    return headObjectWithIo(
        client.allocator,
        client.io,
        client.virtual_hosted,
        client.endpoint,
        client.region,
        client.credentials,
        options,
    );
}

pub fn headObjectWithIo(
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
    if (options.checksum_mode) {
        try extra_headers.put("x-amz-checksum-mode", "ENABLED");
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
        .HEAD,
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
    var req = try http_client.request(.HEAD, uri, .{
        .extra_headers = header_list.items,
    });
    defer req.deinit();
    try req.sendBodiless();

    var redirect_buf: [4096]u8 = undefined;
    const response = try req.receiveHead(&redirect_buf);

    if (response.head.status != .ok) {
        if (response.head.status == .not_found) return error.NoSuchKey;
        return aws_errors.fromStatus(response.head.status);
    }

    const bytes = response.head.bytes;

    const content_type_raw = response.head.content_type orelse "";
    const content_type = try allocator.dupe(u8, content_type_raw);
    errdefer allocator.free(content_type);

    const server_side_encryption = try dupHeader(allocator, bytes, "x-amz-server-side-encryption");
    errdefer if (server_side_encryption) |s| allocator.free(s);

    const object_lock_mode = try dupHeader(allocator, bytes, "x-amz-object-lock-mode");
    errdefer if (object_lock_mode) |s| allocator.free(s);

    const object_lock_legal_hold = try dupHeader(allocator, bytes, "x-amz-object-lock-legal-hold-status");
    errdefer if (object_lock_legal_hold) |s| allocator.free(s);

    const checksum_value = try findChecksumHeader(allocator, bytes);

    return .{
        .allocator = allocator,
        .content_type = content_type,
        .server_side_encryption = server_side_encryption,
        .object_lock_mode = object_lock_mode,
        .object_lock_legal_hold = object_lock_legal_hold,
        .checksum_value = checksum_value,
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

fn dupHeader(allocator: Allocator, bytes: []const u8, header_name: []const u8) !?[]u8 {
    const val = extractHeader(bytes, header_name) orelse return null;
    return try allocator.dupe(u8, val);
}

fn findChecksumHeader(allocator: Allocator, bytes: []const u8) !?[]u8 {
    const names = [_][]const u8{
        "x-amz-checksum-crc32",
        "x-amz-checksum-crc32c",
        "x-amz-checksum-sha1",
        "x-amz-checksum-sha256",
        "x-amz-checksum-crc64nvme",
    };
    for (names) |h| {
        if (extractHeader(bytes, h)) |v| return try allocator.dupe(u8, v);
    }
    return null;
}
