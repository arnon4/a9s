const std = @import("std");
const Allocator = std.mem.Allocator;

const sigv4 = @import("../../../sig/sigv4.zig");
const xml = @import("../../../utils/xml.zig");
const aws_errors = @import("../../aws_errors.zig");

const typesMod = @import("../types.zig");

pub const listObjectsError = error{NoSuchBucket};

pub const Headers = struct {
    request_payer: ?typesMod.RequestPayer = null,
    expected_bucket_owner: ?[]const u8 = null,
    optional_object_attributes: ?typesMod.OptionlBucketAttributes = null,
};

pub const Params = struct {
    continuation_token: ?[]const u8 = null,
    delimiter: ?[]const u8 = null,
    encoding_type: ?typesMod.EncodingType = null,
    fetch_owner: ?bool = null,
    max_keys: ?usize = null,
    prefix: ?[]const u8 = null,
    start_after: ?[]const u8 = null,
};

pub const Options = struct {
    bucket: []const u8,
    headers: Headers = .{},
    query_params: Params = .{},
};

pub const Owner = struct {
    allocator: Allocator,
    id: []u8,
    display_name: []u8,

    pub fn deinit(self: Owner) void {
        self.allocator.free(self.id);
        self.allocator.free(self.display_name);
    }

    pub fn clone(self: Owner, allocator: Allocator) !Owner {
        const id = try allocator.dupe(u8, self.id);
        errdefer allocator.free(id);
        const display_name = try allocator.dupe(u8, self.display_name);
        return .{ .allocator = allocator, .id = id, .display_name = display_name };
    }
};

pub const RestoreStatus = struct {
    is_restore_in_progress: bool,
    restore_expiry_date: ?[]u8,

    pub fn deinit(self: RestoreStatus, allocator: Allocator) void {
        if (self.restore_expiry_date) |d| allocator.free(d);
    }

    pub fn clone(self: RestoreStatus, allocator: Allocator) !RestoreStatus {
        return .{
            .is_restore_in_progress = self.is_restore_in_progress,
            .restore_expiry_date = if (self.restore_expiry_date) |d|
                try allocator.dupe(u8, d)
            else
                null,
        };
    }
};

pub const Object = struct {
    allocator: Allocator,
    key: []u8,
    last_modified: []u8,
    etag: []u8,
    size: u64,
    storage_class: typesMod.StorageClass,
    checksum_algorithm: ?typesMod.ChecksumAlgorithm,
    checksum_type: ?typesMod.ChecksumType,
    owner: ?Owner,
    restore_status: ?RestoreStatus,

    pub fn deinit(self: Object) void {
        self.allocator.free(self.key);
        self.allocator.free(self.last_modified);
        self.allocator.free(self.etag);
        if (self.owner) |o| o.deinit();
        if (self.restore_status) |rs| rs.deinit(self.allocator);
    }

    pub fn clone(self: Object, allocator: Allocator) !Object {
        const key = try allocator.dupe(u8, self.key);
        errdefer allocator.free(key);
        const last_modified = try allocator.dupe(u8, self.last_modified);
        errdefer allocator.free(last_modified);
        const etag = try allocator.dupe(u8, self.etag);
        errdefer allocator.free(etag);
        const owner: ?Owner = if (self.owner) |o| try o.clone(allocator) else null;
        errdefer if (owner) |o| o.deinit();
        const restore_status: ?RestoreStatus = if (self.restore_status) |rs| try rs.clone(allocator) else null;
        return .{
            .allocator = allocator,
            .key = key,
            .last_modified = last_modified,
            .etag = etag,
            .size = self.size,
            .storage_class = self.storage_class,
            .checksum_algorithm = self.checksum_algorithm,
            .checksum_type = self.checksum_type,
            .owner = owner,
            .restore_status = restore_status,
        };
    }
};

pub const Result = struct {
    allocator: Allocator,
    name: []u8,
    prefix: []u8,
    is_truncated: bool,
    key_count: usize,
    max_keys: usize,
    objects: []Object,
    delimiter: ?[]u8,
    encoding_type: ?typesMod.EncodingType,
    continuation_token: ?[]u8,
    next_continuation_token: ?[]u8,
    start_after: ?[]u8,
    common_prefixes: ?[][]u8,

    pub fn deinit(self: Result) void {
        self.allocator.free(self.name);
        self.allocator.free(self.prefix);
        for (self.objects) |o| o.deinit();
        self.allocator.free(self.objects);
        if (self.delimiter) |d| self.allocator.free(d);
        if (self.continuation_token) |t| self.allocator.free(t);
        if (self.next_continuation_token) |t| self.allocator.free(t);
        if (self.start_after) |s| self.allocator.free(s);
        if (self.common_prefixes) |cp| {
            for (cp) |p| self.allocator.free(p);
            self.allocator.free(cp);
        }
    }
};

/// ListObjectsV2
pub fn listObjects(client: anytype, options: Options) !Result {
    var query = std.ArrayList(u8).empty;
    defer query.deinit(client.allocator);
    try query.appendSlice(client.allocator, "?list-type=2");

    inline for (@typeInfo(Params).@"struct".fields) |field| {
        if (@field(options.query_params, field.name)) |v| {
            const param_name: []const u8 = comptime blk: {
                var buf: [field.name.len]u8 = undefined;
                for (field.name, 0..) |c, i| buf[i] = if (c == '_') '-' else c;
                const frozen = buf;
                break :blk &frozen;
            };
            try query.appendSlice(client.allocator, "&");
            try query.appendSlice(client.allocator, param_name);
            try query.append(client.allocator, '=');
            switch (@TypeOf(v)) {
                []const u8 => try query.appendSlice(client.allocator, v),
                bool => try query.appendSlice(client.allocator, if (v) "true" else "false"),
                usize => {
                    const s = try std.fmt.allocPrint(client.allocator, "{d}", .{v});
                    defer client.allocator.free(s);
                    try query.appendSlice(client.allocator, s);
                },
                else => try query.appendSlice(client.allocator, @tagName(v)),
            }
        }
    }

    const request_url = if (client.virtual_hosted)
        try std.fmt.allocPrint(client.allocator, "https://{s}.s3.{s}.amazonaws.com{s}", .{ options.bucket, client.region, query.items })
    else
        try std.fmt.allocPrint(client.allocator, "{s}/{s}{s}", .{ client.endpoint, options.bucket, query.items });
    defer client.allocator.free(request_url);

    var extra_headers = std.StringHashMap([]const u8).init(client.allocator);
    defer extra_headers.deinit();
    if (client.credentials.session_token) |token| {
        try extra_headers.put("X-Amz-Security-Token", token);
    }
    if (options.headers.request_payer) |_| {
        try extra_headers.put("x-amz-request-payer", "requester");
    }
    if (options.headers.expected_bucket_owner) |v| {
        try extra_headers.put("x-amz-expected-bucket-owner", v);
    }
    if (options.headers.optional_object_attributes) |v| {
        try extra_headers.put("x-amz-optional-object-attributes", @tagName(v));
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
        null,
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
            std.log.err("S3 ListObjects error: {s} (status {d})", .{ c, @intFromEnum(result.status) });
            inline for (@typeInfo(listObjectsError).error_set.?) |entry| {
                if (std.mem.eql(u8, entry.name, c)) return @field(listObjectsError, entry.name);
            }
            return aws_errors.fromCode(c) orelse aws_errors.fromStatus(result.status);
        }
        return aws_errors.fromStatus(result.status);
    }

    return parseObjects(client.allocator, resp_body);
}

fn parseObjects(allocator: Allocator, body: []const u8) !Result {
    const name = try xml.extractTagContent(allocator, body, "Name");
    errdefer allocator.free(name);

    const prefix = xml.extractTagContent(allocator, body, "Prefix") catch |e| switch (e) {
        error.XmlTagNotFound => try allocator.dupe(u8, ""),
        else => return e,
    };
    errdefer allocator.free(prefix);

    const is_truncated: bool = blk: {
        const s = try xml.extractTagContent(allocator, body, "IsTruncated");
        defer allocator.free(s);
        break :blk std.mem.eql(u8, s, "true");
    };

    const max_keys: usize = blk: {
        const s = try xml.extractTagContent(allocator, body, "MaxKeys");
        defer allocator.free(s);
        break :blk try std.fmt.parseInt(usize, std.mem.trim(u8, s, " \t\r\n"), 10);
    };

    const key_count: usize = blk: {
        const s = try xml.extractTagContent(allocator, body, "KeyCount");
        defer allocator.free(s);
        break :blk try std.fmt.parseInt(usize, std.mem.trim(u8, s, " \t\r\n"), 10);
    };

    const delimiter = xml.extractTagContent(allocator, body, "Delimiter") catch |e| switch (e) {
        error.XmlTagNotFound => null,
        else => return e,
    };
    errdefer if (delimiter) |d| allocator.free(d);

    const encoding_type: ?typesMod.EncodingType = blk: {
        const s = xml.extractTagContent(allocator, body, "EncodingType") catch |e| switch (e) {
            error.XmlTagNotFound => break :blk null,
            else => return e,
        };
        defer allocator.free(s);
        const et = std.meta.stringToEnum(typesMod.EncodingType, s) orelse {
            std.log.err("S3 ListObjects: unknown EncodingType: {s}", .{s});
            return error.UnknownEncodingType;
        };
        break :blk et;
    };

    const continuation_token = xml.extractTagContent(allocator, body, "ContinuationToken") catch |e| switch (e) {
        error.XmlTagNotFound => null,
        else => return e,
    };
    errdefer if (continuation_token) |t| allocator.free(t);

    const next_continuation_token = xml.extractTagContent(allocator, body, "NextContinuationToken") catch |e| switch (e) {
        error.XmlTagNotFound => null,
        else => return e,
    };
    errdefer if (next_continuation_token) |t| allocator.free(t);

    const start_after = xml.extractTagContent(allocator, body, "StartAfter") catch |e| switch (e) {
        error.XmlTagNotFound => null,
        else => return e,
    };
    errdefer if (start_after) |s| allocator.free(s);

    var objects: std.ArrayList(Object) = .empty;
    errdefer {
        for (objects.items) |o| o.deinit();
        objects.deinit(allocator);
    }
    {
        const open_tag = "<Contents>";
        const close_tag = "</Contents>";
        var search = body;
        while (std.mem.indexOf(u8, search, open_tag)) |start| {
            const content_start = start + open_tag.len;
            const end = std.mem.indexOf(u8, search[content_start..], close_tag) orelse break;
            const block = search[content_start .. content_start + end];
            try objects.append(allocator, try parseObject(allocator, block));
            search = search[content_start + end + close_tag.len ..];
        }
    }

    var cp_list: std.ArrayList([]u8) = .empty;
    errdefer {
        for (cp_list.items) |p| allocator.free(p);
        cp_list.deinit(allocator);
    }
    {
        const open_tag = "<CommonPrefixes>";
        const close_tag = "</CommonPrefixes>";
        var search = body;
        while (std.mem.indexOf(u8, search, open_tag)) |start| {
            const content_start = start + open_tag.len;
            const end = std.mem.indexOf(u8, search[content_start..], close_tag) orelse break;
            const block = search[content_start .. content_start + end];
            try cp_list.append(allocator, try xml.extractTagContent(allocator, block, "Prefix"));
            search = search[content_start + end + close_tag.len ..];
        }
    }

    const common_prefixes: ?[][]u8 = if (cp_list.items.len > 0)
        try cp_list.toOwnedSlice(allocator)
    else
        null;
    errdefer if (common_prefixes) |cp| {
        for (cp) |p| allocator.free(p);
        allocator.free(cp);
    };

    return .{
        .allocator = allocator,
        .name = name,
        .prefix = prefix,
        .is_truncated = is_truncated,
        .key_count = key_count,
        .max_keys = max_keys,
        .objects = try objects.toOwnedSlice(allocator),
        .delimiter = delimiter,
        .encoding_type = encoding_type,
        .continuation_token = continuation_token,
        .next_continuation_token = next_continuation_token,
        .start_after = start_after,
        .common_prefixes = common_prefixes,
    };
}

fn parseObject(allocator: Allocator, block: []const u8) !Object {
    const key = try xml.extractTagContent(allocator, block, "Key");
    errdefer allocator.free(key);

    const last_modified = try xml.extractTagContent(allocator, block, "LastModified");
    errdefer allocator.free(last_modified);

    const etag = try xml.extractTagContent(allocator, block, "ETag");
    errdefer allocator.free(etag);

    const size: u64 = blk: {
        const s = try xml.extractTagContent(allocator, block, "Size");
        defer allocator.free(s);
        break :blk try std.fmt.parseInt(u64, std.mem.trim(u8, s, " \t\r\n"), 10);
    };

    const storage_class: typesMod.StorageClass = blk: {
        const s = try xml.extractTagContent(allocator, block, "StorageClass");
        defer allocator.free(s);
        const sc = std.meta.stringToEnum(typesMod.StorageClass, s) orelse {
            std.log.err("S3 ListObjects: unknown StorageClass: {s}", .{s});
            return error.UnknownStorageClass;
        };
        break :blk sc;
    };

    const checksum_algorithm: ?typesMod.ChecksumAlgorithm = blk: {
        const s = xml.extractTagContent(allocator, block, "ChecksumAlgorithm") catch |e| switch (e) {
            error.XmlTagNotFound => break :blk null,
            else => return e,
        };
        defer allocator.free(s);
        const ca = std.meta.stringToEnum(typesMod.ChecksumAlgorithm, s) orelse {
            std.log.err("S3 ListObjects: unknown ChecksumAlgorithm: {s}", .{s});
            return error.UnknownChecksumAlgorithm;
        };
        break :blk ca;
    };

    const checksum_type: ?typesMod.ChecksumType = blk: {
        const s = xml.extractTagContent(allocator, block, "ChecksumType") catch |e| switch (e) {
            error.XmlTagNotFound => break :blk null,
            else => return e,
        };
        defer allocator.free(s);
        const ct = std.meta.stringToEnum(typesMod.ChecksumType, s) orelse {
            std.log.err("S3 ListObjects: unknown ChecksumType: {s}", .{s});
            return error.UnknownChecksumType;
        };
        break :blk ct;
    };

    const owner: ?Owner = blk: {
        const owner_block = xml.extractTagContent(allocator, block, "Owner") catch |e| switch (e) {
            error.XmlTagNotFound => break :blk null,
            else => return e,
        };
        defer allocator.free(owner_block);

        const id = try xml.extractTagContent(allocator, owner_block, "ID");
        errdefer allocator.free(id);
        const display_name = xml.extractTagContent(allocator, owner_block, "DisplayName") catch |e| switch (e) {
            error.XmlTagNotFound => try allocator.dupe(u8, ""),
            else => return e,
        };

        break :blk Owner{
            .allocator = allocator,
            .id = id,
            .display_name = display_name,
        };
    };
    errdefer if (owner) |o| o.deinit();

    const restore_status: ?RestoreStatus = blk: {
        const rs_block = xml.extractTagContent(allocator, block, "RestoreStatus") catch |e| switch (e) {
            error.XmlTagNotFound => break :blk null,
            else => return e,
        };
        defer allocator.free(rs_block);

        const in_progress: bool = blk2: {
            const s = try xml.extractTagContent(allocator, rs_block, "IsRestoreInProgress");
            defer allocator.free(s);
            break :blk2 std.mem.eql(u8, s, "true");
        };

        const expiry = xml.extractTagContent(allocator, rs_block, "RestoreExpiryDate") catch |e| switch (e) {
            error.XmlTagNotFound => null,
            else => return e,
        };

        break :blk RestoreStatus{
            .is_restore_in_progress = in_progress,
            .restore_expiry_date = expiry,
        };
    };

    return .{
        .allocator = allocator,
        .key = key,
        .last_modified = last_modified,
        .etag = etag,
        .size = size,
        .storage_class = storage_class,
        .checksum_algorithm = checksum_algorithm,
        .checksum_type = checksum_type,
        .owner = owner,
        .restore_status = restore_status,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "parseObjects basic" {
    const body =
        \\<ListBucketResult>
        \\  <Name>my-bucket</Name>
        \\  <Prefix></Prefix>
        \\  <IsTruncated>false</IsTruncated>
        \\  <MaxKeys>1000</MaxKeys>
        \\  <KeyCount>2</KeyCount>
        \\  <Contents>
        \\    <Key>foo/bar.txt</Key>
        \\    <LastModified>2024-01-15T10:30:00.000Z</LastModified>
        \\    <ETag>&quot;abc123&quot;</ETag>
        \\    <Size>1024</Size>
        \\    <StorageClass>STANDARD</StorageClass>
        \\  </Contents>
        \\  <Contents>
        \\    <Key>foo/baz.txt</Key>
        \\    <LastModified>2024-01-16T08:00:00.000Z</LastModified>
        \\    <ETag>&quot;def456&quot;</ETag>
        \\    <Size>2048</Size>
        \\    <StorageClass>INTELLIGENT_TIERING</StorageClass>
        \\  </Contents>
        \\</ListBucketResult>
    ;
    const result = try parseObjects(std.testing.allocator, body);
    defer result.deinit();

    try std.testing.expectEqualStrings("my-bucket", result.name);
    try std.testing.expectEqualStrings("", result.prefix);
    try std.testing.expect(!result.is_truncated);
    try std.testing.expectEqual(@as(usize, 1000), result.max_keys);
    try std.testing.expectEqual(@as(usize, 2), result.key_count);
    try std.testing.expectEqual(@as(usize, 2), result.objects.len);
    try std.testing.expectEqualStrings("foo/bar.txt", result.objects[0].key);
    try std.testing.expectEqual(@as(u64, 1024), result.objects[0].size);
    try std.testing.expectEqual(typesMod.StorageClass.STANDARD, result.objects[0].storage_class);
    try std.testing.expectEqual(typesMod.StorageClass.INTELLIGENT_TIERING, result.objects[1].storage_class);
    try std.testing.expect(result.objects[0].owner == null);
    try std.testing.expect(result.common_prefixes == null);
}

test "parseObjects truncated with continuation token and common prefixes" {
    const body =
        \\<ListBucketResult>
        \\  <Name>my-bucket</Name>
        \\  <Prefix>logs/</Prefix>
        \\  <Delimiter>/</Delimiter>
        \\  <IsTruncated>true</IsTruncated>
        \\  <MaxKeys>100</MaxKeys>
        \\  <KeyCount>100</KeyCount>
        \\  <ContinuationToken>token-abc</ContinuationToken>
        \\  <NextContinuationToken>token-def</NextContinuationToken>
        \\  <CommonPrefixes><Prefix>logs/2024/</Prefix></CommonPrefixes>
        \\  <CommonPrefixes><Prefix>logs/2025/</Prefix></CommonPrefixes>
        \\</ListBucketResult>
    ;
    const result = try parseObjects(std.testing.allocator, body);
    defer result.deinit();

    try std.testing.expect(result.is_truncated);
    try std.testing.expectEqualStrings("logs/", result.prefix);
    try std.testing.expectEqualStrings("/", result.delimiter.?);
    try std.testing.expectEqualStrings("token-abc", result.continuation_token.?);
    try std.testing.expectEqualStrings("token-def", result.next_continuation_token.?);
    try std.testing.expectEqual(@as(usize, 0), result.objects.len);
    try std.testing.expectEqual(@as(usize, 2), result.common_prefixes.?.len);
    try std.testing.expectEqualStrings("logs/2024/", result.common_prefixes.?[0]);
    try std.testing.expectEqualStrings("logs/2025/", result.common_prefixes.?[1]);
}
