const std = @import("std");
const Allocator = std.mem.Allocator;

const Credentials = @import("../../credentials/fetcher.zig").Credentials;

const typesMod = @import("types.zig");
pub const MetadataDirective = typesMod.MetadataDirective;
pub const TaggingDirective = typesMod.TaggingDirective;
pub const ObjectCannedAcl = typesMod.ObjectCannedAcl;
pub const StorageClass = typesMod.StorageClass;
pub const RequestPayer = typesMod.RequestPayer;
pub const ChecksumAlgorithm = typesMod.ChecksumAlgorithm;
pub const ObjectLockMode = typesMod.ObjectLockMode;
pub const ObjectLockLegalHold = typesMod.ObjectLockLegalHold;
pub const ServerSideEncryption = typesMod.ServerSideEncryption;

const listBucketsMod = @import("list/buckets.zig");
const listBucketsImpl = listBucketsMod.listBuckets;

pub const ListBucketsOptions = listBucketsMod.Options;
pub const ListBucketsResult = listBucketsMod.Result;
pub const Bucket = listBucketsMod.Bucket;

const listObjectsMod = @import("list/objects.zig");
const listObjectsImpl = listObjectsMod.listObjects;

pub const ListObjectsOptions = listObjectsMod.Options;
pub const ListObjectsResult = listObjectsMod.Result;
pub const S3Object = listObjectsMod.Object;
pub const S3Owner = listObjectsMod.Owner;
pub const S3RestoreStatus = listObjectsMod.RestoreStatus;

const headObjectMod = @import("head/object.zig");
const headObjectImpl = headObjectMod.headObject;

pub const HeadObjectOptions = headObjectMod.Options;
pub const HeadObjectResult = headObjectMod.Result;
pub const headObjectWithIo = headObjectMod.headObjectWithIo;

const getObjectMod = @import("get/object.zig");
const getObjectImpl = getObjectMod.getObject;

pub const GetObjectOptions = getObjectMod.Options;
pub const GetObjectResult = getObjectMod.Result;
pub const getObjectWithIo = getObjectMod.getObjectWithIo;

pub const ClientOptions = struct {
    region: []const u8 = "us-east-1",
    io: std.Io,
    credentials: Credentials,
    /// Override the S3 endpoint host (e.g. "http://localhost:9000" for MinIO).
    /// When set, virtual-hosted-style bucket addressing is not used — the bucket
    /// is placed in the path instead.
    endpoint_url: ?[]const u8 = null,
};

pub const Client = struct {
    allocator: Allocator,
    io: std.Io,
    region: []const u8,
    credentials: Credentials,
    /// Owned. Base URL, no trailing slash:
    ///   virtual-hosted default : "https://s3.{region}.amazonaws.com".
    ///   custom endpoint: copy of options.endpoint_url
    endpoint: []const u8,
    /// True when using the default AWS endpoints (virtual-hosted bucket addressing).
    /// False when a custom endpoint is set (path-style addressing).
    virtual_hosted: bool,

    pub fn init(allocator: Allocator, options: ClientOptions) !Client {
        const endpoint = if (options.endpoint_url) |ep|
            try allocator.dupe(u8, ep)
        else
            try std.fmt.allocPrint(allocator, "https://s3.{s}.amazonaws.com", .{options.region});

        return .{
            .allocator = allocator,
            .io = options.io,
            .region = options.region,
            .credentials = options.credentials,
            .endpoint = endpoint,
            .virtual_hosted = options.endpoint_url == null,
        };
    }

    pub fn deinit(self: *Client) void {
        self.allocator.free(self.endpoint);
    }

    /// List all S3 buckets owned by the authenticated sender.
    /// Caller owns the returned ListBucketsResult and must call deinit.
    pub fn listBuckets(
        self: *Client,
        options: ListBucketsOptions,
    ) !ListBucketsResult {
        return listBucketsImpl(self, options);
    }

    /// List objects in a bucket (ListObjectsV2). Caller owns the result and must call deinit.
    pub fn listObjects(
        self: *Client,
        options: ListObjectsOptions,
    ) !ListObjectsResult {
        return listObjectsImpl(self, options);
    }

    /// HEAD a single S3 object to retrieve metadata (e.g. Content-Type).
    /// Caller owns the returned HeadObjectResult and must call deinit.
    pub fn headObject(
        self: *Client,
        options: HeadObjectOptions,
    ) !HeadObjectResult {
        return headObjectImpl(self, options);
    }

    /// GET a single S3 object. Caller owns the returned GetObjectResult and must call deinit.
    pub fn getObject(
        self: *Client,
        options: GetObjectOptions,
    ) !GetObjectResult {
        return getObjectImpl(self, options);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "Client init default endpoint" {
    const allocator = std.testing.allocator;
    var c = try Client.init(allocator, .{
        .region = "us-west-2",
        .io = std.testing.io,
        .credentials = .{
            .access_key_id = "AKID",
            .secret_access_key = "SECRET",
            .session_token = null,
            .source = "test",
        },
    });
    defer c.deinit();
    try std.testing.expectEqualStrings("https://s3.us-west-2.amazonaws.com", c.endpoint);
    try std.testing.expect(c.virtual_hosted);
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
        .endpoint_url = "http://localhost:9000",
    });
    defer c.deinit();
    try std.testing.expectEqualStrings("http://localhost:9000", c.endpoint);
    try std.testing.expect(!c.virtual_hosted);
}
