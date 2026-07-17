const std = @import("std");

const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const Sha256 = std.crypto.hash.sha2.Sha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Uri = std.Uri;

const time = @import("../utils/time.zig");

/// Configuration for the SigV4 signer
pub const SignerConfig = struct {
    access_key: []const u8,
    secret_key: []const u8,
    region: []const u8,
    service: []const u8,
    /// Include X-Amz-Content-Sha256 header. Required for S3, should be omitted for STS.
    include_sha256_header: bool = true,
};

/// Result of signing operation containing all headers needed for the request
pub const SignedRequest = struct {
    allocator: Allocator,
    headers: std.StringHashMap([]const u8),

    pub fn deinit(self: *SignedRequest) void {
        var iter = self.headers.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.headers.deinit();
    }

    pub fn getHeader(self: *const SignedRequest, key: []const u8) ?[]const u8 {
        return self.headers.get(key);
    }
};

/// Calculate SHA256 hash and return as lowercase hex string
fn sha256Hash(allocator: Allocator, data: []const u8) ![]u8 {
    var hash: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(data, &hash, .{});
    return try bytesToHex(allocator, &hash);
}

/// Calculate HMAC-SHA256
fn hmacSha256(key: []const u8, data: []const u8) [HmacSha256.mac_length]u8 {
    var mac: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&mac, data, key);
    return mac;
}

/// Convert bytes to lowercase hex string
fn bytesToHex(allocator: Allocator, bytes: []const u8) ![]u8 {
    const hex_chars = "0123456789abcdef";
    const result = try allocator.alloc(u8, bytes.len * 2);
    for (bytes, 0..) |byte, i| {
        result[i * 2] = hex_chars[byte >> 4];
        result[i * 2 + 1] = hex_chars[byte & 0x0f];
    }
    return result;
}

/// Encode a single component for canonical query string (percent-encode all except unreserved)
fn encodeQueryComponent(allocator: Allocator, component: []const u8) ![]u8 {
    var result: ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);

    const hex_chars = "0123456789ABCDEF";

    for (component) |c| {
        if ((c >= 'A' and c <= 'Z') or
            (c >= 'a' and c <= 'z') or
            (c >= '0' and c <= '9') or
            c == '-' or c == '_' or c == '.' or c == '~')
        {
            try result.append(allocator, c);
        } else {
            try result.append(allocator, '%');
            try result.append(allocator, hex_chars[c >> 4]);
            try result.append(allocator, hex_chars[c & 0x0f]);
        }
    }

    return try result.toOwnedSlice(allocator);
}

/// Create canonical query string from raw query
fn createCanonicalQueryString(allocator: Allocator, query: ?[]const u8) ![]u8 {
    const q = query orelse return try allocator.dupe(u8, "");
    if (q.len == 0) return try allocator.dupe(u8, "");

    const QueryParam = struct { key: []const u8, value: []const u8 };

    // Parse query parameters
    var params: ArrayList(QueryParam) = .empty;
    defer params.deinit(allocator);

    var iter = std.mem.splitScalar(u8, q, '&');
    while (iter.next()) |param| {
        if (param.len == 0) continue;

        if (std.mem.indexOf(u8, param, "=")) |eq_pos| {
            try params.append(allocator, .{
                .key = param[0..eq_pos],
                .value = param[eq_pos + 1 ..],
            });
        } else {
            try params.append(allocator, .{
                .key = param,
                .value = "",
            });
        }
    }

    // Sort by key, then by value
    std.mem.sort(
        QueryParam,
        params.items,
        {},
        struct {
            fn lessThan(_: void, a: QueryParam, b: QueryParam) bool {
                const key_cmp = std.mem.order(u8, a.key, b.key);
                if (key_cmp != .eq) return key_cmp == .lt;
                return std.mem.order(u8, a.value, b.value) == .lt;
            }
        }.lessThan,
    );

    // Build result
    var result: ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);

    for (params.items, 0..) |param, i| {
        if (i > 0) try result.append(allocator, '&');

        const encoded_key = try encodeQueryComponent(allocator, param.key);
        defer allocator.free(encoded_key);
        try result.appendSlice(allocator, encoded_key);

        try result.append(allocator, '=');

        const encoded_value = try encodeQueryComponent(allocator, param.value);
        defer allocator.free(encoded_value);
        try result.appendSlice(allocator, encoded_value);
    }

    return try result.toOwnedSlice(allocator);
}

/// Header entry for sorting
const HeaderEntry = struct {
    key: []u8,
    value: []u8,
};

/// Create canonical headers string and signed headers list
fn createCanonicalHeaders(allocator: Allocator, headers: *const std.StringHashMap([]const u8)) !struct { canonical: []u8, signed: []u8 } {
    var entries: ArrayList(HeaderEntry) = .empty;
    defer {
        for (entries.items) |entry| {
            allocator.free(entry.key);
            allocator.free(entry.value);
        }
        entries.deinit(allocator);
    }

    // Convert to lowercase and normalize whitespace
    var iter = headers.iterator();
    while (iter.next()) |entry| {
        const lower_key = try toLowercase(allocator, entry.key_ptr.*);
        const trimmed_value = try normalizeHeaderValue(allocator, entry.value_ptr.*);
        try entries.append(allocator, .{ .key = lower_key, .value = trimmed_value });
    }

    // Sort by key
    std.mem.sort(HeaderEntry, entries.items, {}, struct {
        fn lessThan(_: void, a: HeaderEntry, b: HeaderEntry) bool {
            return std.mem.order(u8, a.key, b.key) == .lt;
        }
    }.lessThan);

    // Build canonical headers string
    var canonical: ArrayList(u8) = .empty;
    errdefer canonical.deinit(allocator);

    for (entries.items) |entry| {
        try canonical.appendSlice(allocator, entry.key);
        try canonical.append(allocator, ':');
        try canonical.appendSlice(allocator, entry.value);
        try canonical.append(allocator, '\n');
    }

    // Build signed headers string
    var signed: ArrayList(u8) = .empty;
    errdefer signed.deinit(allocator);

    for (entries.items, 0..) |entry, i| {
        if (i > 0) try signed.append(allocator, ';');
        try signed.appendSlice(allocator, entry.key);
    }

    return .{
        .canonical = try canonical.toOwnedSlice(allocator),
        .signed = try signed.toOwnedSlice(allocator),
    };
}

/// Convert string to lowercase
fn toLowercase(allocator: Allocator, s: []const u8) ![]u8 {
    const result = try allocator.alloc(u8, s.len);
    for (s, 0..) |c, i| {
        result[i] = if (c >= 'A' and c <= 'Z') c + 32 else c;
    }
    return result;
}

/// Normalize header value (trim and collapse whitespace)
fn normalizeHeaderValue(allocator: Allocator, value: []const u8) ![]u8 {
    var result: ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);

    var in_whitespace = true;
    var last_was_space = false;

    for (value) |c| {
        if (c == ' ' or c == '\t') {
            if (!in_whitespace) {
                last_was_space = true;
            }
        } else {
            if (last_was_space and result.items.len > 0) {
                try result.append(allocator, ' ');
            }
            try result.append(allocator, c);
            in_whitespace = false;
            last_was_space = false;
        }
    }

    return try result.toOwnedSlice(allocator);
}

/// Create the canonical request string
fn createCanonicalRequest(
    allocator: Allocator,
    method: []const u8,
    canonical_uri: []const u8,
    canonical_query: []const u8,
    canonical_headers: []const u8,
    signed_headers: []const u8,
    payload_hash: []const u8,
) ![]u8 {
    var result: ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);

    try result.appendSlice(allocator, method);
    try result.append(allocator, '\n');
    try result.appendSlice(allocator, canonical_uri);
    try result.append(allocator, '\n');
    try result.appendSlice(allocator, canonical_query);
    try result.append(allocator, '\n');
    try result.appendSlice(allocator, canonical_headers);
    try result.append(allocator, '\n');
    try result.appendSlice(allocator, signed_headers);
    try result.append(allocator, '\n');
    try result.appendSlice(allocator, payload_hash);

    return try result.toOwnedSlice(allocator);
}

/// Create the string to sign
fn createStringToSign(
    allocator: Allocator,
    timestamp: []const u8,
    credential_scope: []const u8,
    canonical_request_hash: []const u8,
) ![]u8 {
    var result: ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);

    try result.appendSlice(allocator, "AWS4-HMAC-SHA256");
    try result.append(allocator, '\n');
    try result.appendSlice(allocator, timestamp);
    try result.append(allocator, '\n');
    try result.appendSlice(allocator, credential_scope);
    try result.append(allocator, '\n');
    try result.appendSlice(allocator, canonical_request_hash);

    return try result.toOwnedSlice(allocator);
}

/// Get credential scope string
fn getCredentialScope(allocator: Allocator, date_stamp: []const u8, region: []const u8, service: []const u8) ![]u8 {
    return try std.fmt.allocPrint(allocator, "{s}/{s}/{s}/aws4_request", .{ date_stamp, region, service });
}

/// Calculate the signing key
fn calculateSigningKey(secret_key: []const u8, date_stamp: []const u8, region: []const u8, service: []const u8) [32]u8 {
    // Construct "AWS4" + secret_key
    var aws4_key: [256]u8 = undefined;
    const prefix = "AWS4";
    @memcpy(aws4_key[0..prefix.len], prefix);
    @memcpy(aws4_key[prefix.len .. prefix.len + secret_key.len], secret_key);
    const full_key = aws4_key[0 .. prefix.len + secret_key.len];

    const k_date = hmacSha256(full_key, date_stamp);
    const k_region = hmacSha256(&k_date, region);
    const k_service = hmacSha256(&k_region, service);
    const k_signing = hmacSha256(&k_service, "aws4_request");

    return k_signing;
}

/// Convert HTTP method to string
fn methodToString(method: std.http.Method) []const u8 {
    return @tagName(method);
}

/// Sign an AWS request with SigV4
///
/// Parameters:
/// - allocator: Memory allocator
/// - config: Signer configuration (access key, secret key, region, service)
/// - method: HTTP method
/// - url: Full URL of the request
/// - headers: Optional additional headers (will be modified to include required headers)
/// - payload: Request body (empty string for no body)
/// - canonical_uri: Pre-encoded canonical URI (optional, will parse from URL if null)
///
/// Returns: SignedRequest containing all headers including Authorization
pub fn sign(
    allocator: Allocator,
    io: std.Io,
    config: SignerConfig,
    method: std.http.Method,
    url: []const u8,
    headers: ?std.StringHashMap([]const u8),
    payload: []const u8,
    canonical_uri: ?[]const u8,
) !SignedRequest {
    // Parse URL
    const parsed = try Uri.parse(url);

    // Extract host
    const host = if (parsed.host) |h| switch (h) {
        .raw => |r| r,
        .percent_encoded => |p| p,
    } else return error.MissingHost;

    // Get path
    const path = if (canonical_uri) |uri| uri else switch (parsed.path) {
        .percent_encoded => |p| if (p.len > 0) p else "/",
        .raw => |p| if (p.len > 0) p else "/",
    };

    // Get query string
    const query_str: ?[]const u8 = if (parsed.query) |q| switch (q) {
        .percent_encoded => |p| p,
        .raw => |r| r,
    } else null;

    // Generate timestamp
    const _ts = std.Io.Timestamp.now(io, .real);
    const timestamp_val: i64 = @intCast(@divFloor(_ts.nanoseconds, std.time.ns_per_s));
    const timestamp_str = try time.secondsToDate(allocator, timestamp_val);
    defer allocator.free(timestamp_str);

    const date_stamp = timestamp_str[0..8];

    // Calculate payload hash
    const payload_hash = try sha256Hash(allocator, payload);
    defer allocator.free(payload_hash);

    // Build working headers map
    var work_headers = std.StringHashMap([]const u8).init(allocator);
    defer work_headers.deinit();

    // Copy input headers if provided
    if (headers) |h| {
        var iter = h.iterator();
        while (iter.next()) |entry| {
            try work_headers.put(entry.key_ptr.*, entry.value_ptr.*);
        }
    }

    // Add required headers
    try work_headers.put("Host", host);
    try work_headers.put("X-Amz-Date", timestamp_str);
    if (config.include_sha256_header) {
        try work_headers.put("X-Amz-Content-Sha256", payload_hash);
    }

    // Create canonical components
    const canonical_query = try createCanonicalQueryString(allocator, query_str);
    defer allocator.free(canonical_query);

    const header_result = try createCanonicalHeaders(allocator, &work_headers);
    defer allocator.free(header_result.canonical);
    defer allocator.free(header_result.signed);

    // Create canonical request
    const method_str = methodToString(method);
    const canonical_request = try createCanonicalRequest(
        allocator,
        method_str,
        path,
        canonical_query,
        header_result.canonical,
        header_result.signed,
        payload_hash,
    );
    defer allocator.free(canonical_request);

    // Hash canonical request
    const canonical_request_hash = try sha256Hash(allocator, canonical_request);
    defer allocator.free(canonical_request_hash);

    // Create credential scope
    const credential_scope = try getCredentialScope(allocator, date_stamp, config.region, config.service);
    defer allocator.free(credential_scope);

    // Create string to sign
    const string_to_sign = try createStringToSign(
        allocator,
        timestamp_str,
        credential_scope,
        canonical_request_hash,
    );
    defer allocator.free(string_to_sign);

    // Calculate signing key
    const signing_key = calculateSigningKey(config.secret_key, date_stamp, config.region, config.service);

    // Calculate signature
    const signature_bytes = hmacSha256(&signing_key, string_to_sign);
    const signature = try bytesToHex(allocator, &signature_bytes);
    defer allocator.free(signature);

    // Build authorization header
    const auth_header = try std.fmt.allocPrint(
        allocator,
        "AWS4-HMAC-SHA256 Credential={s}/{s}, SignedHeaders={s}, Signature={s}",
        .{ config.access_key, credential_scope, header_result.signed, signature },
    );

    // Build result headers
    var result_headers = std.StringHashMap([]const u8).init(allocator);
    errdefer {
        var iter = result_headers.iterator();
        while (iter.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        result_headers.deinit();
    }

    // Copy original headers
    if (headers) |h| {
        var iter = h.iterator();
        while (iter.next()) |entry| {
            const key_copy = try allocator.dupe(u8, entry.key_ptr.*);
            errdefer allocator.free(key_copy);
            const value_copy = try allocator.dupe(u8, entry.value_ptr.*);
            try result_headers.put(key_copy, value_copy);
        }
    }

    // Add/overwrite required headers
    const host_key = try allocator.dupe(u8, "Host");
    errdefer allocator.free(host_key);
    const host_value = try allocator.dupe(u8, host);
    try result_headers.put(host_key, host_value);

    const date_key = try allocator.dupe(u8, "X-Amz-Date");
    errdefer allocator.free(date_key);
    const date_value = try allocator.dupe(u8, timestamp_str);
    try result_headers.put(date_key, date_value);

    const auth_key = try allocator.dupe(u8, "Authorization");
    try result_headers.put(auth_key, auth_header);

    if (config.include_sha256_header) {
        const sha256_key = try allocator.dupe(u8, "X-Amz-Content-Sha256");
        errdefer allocator.free(sha256_key);
        const sha256_value = try allocator.dupe(u8, payload_hash);
        try result_headers.put(sha256_key, sha256_value);
    }

    return SignedRequest{
        .allocator = allocator,
        .headers = result_headers,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "sha256Hash produces correct hash" {
    const allocator = std.testing.allocator;
    const hash = try sha256Hash(allocator, "");
    defer allocator.free(hash);
    // SHA256 of empty string
    try std.testing.expectEqualStrings("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hash);
}

test "sha256Hash with payload" {
    const allocator = std.testing.allocator;
    const hash = try sha256Hash(allocator, "test");
    defer allocator.free(hash);
    try std.testing.expectEqualStrings("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", hash);
}

test "createCanonicalQueryString empty query" {
    const allocator = std.testing.allocator;
    const result = try createCanonicalQueryString(allocator, null);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("", result);
}

test "createCanonicalQueryString sorts parameters" {
    const allocator = std.testing.allocator;
    const result = try createCanonicalQueryString(allocator, "z=1&a=2&m=3");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("a=2&m=3&z=1", result);
}

test "createCanonicalQueryString handles encoding" {
    const allocator = std.testing.allocator;
    const result = try createCanonicalQueryString(allocator, "key=hello world");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("key=hello%20world", result);
}

test "toLowercase works" {
    const allocator = std.testing.allocator;
    const result = try toLowercase(allocator, "Content-Type");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("content-type", result);
}

test "normalizeHeaderValue trims and collapses whitespace" {
    const allocator = std.testing.allocator;
    const result = try normalizeHeaderValue(allocator, "  hello   world  ");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("hello world", result);
}

test "calculateSigningKey produces deterministic output" {
    const key1 = calculateSigningKey("secret", "20230101", "us-east-1", "s3");
    const key2 = calculateSigningKey("secret", "20230101", "us-east-1", "s3");
    try std.testing.expectEqualSlices(u8, &key1, &key2);
}

test "hmacSha256 produces correct MAC" {
    const mac = hmacSha256("key", "data");
    const allocator = std.testing.allocator;
    const hex = try bytesToHex(allocator, &mac);
    defer allocator.free(hex);
    // Known HMAC-SHA256("key", "data") value
    try std.testing.expectEqualStrings("5031fe3d989c6d1537a013fa6e739da23463fdaec3b70137d828e36ace221bd0", hex);
}

test "createCanonicalHeaders sorts and formats correctly" {
    const allocator = std.testing.allocator;

    var headers = std.StringHashMap([]const u8).init(allocator);
    defer headers.deinit();

    try headers.put("X-Amz-Date", "20230101T000000Z");
    try headers.put("Host", "example.com");
    try headers.put("Content-Type", "application/json");

    const result = try createCanonicalHeaders(allocator, &headers);
    defer allocator.free(result.canonical);
    defer allocator.free(result.signed);

    try std.testing.expectEqualStrings("content-type;host;x-amz-date", result.signed);
    try std.testing.expectEqualStrings("content-type:application/json\nhost:example.com\nx-amz-date:20230101T000000Z\n", result.canonical);
}

test "full signing produces valid authorization header" {
    const allocator = std.testing.allocator;

    const config = SignerConfig{
        .access_key = "AKIAIOSFODNN7EXAMPLE",
        .secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        .region = "us-east-1",
        .service = "s3",
    };

    var signed = try sign(
        allocator,
        std.testing.io,
        config,
        .GET,
        "https://my-bucket.s3.us-east-1.amazonaws.com/test.txt",
        null,
        "",
        "/test.txt",
    );
    defer signed.deinit();

    // Verify required headers exist
    try std.testing.expect(signed.getHeader("Authorization") != null);
    try std.testing.expect(signed.getHeader("Host") != null);
    try std.testing.expect(signed.getHeader("X-Amz-Date") != null);

    // Verify authorization header format
    const auth = signed.getHeader("Authorization").?;
    try std.testing.expect(std.mem.startsWith(u8, auth, "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/"));
    try std.testing.expect(std.mem.indexOf(u8, auth, "SignedHeaders=") != null);
    try std.testing.expect(std.mem.indexOf(u8, auth, "Signature=") != null);
}
