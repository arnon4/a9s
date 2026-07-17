const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

/// Check if character is unreserved per RFC 3986
fn isUnreservedChar(c: u8) bool {
    return (c >= 'A' and c <= 'Z') or
        (c >= 'a' and c <= 'z') or
        (c >= '0' and c <= '9') or
        c == '-' or c == '_' or c == '.' or c == '~';
}

/// Encode URI component for S3 (preserves forward slashes)
/// This is needed for S3 because object keys can contain special characters
/// but paths should maintain their structure with forward slashes.
pub fn encodeS3Path(allocator: Allocator, path: []const u8) ![]u8 {
    return try encodeInternal(allocator, path, true);
}

/// Encode URI component for standard services (encodes everything except unreserved chars)
/// Use this for most AWS services that don't have special path encoding requirements.
pub fn encodeStandard(allocator: Allocator, path: []const u8) ![]u8 {
    return try encodeInternal(allocator, path, false);
}

/// Internal URI encoding function
fn encodeInternal(allocator: Allocator, path: []const u8, preserve_slashes: bool) ![]u8 {
    var result: ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);

    const hex_chars = "0123456789ABCDEF";

    for (path) |c| {
        if (isUnreservedChar(c) or (preserve_slashes and c == '/')) {
            try result.append(allocator, c);
        } else {
            try result.append(allocator, '%');
            try result.append(allocator, hex_chars[c >> 4]);
            try result.append(allocator, hex_chars[c & 0x0f]);
        }
    }

    return try result.toOwnedSlice(allocator);
}

// ============================================================================
// Tests
// ============================================================================

test "encodeS3Path preserves slashes" {
    const allocator = std.testing.allocator;
    const encoded = try encodeS3Path(allocator, "/my-folder/my file.txt");
    defer allocator.free(encoded);
    try std.testing.expectEqualStrings("/my-folder/my%20file.txt", encoded);
}

test "encodeStandard encodes slashes" {
    const allocator = std.testing.allocator;
    const encoded = try encodeStandard(allocator, "/path/to/file");
    defer allocator.free(encoded);
    try std.testing.expectEqualStrings("%2Fpath%2Fto%2Ffile", encoded);
}

test "encodeS3Path handles special characters" {
    const allocator = std.testing.allocator;
    const encoded = try encodeS3Path(allocator, "/test+file name.txt");
    defer allocator.free(encoded);
    try std.testing.expectEqualStrings("/test%2Bfile%20name.txt", encoded);
}

test "encodeS3Path preserves unreserved chars" {
    const allocator = std.testing.allocator;
    const encoded = try encodeS3Path(allocator, "/path/to-file_name.txt~123");
    defer allocator.free(encoded);
    try std.testing.expectEqualStrings("/path/to-file_name.txt~123", encoded);
}

test "encodeStandard encodes all reserved chars" {
    const allocator = std.testing.allocator;
    const encoded = try encodeStandard(allocator, "hello world!");
    defer allocator.free(encoded);
    try std.testing.expectEqualStrings("hello%20world%21", encoded);
}
