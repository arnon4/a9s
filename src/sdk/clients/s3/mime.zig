const std = @import("std");

/// Returns a static MIME type string inferred from the file extension of `key`.
/// Returns null if the extension is unknown or absent.
pub fn fromExtension(key: []const u8) ?[]const u8 {
    const ext = std.fs.path.extension(key);
    if (ext.len == 0) return null;
    const table = [_]struct { ext: []const u8, mime: []const u8 }{
        .{ .ext = ".txt", .mime = "text/plain" },
        .{ .ext = ".md", .mime = "text/markdown" },
        .{ .ext = ".html", .mime = "text/html" },
        .{ .ext = ".htm", .mime = "text/html" },
        .{ .ext = ".css", .mime = "text/css" },
        .{ .ext = ".csv", .mime = "text/csv" },
        .{ .ext = ".xml", .mime = "application/xml" },
        .{ .ext = ".json", .mime = "application/json" },
        .{ .ext = ".js", .mime = "application/javascript" },
        .{ .ext = ".ts", .mime = "application/typescript" },
        .{ .ext = ".yaml", .mime = "application/yaml" },
        .{ .ext = ".yml", .mime = "application/yaml" },
        .{ .ext = ".toml", .mime = "application/toml" },
        .{ .ext = ".pdf", .mime = "application/pdf" },
        .{ .ext = ".zip", .mime = "application/zip" },
        .{ .ext = ".gz", .mime = "application/gzip" },
        .{ .ext = ".tar", .mime = "application/x-tar" },
        .{ .ext = ".exe", .mime = "application/x-msdownload" },
        .{ .ext = ".dll", .mime = "application/x-msdownload" },
        .{ .ext = ".png", .mime = "image/png" },
        .{ .ext = ".jpg", .mime = "image/jpeg" },
        .{ .ext = ".jpeg", .mime = "image/jpeg" },
        .{ .ext = ".gif", .mime = "image/gif" },
        .{ .ext = ".svg", .mime = "image/svg+xml" },
        .{ .ext = ".webp", .mime = "image/webp" },
        .{ .ext = ".mp3", .mime = "audio/mpeg" },
        .{ .ext = ".mp4", .mime = "video/mp4" },
        .{ .ext = ".zig", .mime = "text/x-zig" },
    };
    for (table) |entry| {
        if (std.ascii.eqlIgnoreCase(ext, entry.ext)) return entry.mime;
    }
    return null;
}
