const std = @import("std");

/// Format a byte count as a human-readable size string (B / KB / MB / GB / TB).
pub fn size(buf: []u8, bytes: u64) []u8 {
    const kb: f64 = 1024;
    const mb: f64 = kb * 1024;
    const gb: f64 = mb * 1024;
    const tb: f64 = gb * 1024;
    const f: f64 = @floatFromInt(bytes);
    return if (bytes < 1024)
        std.fmt.bufPrint(buf, "{d} B", .{bytes}) catch buf[0..0]
    else if (f < mb)
        std.fmt.bufPrint(buf, "{d:.1} KB", .{f / kb}) catch buf[0..0]
    else if (f < gb)
        std.fmt.bufPrint(buf, "{d:.1} MB", .{f / mb}) catch buf[0..0]
    else if (f < tb)
        std.fmt.bufPrint(buf, "{d:.1} GB", .{f / gb}) catch buf[0..0]
    else
        std.fmt.bufPrint(buf, "{d:.1} TB", .{f / tb}) catch buf[0..0];
}
