const std = @import("std");

const Allocator = std.mem.Allocator;
const allocPrint = std.fmt.allocPrint;

fn isLeapYear(year: i64) bool {
    return @mod(year, 4) == 0 and (@mod(year, 100) != 0 or @mod(year, 400) == 0);
}

fn daysInMonth(year: i64, month: i64) i8 {
    switch (month) {
        1, 3, 5, 7, 8, 10, 12 => {
            return 31;
        },
        4, 6, 9, 11 => {
            return 30;
        },
        2 => {
            return if (isLeapYear(year)) 29 else 28;
        },
        else => unreachable,
    }
}

pub fn secondsToDate(allocator: Allocator, timestamp: i64) ![]u8 {
    var year: i64 = 1970;
    var month: i64 = 1;
    var day: i64 = 1;

    var days_total = @divFloor(timestamp, 86400);
    var remaining_seconds = @mod(timestamp, 86400);

    const hours = @divFloor(remaining_seconds, 3600);
    remaining_seconds = @mod(remaining_seconds, 3600);

    const minutes = @divFloor(remaining_seconds, 60);
    remaining_seconds = @mod(remaining_seconds, 60);

    const seconds = @mod(remaining_seconds, 60);

    while (true) {
        const days_in_year: i64 = if (isLeapYear(year)) 366 else 365;
        if (days_total >= days_in_year) {
            days_total -= days_in_year;
            year += 1;
        } else break;
    }

    while (true) {
        const days_in_current_month = daysInMonth(year, month);
        if (days_total >= days_in_current_month) {
            days_total -= days_in_current_month;
            month += 1;

            if (month > 12) {
                month = 1;
                year += 1;
            }
        } else break;
    }

    day = days_total + 1;

    const month_pad = if (month < 10) "0" else "";
    const day_pad = if (day < 10) "0" else "";
    const hour_pad = if (hours < 10) "0" else "";
    const minute_pad = if (minutes < 10) "0" else "";
    const second_pad = if (seconds < 10) "0" else "";
    return try std.fmt.allocPrint(allocator, "{d}{s}{d}{s}{d}T{s}{d}{s}{d}{s}{d}Z", .{
        year,
        month_pad,
        month,
        day_pad,
        day,
        hour_pad,
        hours,
        minute_pad,
        minutes,
        second_pad,
        seconds,
    });
}

pub fn hasPassed(io: std.Io, timestamp: i64) bool {
    const ts = std.Io.Timestamp.now(io, .real);
    const now_s: i64 = @intCast(@divFloor(ts.nanoseconds, std.time.ns_per_s));
    return now_s >= timestamp;
}

/// Parse ISO8601 timestamp to Unix timestamp.
/// Handles formats like: 2024-01-15T10:30:00Z
pub fn parseIso8601ToTimestamp(iso_str: []const u8) ?i64 {
    if (iso_str.len < 19) return null;

    // Parse year
    const year = std.fmt.parseInt(i32, iso_str[0..4], 10) catch return null;
    // Parse month
    const month = std.fmt.parseInt(u8, iso_str[5..7], 10) catch return null;
    // Parse day
    const day = std.fmt.parseInt(u8, iso_str[8..10], 10) catch return null;
    // Parse hour
    const hour = std.fmt.parseInt(u8, iso_str[11..13], 10) catch return null;
    // Parse minute
    const minute = std.fmt.parseInt(u8, iso_str[14..16], 10) catch return null;
    // Parse second
    const second = std.fmt.parseInt(u8, iso_str[17..19], 10) catch return null;

    // Calculate Unix timestamp
    // Days from epoch to start of year
    var days: i64 = 0;
    var y: i32 = 1970;
    while (y < year) : (y += 1) {
        days += if (isLeapYear(y)) 366 else 365;
    }

    // Days in months of current year
    const days_in_months = [_]u8{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    var m: usize = 0;
    while (m < month - 1) : (m += 1) {
        days += days_in_months[m];
        if (m == 1 and isLeapYear(y)) {
            days += 1;
        }
    }

    // Add days in current month
    days += day - 1;

    // Convert to seconds and add time
    const timestamp = days * 86400 + @as(i64, hour) * 3600 + @as(i64, minute) * 60 + @as(i64, second);

    return timestamp;
}

test "Timestamp works" {
    var dbg = std.heap.DebugAllocator(.{}){};
    const alloc = dbg.allocator();
    defer {
        const deinit_status = dbg.deinit();
        if (deinit_status == .leak) {
            std.debug.print("leak detected\n", .{});
        }
    }

    var dummy_time: i64 = 0;
    const result = try secondsToDate(alloc, dummy_time);
    std.debug.assert(std.mem.eql(u8, result, "19700101T000000Z")); // 00:00:00 01-01-1970
    defer alloc.free(result);

    dummy_time = 86400;
    const result2 = try secondsToDate(alloc, dummy_time);
    std.debug.assert(std.mem.eql(u8, result2, "19700102T000000Z")); // 00:00:00 02-01-1970
    defer alloc.free(result2);
}

test "parseIso8601ToTimestamp parses valid timestamps" {
    // 1970-01-01T00:00:00Z should be 0
    const epoch = parseIso8601ToTimestamp("1970-01-01T00:00:00Z");
    try std.testing.expectEqual(@as(?i64, 0), epoch);

    // 2024-01-01T00:00:00Z should be a known value
    const timestamp = parseIso8601ToTimestamp("2024-01-01T00:00:00Z");
    try std.testing.expect(timestamp != null);
    try std.testing.expect(timestamp.? > 0);
}
