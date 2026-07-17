const terminal = @import("../terminal/terminal.zig");

pub const ViewColors = struct {
    fg: []const u8,
    bg: []const u8,
};

/// Orange theme — used by Lambda, SSO, auth, and home views.
pub fn orange(support: terminal.ColorSupport) ViewColors {
    return switch (support) {
        .truecolor => .{
            .fg = terminal.TRUECOLOR_FG ++ "255;153;0m",
            .bg = terminal.TRUECOLOR_BG ++ "255;153;0m",
        },
        .color256 => .{
            .fg = terminal.BYTECOLOR_FG ++ "214m",
            .bg = terminal.BYTECOLOR_BG ++ "214m",
        },
        .color16 => .{ .fg = terminal.FG_YELLOW, .bg = terminal.BG_YELLOW },
    };
}

/// Red theme — used by CloudWatch Logs views.
pub fn red(support: terminal.ColorSupport) ViewColors {
    return switch (support) {
        .truecolor => .{
            .fg = terminal.TRUECOLOR_FG ++ "232;77;77m",
            .bg = terminal.TRUECOLOR_BG ++ "232;77;77m",
        },
        .color256 => .{
            .fg = terminal.BYTECOLOR_FG ++ "160m",
            .bg = terminal.BYTECOLOR_BG ++ "160m",
        },
        .color16 => .{ .fg = terminal.FG_RED, .bg = terminal.BG_RED },
    };
}

/// Blue theme — used by database services (DynamoDB, RDS).
pub fn blue(support: terminal.ColorSupport) ViewColors {
    return switch (support) {
        .truecolor => .{
            .fg = terminal.TRUECOLOR_FG ++ "64;83;214m",
            .bg = terminal.TRUECOLOR_BG ++ "64;83;214m",
        },
        .color256 => .{
            .fg = terminal.BYTECOLOR_FG ++ "63m",
            .bg = terminal.BYTECOLOR_BG ++ "63m",
        },
        .color16 => .{ .fg = terminal.FG_CYAN, .bg = terminal.BG_CYAN },
    };
}

/// IAM theme — AWS IAM red (#DD344C).
pub fn iam(support: terminal.ColorSupport) ViewColors {
    return switch (support) {
        .truecolor => .{
            .fg = terminal.TRUECOLOR_FG ++ "221;52;76m",
            .bg = terminal.TRUECOLOR_BG ++ "221;52;76m",
        },
        .color256 => .{
            .fg = terminal.BYTECOLOR_FG ++ "167m",
            .bg = terminal.BYTECOLOR_BG ++ "167m",
        },
        .color16 => .{ .fg = terminal.FG_RED, .bg = terminal.BG_RED },
    };
}

/// Green theme — used by S3 views.
pub fn green(support: terminal.ColorSupport) ViewColors {
    return switch (support) {
        .truecolor => .{
            .fg = terminal.TRUECOLOR_FG ++ "86;167;0m",
            .bg = terminal.TRUECOLOR_BG ++ "86;167;0m",
        },
        .color256 => .{
            .fg = terminal.BYTECOLOR_FG ++ "70m",
            .bg = terminal.BYTECOLOR_BG ++ "70m",
        },
        .color16 => .{ .fg = terminal.FG_GREEN, .bg = terminal.BG_GREEN },
    };
}
