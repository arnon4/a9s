const std = @import("std");
const builtin = @import("builtin");
const is_windows = builtin.os.tag == .windows;

const windows = if (is_windows) std.os.windows else void;
const posix = if (!is_windows) std.posix else void;
const ioctl = std.c.ioctl;

/// A terminal position expressed in columns (x) and rows (y).
pub const Coord = struct { x: i16, y: i16 };

pub const ColorSupport = enum { truecolor, color256, color16 };

/// Detects terminal color support by inspecting environment variables.
/// On Windows always returns truecolor (cmd and PowerShell both support it).
pub fn getColorSupport(environ_map: *const std.process.Environ.Map) ColorSupport {
    if (is_windows) {
        return .truecolor;
    } else {
        if (environ_map.get("COLORTERM")) |val| {
            if (std.mem.eql(u8, val, "truecolor") or std.mem.eql(u8, val, "24bit"))
                return .truecolor;
        }
        if (environ_map.get("TERM_PROGRAM")) |val| {
            if (std.mem.eql(u8, val, "iTerm.app") or
                std.mem.eql(u8, val, "Hyper") or
                std.mem.eql(u8, val, "vscode") or
                std.mem.eql(u8, val, "WezTerm") or
                std.mem.eql(u8, val, "ghostty"))
                return .truecolor;
        }
        if (environ_map.get("TERM")) |val| {
            if (std.mem.indexOf(u8, val, "256color") != null)
                return .color256;
        }
        return .color16;
    }
}

pub const ESC = "\x1b[";

pub const RESET = ESC ++ "0m";

// ── Text Style ───────────────────────────────────────────────────────────────
pub const BOLD = ESC ++ "1m";
pub const DIM = ESC ++ "2m";
pub const ITALIC = ESC ++ "3m";
pub const UNDERLINE = ESC ++ "4m";
pub const BLINK = ESC ++ "5m";
pub const BLINK_FAST = ESC ++ "6m";
pub const REVERSE = ESC ++ "7m"; // swap FG/BG
pub const HIDDEN = ESC ++ "8m";
pub const STRIKETHROUGH = ESC ++ "9m";

// ── Reset Individual Styles ───────────────────────────────────────────────────
pub const RESET_BOLD = ESC ++ "22m";
pub const RESET_DIM = ESC ++ "22m";
pub const RESET_ITALIC = ESC ++ "23m";
pub const RESET_UNDERLINE = ESC ++ "24m";
pub const RESET_BLINK = ESC ++ "25m";
pub const RESET_REVERSE = ESC ++ "27m";
pub const RESET_HIDDEN = ESC ++ "28m";
pub const RESET_STRIKETHROUGH = ESC ++ "29m";

// ── Foreground Colors (Standard) ─────────────────────────────────────────────
pub const FG_BLACK = ESC ++ "30m";
pub const FG_RED = ESC ++ "31m";
pub const FG_GREEN = ESC ++ "32m";
pub const FG_YELLOW = ESC ++ "33m";
pub const FG_BLUE = ESC ++ "34m";
pub const FG_MAGENTA = ESC ++ "35m";
pub const FG_CYAN = ESC ++ "36m";
pub const FG_WHITE = ESC ++ "37m";
pub const FG_DEFAULT = ESC ++ "39m";

// ── Foreground Colors (Bright) ────────────────────────────────────────────────
pub const FG_BRIGHT_BLACK = ESC ++ "90m"; // "dark gray"
pub const FG_BRIGHT_RED = ESC ++ "91m";
pub const FG_BRIGHT_GREEN = ESC ++ "92m";
pub const FG_BRIGHT_YELLOW = ESC ++ "93m";
pub const FG_BRIGHT_BLUE = ESC ++ "94m";
pub const FG_BRIGHT_MAGENTA = ESC ++ "95m";
pub const FG_BRIGHT_CYAN = ESC ++ "96m";
pub const FG_BRIGHT_WHITE = ESC ++ "97m";

// ── Background Colors (Standard) ─────────────────────────────────────────────
pub const BG_BLACK = ESC ++ "40m";
pub const BG_RED = ESC ++ "41m";
pub const BG_GREEN = ESC ++ "42m";
pub const BG_YELLOW = ESC ++ "43m";
pub const BG_BLUE = ESC ++ "44m";
pub const BG_MAGENTA = ESC ++ "45m";
pub const BG_CYAN = ESC ++ "46m";
pub const BG_WHITE = ESC ++ "47m";
pub const BG_DEFAULT = ESC ++ "49m";

// ── Background Colors (Bright) ────────────────────────────────────────────────
pub const BG_BRIGHT_BLACK = ESC ++ "100m";
pub const BG_BRIGHT_RED = ESC ++ "101m";
pub const BG_BRIGHT_GREEN = ESC ++ "102m";
pub const BG_BRIGHT_YELLOW = ESC ++ "103m";
pub const BG_BRIGHT_BLUE = ESC ++ "104m";
pub const BG_BRIGHT_MAGENTA = ESC ++ "105m";
pub const BG_BRIGHT_CYAN = ESC ++ "106m";
pub const BG_BRIGHT_WHITE = ESC ++ "107m";

// ── 256-Color (runtime formatting required) ───────────────────────────────────
pub const BYTECOLOR_FG = ESC ++ "38;5;"; //{0-255}m
pub const BYTECOLOR_BG = ESC ++ "48;5;";
//   0–7:    standard colors
//   8–15:   bright colors
//   16–231: 6×6×6 color cube
//   232–255: grayscale ramp

// ── Truecolor / 24-bit (runtime formatting required) ─────────────────────────
pub const TRUECOLOR_FG = ESC ++ "38;2;"; //{r};{g};{b}m
pub const TRUECOLOR_BG = ESC ++ "48;2;";

// ── Cursor Movement ───────────────────────────────────────────────────────────
pub const CURSOR_SAVE = ESC ++ "s";
pub const CURSOR_RESTORE = ESC ++ "u";
pub const CURSOR_HOME = ESC ++ "H"; // top-left (1,1)
pub const CURSOR_SHOW = ESC ++ "?25h";
pub const CURSOR_HIDE = ESC ++ "?25l";

// Parameterized
// Move to row R, col C:  ESC ++ "{R};{C}H"
// Move up N:             ESC ++ "{N}A"
// Move down N:           ESC ++ "{N}B"
// Move right N:          ESC ++ "{N}C"
// Move left N:           ESC ++ "{N}D"
// Move to col N:         ESC ++ "{N}G"

// ── Erase ─────────────────────────────────────────────────────────────────────
pub const ERASE_SCREEN = ESC ++ "2J"; // clear entire screen
pub const ERASE_SCREEN_DOWN = ESC ++ "0J"; // cursor to end
pub const ERASE_SCREEN_UP = ESC ++ "1J"; // cursor to start
pub const ERASE_LINE = ESC ++ "2K"; // entire line
pub const ERASE_LINE_RIGHT = ESC ++ "0K"; // cursor to end of line
pub const ERASE_LINE_LEFT = ESC ++ "1K"; // cursor to start of line

// ── Scrolling ─────────────────────────────────────────────────────────────────
// Scroll up N:   ESC ++ "{N}S"
// Scroll down N: ESC ++ "{N}T"

// ── Screen Modes ─────────────────────────────────────────────────────────────
pub const ALT_SCREEN_ENTER = ESC ++ "?1049h";
pub const ALT_SCREEN_EXIT = ESC ++ "?1049l";

/// Moves the cursor in the terminal to the given coordinates
pub fn moveCursor(writer: *std.Io.Writer, col: u8, row: u8) !void {
    try writer.print("{s}{d};{d}H", .{ ESC, col, row });
    try writer.flush();
}

/// Clears the terminal screen
pub fn clearScreen(writer: *std.Io.Writer) !void {
    try writer.print(ERASE_SCREEN, .{});
    try writer.flush();
}

const ENABLE_ECHO_INPUT: u32 = if (is_windows) 0x0004 else 0;
const ENABLE_EXTENDED_FLAGS: u32 = if (is_windows) 0x0080 else 0;
const ENABLE_LINE_INPUT: u32 = if (is_windows) 0x0002 else 0;
const ENABLE_PROCESSED_INPUT: u32 = if (is_windows) 0x0001 else 0;
const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = if (is_windows) 0x0004 else 0;
const ENABLE_WINDOW_INPUT: u32 = if (is_windows) 0x0008 else 0;

/// Returns the current terminal dimensions as columns (x) and rows (y).
pub fn getTerminalSize(io: std.Io, file: std.Io.File) !Coord {
    if (is_windows) {
        var screen_buffer_info = windows.CONSOLE.USER_IO.GET_SCREEN_BUFFER_INFO;
        switch (try screen_buffer_info.operate(io, file)) {
            .SUCCESS => return Coord{
                .x = screen_buffer_info.Data.dwWindowSize.X,
                .y = screen_buffer_info.Data.dwWindowSize.Y,
            },
            else => return Coord{ .x = 0, .y = 0 },
        }
    } else {
        var winsize: posix.winsize = undefined;
        const rc = posix.system.ioctl(file.handle, posix.T.IOCGWINSZ, @intFromPtr(&winsize));
        if (rc == 0) {
            std.log.debug("getTerminalSize: fd={d} col={d} row={d}", .{ file.handle, winsize.col, winsize.row });
            return Coord{
                .x = @intCast(winsize.col),
                .y = @intCast(winsize.row),
            };
        }
        std.log.debug("getTerminalSize: ioctl failed rc={d} fd={d}", .{ rc, file.handle });
        return Coord{ .x = 0, .y = 0 };
    }
}

/// Switches the terminal to raw mode, disabling line buffering and echo.
/// Returns the previous terminal state; pass it to disableRawMode to restore.
pub fn enableRawMode(io: std.Io, stdin: std.Io.File, stdout: std.Io.File) !if (is_windows) u32 else posix.termios {
    if (is_windows) {
        var set_cp_out = windows.CONSOLE.USER_IO.SET_CP(.Output, 65001);
        _ = try set_cp_out.operate(io, stdout);
        var set_cp_in = windows.CONSOLE.USER_IO.SET_CP(.Input, 65001);
        _ = try set_cp_in.operate(io, stdin);

        var get_mode = windows.CONSOLE.USER_IO.GET_MODE;
        _ = try get_mode.operate(io, stdin);
        const original_mode = get_mode.Data;

        var set_stdin = windows.CONSOLE.USER_IO.SET_MODE(original_mode & ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT | ENABLE_WINDOW_INPUT | ENABLE_EXTENDED_FLAGS));
        _ = try set_stdin.operate(io, stdin);

        var get_out = windows.CONSOLE.USER_IO.GET_MODE;
        _ = try get_out.operate(io, stdout);
        var set_stdout = windows.CONSOLE.USER_IO.SET_MODE(get_out.Data | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        _ = try set_stdout.operate(io, stdout);

        return original_mode;
    } else {
        std.log.debug("enableRawMode: stdin.handle={d} stdout.handle={d}", .{ stdin.handle, stdout.handle });
        const original = try posix.tcgetattr(stdin.handle);
        var raw = original;
        // clear canonical mode, echo, signals
        raw.lflag.ICANON = false;
        raw.lflag.ECHO = false;
        raw.lflag.ISIG = false;
        raw.lflag.IEXTEN = false;
        // clear software flow control, CR to NL translation
        raw.iflag.IXON = false;
        raw.iflag.ICRNL = false;
        raw.iflag.BRKINT = false;
        raw.iflag.INPCK = false;
        raw.iflag.ISTRIP = false;
        // output: disable NL to CRNL
        raw.oflag.OPOST = false;
        // read: return after 1 byte, no timeout
        raw.cc[@intFromEnum(posix.V.MIN)] = 1;
        raw.cc[@intFromEnum(posix.V.TIME)] = 0;
        try std.posix.tcsetattr(stdin.handle, .FLUSH, raw);
        std.log.debug("enableRawMode: raw mode set OK", .{});
        return original;
    }
}

/// Restores the terminal to the state captured by enableRawMode.
pub fn disableRawMode(io: std.Io, stdin: std.Io.File, original: if (is_windows) u32 else std.posix.termios) !void {
    if (is_windows) {
        var set_mode = windows.CONSOLE.USER_IO.SET_MODE(original);
        _ = try set_mode.operate(io, stdin);
    } else {
        try posix.tcsetattr(stdin.handle, .FLUSH, original);
    }
}
