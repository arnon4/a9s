const terminal = @import("terminal/terminal.zig");
const Coord = terminal.Coord;
const View = @import("ui/view.zig").View;

/// All events the application can receive from the terminal.
pub const Event = union(enum) {
    key: Key,
    resize: Coord,
    tick, // background notify — no input, just re-check state
};

/// A key press or key combination received from the terminal.
pub const Key = union(enum) {
    char: u8,
    up,
    down,
    left,
    right,
    enter,
    escape,
    backspace,
    ctrl_c,
};
