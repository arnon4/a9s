const std = @import("std");
const Credentials = @import("../../../sdk/credentials/fetcher.zig").Credentials;
const terminal = @import("../../../terminal/terminal.zig");
const input = @import("../../../terminal/input.zig");
const Event = @import("../../../event.zig").Event;
const view_mod = @import("../../../ui/view.zig");
const Action = view_mod.Action;
const ViewContext = view_mod.ViewContext;
const Coord = terminal.Coord;
const Ec2 = @import("../../../sdk/clients/ec2/client.zig");
const props_mod = @import("../../../ui/props.zig");
const constants = @import("../../../ui/constants.zig");
const ConfirmView = @import("../../../ui/confirm.zig");

const DhcpOptionsView = @This();
pub const name: []const u8 = "DHCP Options";

const MAX_CONFIG_PROPS = 30;
const MAX_TAG_PROPS = 50;
const MAX_PROPS = 8 + MAX_CONFIG_PROPS + MAX_TAG_PROPS;

// ─── Background fetch context ────────────────────────────────────────────────

const FetchCtx = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    credentials: Credentials,
    region: []u8,
    dhcp_options_id: []u8,
    result: ?Ec2.DescribeDhcpOptionsResult = null,
    err: ?anyerror = null,
    done: std.atomic.Value(bool) = .init(false),
    thread: std.Thread = undefined,
};

fn fetchThread(ctx: *FetchCtx) void {
    defer {
        ctx.done.store(true, .release);
        input.notify();
    }

    var client = Ec2.Client.init(ctx.allocator, .{
        .region = ctx.region,
        .io = ctx.io,
        .credentials = ctx.credentials,
    }) catch |e| {
        ctx.err = e;
        return;
    };
    defer client.deinit();

    const ids = [_][]const u8{ctx.dhcp_options_id};
    const result = client.describeDhcpOptions(.{ .params = .{ .dhcp_options_ids = &ids } }) catch |e| {
        ctx.err = e;
        return;
    };
    ctx.result = result;
    if (result.dhcp_options.len == 0) ctx.err = error.DhcpOptionsNotFound;
}

// ─── View fields ─────────────────────────────────────────────────────────────

fg_color: []const u8,
bg_color: []const u8,
scroll: usize = 0,
pending_g: bool = false,
display_name: []u8,
ctx: *FetchCtx,
alloc: std.mem.Allocator,
breadcrumb_buf: [320]u8 = undefined,
breadcrumb_len: usize = 0,

// ─── Init / deinit ───────────────────────────────────────────────────────────

pub fn init(
    allocator: std.mem.Allocator,
    io: std.Io,
    credentials: Credentials,
    region: []const u8,
    dhcp_options_id: []const u8,
    display_name: []const u8,
    fg_color: []const u8,
    bg_color: []const u8,
    parent_breadcrumb: []const u8,
) !DhcpOptionsView {
    const display_owned = try allocator.dupe(u8, display_name);
    errdefer allocator.free(display_owned);

    const ctx = try allocator.create(FetchCtx);
    errdefer allocator.destroy(ctx);
    const region_owned = try allocator.dupe(u8, region);
    errdefer allocator.free(region_owned);
    const id_owned = try allocator.dupe(u8, dhcp_options_id);
    errdefer allocator.free(id_owned);

    ctx.* = .{
        .allocator = allocator,
        .io = io,
        .credentials = credentials,
        .region = region_owned,
        .dhcp_options_id = id_owned,
    };
    ctx.thread = try std.Thread.spawn(.{}, fetchThread, .{ctx});

    var view = DhcpOptionsView{
        .fg_color = fg_color,
        .bg_color = bg_color,
        .display_name = display_owned,
        .ctx = ctx,
        .alloc = allocator,
    };
    const bc = std.fmt.bufPrint(&view.breadcrumb_buf, "{s} {s} {s}", .{ parent_breadcrumb, constants.SEP_ARROW, display_name }) catch view.breadcrumb_buf[0..0];
    view.breadcrumb_len = bc.len;
    return view;
}

pub fn breadcrumb(self: *DhcpOptionsView) []const u8 {
    return self.breadcrumb_buf[0..self.breadcrumb_len];
}

pub fn deinit(self: *DhcpOptionsView) void {
    const alloc = self.ctx.allocator;
    self.ctx.thread.join();
    if (self.ctx.result) |r| r.deinit();
    alloc.free(self.ctx.region);
    alloc.free(self.ctx.dhcp_options_id);
    alloc.destroy(self.ctx);
    self.alloc.free(self.display_name);
}

// ─── Event handling ──────────────────────────────────────────────────────────

pub fn handleEvent(self: *DhcpOptionsView, event: Event, _: ViewContext) !Action {
    switch (event) {
        .key => |k| switch (k) {
            .ctrl_c => return .quit,
            .char => |c| switch (c) {
                'q' => return .{ .push = .{ .confirm = ConfirmView.init(self.fg_color, self.bg_color) } },
                'j' => self.scroll += 1,
                'k' => if (self.scroll > 0) {
                    self.scroll -= 1;
                },
                'g' => {
                    if (self.pending_g) {
                        self.scroll = 0;
                        self.pending_g = false;
                    } else {
                        self.pending_g = true;
                    }
                },
                'G' => {
                    self.pending_g = false;
                    // render clamps to the real row count
                    self.scroll = MAX_PROPS;
                },
                else => self.pending_g = false,
            },
            .down => self.scroll += 1,
            .up => if (self.scroll > 0) {
                self.scroll -= 1;
            },
            .escape => return .pop,
            else => {},
        },
        else => {},
    }
    return .none;
}

// ─── Rendering ───────────────────────────────────────────────────────────────

/// Bump-allocates formatted text from a fixed buffer; yields "…" when full.
const TextBuf = struct {
    buf: []u8,
    off: usize = 0,

    fn print(self: *TextBuf, comptime fmt: []const u8, args: anytype) []const u8 {
        const out = std.fmt.bufPrint(self.buf[self.off..], fmt, args) catch return "…";
        self.off += out.len;
        return out;
    }
};

fn orDash(s: []const u8) []const u8 {
    return if (s.len > 0) s else "-";
}

fn joinValues(text: *TextBuf, values: []const []u8) []const u8 {
    if (values.len == 0) return "-";
    const start = text.off;
    for (values, 0..) |v, i| {
        const sep: []const u8 = if (i > 0) ", " else "";
        _ = text.print("{s}{s}", .{ sep, v });
    }
    return text.buf[start..text.off];
}

pub fn render(self: *DhcpOptionsView, writer: *std.Io.Writer, size: Coord) !void {
    if (size.x < 10 or size.y < 2) return;
    const w: usize = @intCast(size.x);
    const h: usize = @intCast(size.y);

    const done = self.ctx.done.load(.acquire);
    const opts: ?Ec2.DhcpOptions = if (done and self.ctx.err == null) self.ctx.result.?.dhcp_options[0] else null;

    var text_storage: [8192]u8 = undefined;
    var text: TextBuf = .{ .buf = &text_storage };

    const dash = "-";
    const pending: []const u8 = if (done) dash else "…";

    var props_buf: [MAX_PROPS]props_mod.Prop = undefined;
    var n: usize = 0;

    props_buf[n] = .{ .label = "Name", .value = if (opts) |o| orDash(o.name) else orDash(self.display_name) };
    n += 1;
    props_buf[n] = .{ .label = "DHCP Options ID", .value = self.ctx.dhcp_options_id };
    n += 1;
    props_buf[n] = .{ .label = "Region", .value = self.ctx.region };
    n += 1;

    if (self.ctx.err) |e| {
        if (done) {
            props_buf[n] = .{ .label = "Error", .value = @errorName(e) };
            n += 1;
        }
    }

    props_buf[n] = .{ .label = "Account", .value = if (opts) |o| orDash(o.owner_id) else pending };
    n += 1;

    if (opts) |o| {
        if (o.configurations.len == 0) {
            props_buf[n] = .{ .label = "Options", .value = dash };
            n += 1;
        }
        for (o.configurations[0..@min(o.configurations.len, MAX_CONFIG_PROPS)]) |c| {
            props_buf[n] = .{ .label = c.key, .value = joinValues(&text, c.values) };
            n += 1;
        }
        if (o.tags.len == 0) {
            props_buf[n] = .{ .label = "Tags", .value = dash };
            n += 1;
        }
        for (o.tags[0..@min(o.tags.len, MAX_TAG_PROPS)], 0..) |t, i| {
            props_buf[n] = .{
                .label = if (i == 0) "Tags" else "",
                .value = text.print("{s} = {s}", .{ t.key, t.value }),
            };
            n += 1;
        }
    } else {
        props_buf[n] = .{ .label = "Options", .value = pending };
        n += 1;
    }

    const total = n;
    const data_rows = if (h >= 1) h - 1 else 0;
    if (data_rows > 0 and self.scroll + data_rows > total) {
        self.scroll = if (total > data_rows) total - data_rows else 0;
    }

    try props_mod.render(writer, props_buf[0..n], self.scroll, w, h, self.fg_color);
}
