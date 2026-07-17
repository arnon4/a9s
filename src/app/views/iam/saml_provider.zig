const std = @import("std");
const colors_mod = @import("../../../ui/colors.zig");
const fetcher = @import("../../../sdk/credentials/fetcher.zig");
const Credentials = fetcher.Credentials;
const terminal = @import("../../../terminal/terminal.zig");
const input = @import("../../../terminal/input.zig");
const Event = @import("../../../event.zig").Event;
const view_mod = @import("../../../ui/view.zig");
const Action = view_mod.Action;
const ViewContext = view_mod.ViewContext;
const Coord = terminal.Coord;
const Iam = @import("../../../sdk/clients/iam/client.zig");
const props_mod = @import("../../../ui/props.zig");
const constants = @import("../../../ui/constants.zig");
const ConfirmView = @import("../../../ui/confirm.zig");

const IamSamlProviderView = @This();
pub const name: []const u8 = "IAM SAML Provider";

// ─── Background GetSAMLProvider context ──────────────────────────────────────

const GetSamlCtx = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    credentials: Credentials,
    arn: []u8,
    result: ?Iam.GetSAMLProviderResult = null,
    err: ?anyerror = null,
    done: std.atomic.Value(bool) = .init(false),
    thread: std.Thread = undefined,
};

fn getThread(ctx: *GetSamlCtx) void {
    defer {
        ctx.done.store(true, .release);
        input.notify();
    }

    var client = Iam.Client.init(ctx.allocator, .{
        .io = ctx.io,
        .credentials = ctx.credentials,
    }) catch |e| {
        ctx.err = e;
        return;
    };
    defer client.deinit();

    const result = client.getSAMLProvider(.{ .saml_provider_arn = ctx.arn }) catch |e| {
        ctx.err = e;
        return;
    };
    ctx.result = result;
}

// ─── View fields ─────────────────────────────────────────────────────────────

fg_color: []const u8,
bg_color: []const u8,
scroll: usize = 0,
pending_g: bool = false,
provider_name: []u8,
arn: []u8,
account_id: []u8,
ctx: *GetSamlCtx,
alloc: std.mem.Allocator,
breadcrumb_buf: [320]u8 = undefined,
breadcrumb_len: usize = 0,

// ─── Init / deinit ───────────────────────────────────────────────────────────

pub fn init(
    allocator: std.mem.Allocator,
    io: std.Io,
    credentials: Credentials,
    provider_name: []const u8,
    arn: []const u8,
    account_id: []const u8,
    fg_color: []const u8,
    bg_color: []const u8,
    parent_breadcrumb: []const u8,
) !IamSamlProviderView {
    const provider_name_owned = try allocator.dupe(u8, provider_name);
    errdefer allocator.free(provider_name_owned);
    const account_id_owned = try allocator.dupe(u8, account_id);
    errdefer allocator.free(account_id_owned);

    const ctx = try allocator.create(GetSamlCtx);
    errdefer allocator.destroy(ctx);
    const arn_owned = try allocator.dupe(u8, arn);
    errdefer allocator.free(arn_owned);

    ctx.* = .{
        .allocator = allocator,
        .io = io,
        .credentials = credentials,
        .arn = arn_owned,
    };
    ctx.thread = try std.Thread.spawn(.{}, getThread, .{ctx});

    var view = IamSamlProviderView{
        .fg_color = fg_color,
        .bg_color = bg_color,
        .provider_name = provider_name_owned,
        .arn = arn_owned,
        .account_id = account_id_owned,
        .ctx = ctx,
        .alloc = allocator,
    };
    const bc = std.fmt.bufPrint(&view.breadcrumb_buf, "{s} {s} {s}", .{ parent_breadcrumb, constants.SEP_ARROW, provider_name }) catch view.breadcrumb_buf[0..0];
    view.breadcrumb_len = bc.len;
    return view;
}

pub fn breadcrumb(self: *IamSamlProviderView) []const u8 {
    return self.breadcrumb_buf[0..self.breadcrumb_len];
}

pub fn deinit(self: *IamSamlProviderView) void {
    const alloc = self.ctx.allocator;
    if (!self.ctx.done.load(.acquire)) self.ctx.thread.join();
    if (self.ctx.result) |r| r.deinit();
    alloc.free(self.ctx.arn);
    alloc.destroy(self.ctx);
    self.alloc.free(self.provider_name);
    self.alloc.free(self.account_id);
}

// ─── Event handling ──────────────────────────────────────────────────────────

pub fn handleEvent(self: *IamSamlProviderView, event: Event, _: ViewContext) !Action {
    const total_props = 8;
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
                    self.scroll = total_props;
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

/// Pull the entityID attribute value out of the raw SAML metadata document's
/// top-level <EntityDescriptor entityID="..."> tag.
fn extractEntityId(doc: []const u8) ?[]const u8 {
    const needle = "entityID=\"";
    const start = std.mem.indexOf(u8, doc, needle) orelse return null;
    const val_start = start + needle.len;
    const end = std.mem.indexOfScalarPos(u8, doc, val_start, '"') orelse return null;
    return doc[val_start..end];
}

fn joinPrivateKeys(buf: []u8, keys: []Iam.SAMLPrivateKey) []const u8 {
    var end: usize = 0;
    for (keys, 0..) |k, i| {
        if (i > 0) {
            if (end + 2 > buf.len) break;
            @memcpy(buf[end .. end + 2], ", ");
            end += 2;
        }
        const entry = std.fmt.bufPrint(buf[end..], "{s} ({s})", .{ k.key_id, k.timestamp }) catch break;
        end += entry.len;
    }
    return buf[0..end];
}

pub fn render(self: *IamSamlProviderView, writer: *std.Io.Writer, size: Coord) !void {
    if (size.x < 10 or size.y < 2) return;
    const w: usize = @intCast(size.x);
    const h: usize = @intCast(size.y);

    const done = self.ctx.done.load(.acquire);
    const loading = !done;
    const res: ?Iam.GetSAMLProviderResult = if (done) self.ctx.result else null;

    const ellipsis = "…";
    const dash = "-";

    const created_str: []const u8 = if (res) |r| r.create_date else if (loading) ellipsis else dash;
    const valid_until_str: []const u8 = if (res) |r| r.valid_until else if (loading) ellipsis else dash;
    const entity_id_str: []const u8 = if (res) |r|
        (extractEntityId(r.saml_metadata_document) orelse dash)
    else if (loading) ellipsis else dash;
    const encryption_str: []const u8 = if (res) |r|
        (if (r.assertion_encryption_mode.len > 0) r.assertion_encryption_mode else dash)
    else if (loading) ellipsis else dash;

    var keys_buf: [1024]u8 = undefined;
    const keys_str: []const u8 = if (res) |r|
        (if (r.private_key_list.len > 0) joinPrivateKeys(&keys_buf, r.private_key_list) else dash)
    else if (loading) ellipsis else dash;

    var props_buf: [8]props_mod.Prop = undefined;
    var n: usize = 0;
    props_buf[n] = .{ .label = "Provider Name", .value = self.provider_name };
    n += 1;
    props_buf[n] = .{ .label = "ARN", .value = self.arn };
    n += 1;
    props_buf[n] = .{ .label = "Account", .value = self.account_id };
    n += 1;
    props_buf[n] = .{ .label = "Created", .value = created_str };
    n += 1;
    props_buf[n] = .{ .label = "Valid Until", .value = valid_until_str };
    n += 1;
    props_buf[n] = .{ .label = "Entity ID", .value = entity_id_str };
    n += 1;
    props_buf[n] = .{ .label = "Encryption Mode", .value = encryption_str };
    n += 1;
    props_buf[n] = .{ .label = "Private Keys", .value = keys_str };
    n += 1;

    const total = n;
    const data_rows = if (h >= 1) h - 1 else 0;
    if (data_rows > 0 and self.scroll + data_rows > total) {
        self.scroll = if (total > data_rows) total - data_rows else 0;
    }

    try props_mod.render(writer, props_buf[0..n], self.scroll, w, h, self.fg_color);
}
