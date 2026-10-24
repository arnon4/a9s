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
const VpcView = @import("vpc.zig");
const SubnetView = @import("subnet.zig");
const SecurityGroupView = @import("security_group.zig");

const NetworkInterfaceView = @This();
pub const name: []const u8 = "Network Interface";

/// Breadcrumbs of the lists an entry is shown under when reached from here.
const vpcs_breadcrumb = "VPC " ++ constants.SEP_ARROW ++ " VPCs";
const subnets_breadcrumb = "VPC " ++ constants.SEP_ARROW ++ " Subnets";
const groups_breadcrumb = "VPC " ++ constants.SEP_ARROW ++ " Security Groups";

const MAX_TAG_PROPS = 50;
const MAX_GROUP_PROPS = 20;
const MAX_IP_PROPS = 30;
const MAX_IPV6_PROPS = 10;
const MAX_PERMISSION_PROPS = 20;
const MAX_PROPS = 28 + MAX_TAG_PROPS + MAX_GROUP_PROPS + MAX_IP_PROPS + MAX_IPV6_PROPS + MAX_PERMISSION_PROPS;

// ─── Background fetch context ────────────────────────────────────────────────

const FetchCtx = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    credentials: Credentials,
    region: []u8,
    network_interface_id: []u8,
    result: ?Ec2.DescribeNetworkInterfacesResult = null,
    /// Accounts and services allowed to use the interface; best effort.
    permissions: ?Ec2.DescribeNetworkInterfacePermissionsResult = null,
    /// Name tags of the owning VPC and subnet, when they have one; they label the breadcrumb.
    vpc_name: ?[]u8 = null,
    subnet_name: ?[]u8 = null,
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

    const ids = [_][]const u8{ctx.network_interface_id};
    const result = client.describeNetworkInterfaces(.{ .params = .{ .network_interface_ids = &ids } }) catch |e| {
        ctx.err = e;
        return;
    };
    ctx.result = result;
    if (result.network_interfaces.len == 0) {
        ctx.err = error.NetworkInterfaceNotFound;
        return;
    }
    const eni = result.network_interfaces[0];

    // Best effort from here on: these only add detail.
    const by_eni = [_]Ec2.Filter{.{ .name = "network-interface-permission.network-interface-id", .values = &ids }};
    ctx.permissions = client.describeNetworkInterfacePermissions(.{ .params = .{ .filters = &by_eni } }) catch null;

    if (eni.vpc_id.len > 0) {
        const vpc_ids = [_][]const u8{eni.vpc_id};
        if (client.describeVpcs(.{ .params = .{ .vpc_ids = &vpc_ids } })) |r| {
            defer r.deinit();
            if (r.vpcs.len > 0 and r.vpcs[0].name.len > 0) ctx.vpc_name = ctx.allocator.dupe(u8, r.vpcs[0].name) catch null;
        } else |_| {}
    }
    if (eni.subnet_id.len > 0) {
        const subnet_ids = [_][]const u8{eni.subnet_id};
        if (client.describeSubnets(.{ .params = .{ .subnet_ids = &subnet_ids } })) |r| {
            defer r.deinit();
            if (r.subnets.len > 0 and r.subnets[0].name.len > 0) ctx.subnet_name = ctx.allocator.dupe(u8, r.subnets[0].name) catch null;
        } else |_| {}
    }
}

// ─── View fields ─────────────────────────────────────────────────────────────

fg_color: []const u8,
bg_color: []const u8,
scroll: usize = 0,
pending_g: bool = false,
sel: usize = 0,
/// Row of the selected entry and visible row count, as of the last render.
sel_row: usize = 0,
view_rows: usize = 0,
/// Scroll to keep the selected entry on screen at the next render.
follow_sel: bool = false,
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
    network_interface_id: []const u8,
    display_name: []const u8,
    fg_color: []const u8,
    bg_color: []const u8,
    parent_breadcrumb: []const u8,
) !NetworkInterfaceView {
    const display_owned = try allocator.dupe(u8, display_name);
    errdefer allocator.free(display_owned);

    const ctx = try allocator.create(FetchCtx);
    errdefer allocator.destroy(ctx);
    const region_owned = try allocator.dupe(u8, region);
    errdefer allocator.free(region_owned);
    const id_owned = try allocator.dupe(u8, network_interface_id);
    errdefer allocator.free(id_owned);

    ctx.* = .{
        .allocator = allocator,
        .io = io,
        .credentials = credentials,
        .region = region_owned,
        .network_interface_id = id_owned,
    };
    ctx.thread = try std.Thread.spawn(.{}, fetchThread, .{ctx});

    var view = NetworkInterfaceView{
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

pub fn breadcrumb(self: *NetworkInterfaceView) []const u8 {
    return self.breadcrumb_buf[0..self.breadcrumb_len];
}

pub fn deinit(self: *NetworkInterfaceView) void {
    const alloc = self.ctx.allocator;
    self.ctx.thread.join();
    if (self.ctx.result) |r| r.deinit();
    if (self.ctx.permissions) |r| r.deinit();
    if (self.ctx.vpc_name) |n| alloc.free(n);
    if (self.ctx.subnet_name) |n| alloc.free(n);
    alloc.free(self.ctx.region);
    alloc.free(self.ctx.network_interface_id);
    alloc.destroy(self.ctx);
    self.alloc.free(self.display_name);
}

// ─── Selection ───────────────────────────────────────────────────────────────

/// Selectable entries, in order: the VPC, the subnet (each only when known), then the security groups.
const Selection = union(enum) {
    vpc,
    subnet,
    group: usize,
};

/// The interface, once the fetch has finished without error.
fn loaded(self: *const NetworkInterfaceView) ?Ec2.NetworkInterface {
    if (!self.ctx.done.load(.acquire) or self.ctx.err != null) return null;
    return self.ctx.result.?.network_interfaces[0];
}

fn hasVpc(self: *const NetworkInterfaceView) bool {
    const e = self.loaded() orelse return false;
    return e.vpc_id.len > 0;
}

fn hasSubnet(self: *const NetworkInterfaceView) bool {
    const e = self.loaded() orelse return false;
    return e.subnet_id.len > 0;
}

fn groupCount(self: *const NetworkInterfaceView) usize {
    const e = self.loaded() orelse return 0;
    return @min(e.groups.len, MAX_GROUP_PROPS);
}

fn selectableCount(self: *const NetworkInterfaceView) usize {
    return @as(usize, @intFromBool(self.hasVpc())) + @intFromBool(self.hasSubnet()) + self.groupCount();
}

fn selection(self: *const NetworkInterfaceView) ?Selection {
    const count = self.selectableCount();
    if (count == 0) return null;
    var i = @min(self.sel, count - 1);
    if (self.hasVpc()) {
        if (i == 0) return .vpc;
        i -= 1;
    }
    if (self.hasSubnet()) {
        if (i == 0) return .subnet;
        i -= 1;
    }
    return .{ .group = i };
}

/// Moves the selection when the selected row is on screen.
/// Returns false when it cannot move, so the caller scrolls instead.
fn moveSel(self: *NetworkInterfaceView, delta: i32) bool {
    self.pending_g = false;
    const count = self.selectableCount();
    if (count == 0 or self.view_rows == 0) return false;
    if (self.sel_row < self.scroll or self.sel_row >= self.scroll + self.view_rows) return false;
    if (delta < 0) {
        if (self.sel == 0) return false;
        self.sel -= 1;
    } else {
        if (self.sel + 1 >= count) return false;
        self.sel += 1;
    }
    self.follow_sel = true;
    return true;
}

// ─── Event handling ──────────────────────────────────────────────────────────

pub fn handleEvent(self: *NetworkInterfaceView, event: Event, ctx: ViewContext) !Action {
    switch (event) {
        .key => |k| switch (k) {
            .ctrl_c => return .quit,
            .char => |c| switch (c) {
                'q' => return .{ .push = .{ .confirm = ConfirmView.init(self.fg_color, self.bg_color) } },
                'j' => if (!self.moveSel(1)) {
                    self.scroll += 1;
                },
                'k' => if (!self.moveSel(-1)) {
                    if (self.scroll > 0) self.scroll -= 1;
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
            .down => if (!self.moveSel(1)) {
                self.scroll += 1;
            },
            .up => if (!self.moveSel(-1)) {
                if (self.scroll > 0) self.scroll -= 1;
            },
            .enter => {
                const eni = self.loaded() orelse return .none;
                switch (self.selection() orelse return .none) {
                    .vpc => {
                        const v = try VpcView.init(
                            ctx.allocator,
                            ctx.io,
                            self.ctx.credentials,
                            self.ctx.region,
                            eni.vpc_id,
                            self.ctx.vpc_name orelse eni.vpc_id,
                            self.fg_color,
                            self.bg_color,
                            vpcs_breadcrumb,
                        );
                        return .{ .push = .{ .vpc_vpc = v } };
                    },
                    .subnet => {
                        const v = try SubnetView.init(
                            ctx.allocator,
                            ctx.io,
                            self.ctx.credentials,
                            self.ctx.region,
                            eni.subnet_id,
                            self.ctx.subnet_name orelse eni.subnet_id,
                            self.fg_color,
                            self.bg_color,
                            subnets_breadcrumb,
                        );
                        return .{ .push = .{ .vpc_subnet = v } };
                    },
                    .group => |i| {
                        const g = eni.groups[i];
                        const v = try SecurityGroupView.init(
                            ctx.allocator,
                            ctx.io,
                            self.ctx.credentials,
                            self.ctx.region,
                            g.group_id,
                            if (g.group_name.len > 0) g.group_name else g.group_id,
                            self.fg_color,
                            self.bg_color,
                            groups_breadcrumb,
                        );
                        return .{ .push = .{ .vpc_security_group = v } };
                    },
                }
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

fn enabledLabel(b: bool) []const u8 {
    return if (b) "Enabled" else "Disabled";
}

pub fn render(self: *NetworkInterfaceView, writer: *std.Io.Writer, size: Coord) !void {
    if (size.x < 10 or size.y < 2) return;
    const w: usize = @intCast(size.x);
    const h: usize = @intCast(size.y);

    const done = self.ctx.done.load(.acquire);
    const eni = self.loaded();

    var text_storage: [16384]u8 = undefined;
    var text: TextBuf = .{ .buf = &text_storage };

    const dash = "-";
    const pending: []const u8 = if (done) dash else "…";

    var props_buf: [MAX_PROPS]props_mod.Prop = undefined;
    var n: usize = 0;

    props_buf[n] = .{ .label = "Name", .value = if (eni) |e| orDash(e.name) else orDash(self.display_name) };
    n += 1;
    props_buf[n] = .{ .label = "Network Interface ID", .value = self.ctx.network_interface_id };
    n += 1;
    props_buf[n] = .{ .label = "Region", .value = self.ctx.region };
    n += 1;

    if (self.ctx.err) |e| {
        if (done) {
            props_buf[n] = .{ .label = "Error", .value = @errorName(e) };
            n += 1;
        }
    }

    props_buf[n] = .{ .label = "Status", .value = if (eni) |e| orDash(e.status) else pending };
    n += 1;
    props_buf[n] = .{ .label = "Type", .value = if (eni) |e| orDash(e.interface_type) else pending };
    n += 1;
    props_buf[n] = .{ .label = "Description", .value = if (eni) |e| orDash(e.description) else pending };
    n += 1;

    const selected = self.selection();
    var selected_row: usize = 0;

    if (selected != null and selected.? == .vpc) selected_row = n;
    props_buf[n] = .{
        .label = "VPC ID",
        .value = if (eni) |e| orDash(e.vpc_id) else pending,
        .highlight = if (selected != null and selected.? == .vpc) self.bg_color else "",
    };
    n += 1;
    if (selected != null and selected.? == .subnet) selected_row = n;
    props_buf[n] = .{
        .label = "Subnet ID",
        .value = if (eni) |e| orDash(e.subnet_id) else pending,
        .highlight = if (selected != null and selected.? == .subnet) self.bg_color else "",
    };
    n += 1;

    props_buf[n] = .{ .label = "Availability Zone", .value = if (eni) |e| orDash(e.availability_zone) else pending };
    n += 1;
    props_buf[n] = .{ .label = "Account", .value = if (eni) |e| orDash(e.owner_id) else pending };
    n += 1;
    props_buf[n] = .{
        .label = "Requester",
        .value = if (eni) |e| (if (e.requester_managed) text.print("{s} (managed by an AWS service)", .{orDash(e.requester_id)}) else orDash(e.requester_id)) else pending,
    };
    n += 1;
    props_buf[n] = .{ .label = "MAC Address", .value = if (eni) |e| orDash(e.mac_address) else pending };
    n += 1;
    props_buf[n] = .{ .label = "Private IP", .value = if (eni) |e| orDash(e.private_ip) else pending };
    n += 1;
    props_buf[n] = .{ .label = "Private DNS", .value = if (eni) |e| orDash(e.private_dns_name) else pending };
    n += 1;
    props_buf[n] = .{ .label = "Public IP", .value = if (eni) |e| orDash(e.public_ip) else pending };
    n += 1;
    props_buf[n] = .{ .label = "Elastic IP Allocation", .value = if (eni) |e| orDash(e.allocation_id) else pending };
    n += 1;
    props_buf[n] = .{ .label = "Source/Dest Check", .value = if (eni) |e| enabledLabel(e.source_dest_check) else pending };
    n += 1;

    if (eni) |e| {
        // Security groups: each one selectable.
        if (e.groups.len == 0) {
            props_buf[n] = .{ .label = "Security Groups", .value = dash };
            n += 1;
        }
        for (e.groups[0..@min(e.groups.len, MAX_GROUP_PROPS)], 0..) |g, i| {
            const is_sel = selected != null and selected.? == .group and selected.?.group == i;
            if (is_sel) selected_row = n;
            props_buf[n] = .{
                .label = if (i == 0) "Security Groups" else "",
                .value = if (g.group_name.len > 0) text.print("{s} ({s})", .{ g.group_id, g.group_name }) else g.group_id,
                .highlight = if (is_sel) self.bg_color else "",
            };
            n += 1;
        }

        if (e.attachment) |at| {
            props_buf[n] = .{ .label = "Attached To", .value = if (at.instance_id.len > 0) at.instance_id else "another resource" };
            n += 1;
            const device = if (at.device_index) |d| text.print(", device index {d}", .{d}) else "";
            props_buf[n] = .{
                .label = "Attachment",
                .value = text.print("{s}{s}{s}", .{ orDash(at.status), device, if (at.delete_on_termination) ", deleted on termination" else "" }),
            };
            n += 1;
        } else {
            props_buf[n] = .{ .label = "Attached To", .value = "Not attached" };
            n += 1;
        }

        for (e.private_ips[0..@min(e.private_ips.len, MAX_IP_PROPS)], 0..) |ip, i| {
            props_buf[n] = .{
                .label = if (i == 0) "Private IPs" else "",
                .value = text.print("{s}{s}{s}{s}", .{
                    ip.private_ip,
                    if (ip.primary) " (primary)" else "",
                    if (ip.public_ip.len > 0) " -> " else "",
                    ip.public_ip,
                }),
            };
            n += 1;
        }
        for (e.ipv6_addresses[0..@min(e.ipv6_addresses.len, MAX_IPV6_PROPS)], 0..) |a, i| {
            props_buf[n] = .{ .label = if (i == 0) "IPv6 Addresses" else "", .value = a };
            n += 1;
        }

        if (self.ctx.permissions) |perms| {
            if (perms.permissions.len == 0) {
                props_buf[n] = .{ .label = "Permissions", .value = dash };
                n += 1;
            }
            for (perms.permissions[0..@min(perms.permissions.len, MAX_PERMISSION_PROPS)], 0..) |p, i| {
                const who = if (p.aws_account_id.len > 0) p.aws_account_id else orDash(p.aws_service);
                props_buf[n] = .{
                    .label = if (i == 0) "Permissions" else "",
                    .value = text.print("{s}: {s} [{s}]", .{ who, orDash(p.permission), orDash(p.state) }),
                };
                n += 1;
            }
        }

        if (e.tags.len == 0) {
            props_buf[n] = .{ .label = "Tags", .value = dash };
            n += 1;
        }
        for (e.tags[0..@min(e.tags.len, MAX_TAG_PROPS)], 0..) |tag, i| {
            props_buf[n] = .{
                .label = if (i == 0) "Tags" else "",
                .value = text.print("{s} = {s}", .{ tag.key, tag.value }),
            };
            n += 1;
        }
    }

    const total = n;
    const data_rows = if (h >= 1) h - 1 else 0;
    self.view_rows = data_rows;
    self.sel_row = selected_row;
    if (self.selectableCount() > 0 and self.sel >= self.selectableCount()) self.sel = self.selectableCount() - 1;
    if (self.follow_sel and data_rows > 0) {
        self.follow_sel = false;
        if (self.sel_row < self.scroll) self.scroll = self.sel_row;
        if (self.sel_row >= self.scroll + data_rows) self.scroll = self.sel_row + 1 - data_rows;
    }
    if (data_rows > 0 and self.scroll + data_rows > total) {
        self.scroll = if (total > data_rows) total - data_rows else 0;
    }

    try props_mod.render(writer, props_buf[0..n], self.scroll, w, h, self.fg_color);
}
