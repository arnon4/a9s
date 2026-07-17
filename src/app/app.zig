const std = @import("std");
const builtin = @import("builtin");
const is_windows = builtin.os.tag == .windows;

const terminal = @import("../terminal/terminal.zig");
const Coord = terminal.Coord;
const getTerminalSize = terminal.getTerminalSize;
const view_mod = @import("../ui/view.zig");
const View = view_mod.View;
const ViewContext = view_mod.ViewContext;
const BaseView = @import("views/base.zig");
const AuthPromptView = @import("views/auth/prompt.zig");
const HelpView = @import("views/help.zig").HelpView;
const SSOProfileView = @import("views/auth/sso_profile.zig");
const sso = @import("../auth/sso.zig");

const input = @import("../terminal/input.zig");
const Event = @import("../event.zig").Event;
const Header = @import("../ui/header.zig");
const CommandBar = @import("../ui/cmdbar.zig").CommandBar;
const sts = @import("../sdk/clients/sts/client.zig");
const constants = @import("../ui/constants.zig");
const s3_buckets_mod = @import("views/s3/buckets.zig");
const BucketSortKey = s3_buckets_mod.BucketSortKey;
const ObjectSortKey = @import("views/s3/objects.zig").ObjectSortKey;
const filter_mod = @import("../commands/filter.zig");
const profile_cmd = @import("../commands/profile.zig");
const region_cmd = @import("../commands/region.zig");
const ProfileSet = @import("profile_set.zig").ProfileSet;
const LambdasView = @import("views/lambda/lambdas.zig");
const LambdaSortKey = LambdasView.LambdaSortKey;
const LogGroupsView = @import("views/logs/log_groups.zig");
const LogGroupsSortKey = LogGroupsView.SortKey;
const IamHomeView = @import("views/iam/iam_home.zig");
const IamRolesView = @import("views/iam/roles.zig");
const RoleSortKey = IamRolesView.RoleSortKey;
const IamPoliciesView = @import("views/iam/policies.zig");
const PolicySortKey = IamPoliciesView.PolicySortKey;
const IamUsersView = @import("views/iam/users.zig");
const UserSortKey = IamUsersView.UserSortKey;
const IamGroupsView = @import("views/iam/groups.zig");
const GroupSortKey = IamGroupsView.GroupSortKey;
const IamIdentityProvidersView = @import("views/iam/identity_providers.zig");
const ProviderSortKey = IamIdentityProvidersView.ProviderSortKey;
const SecretsView = @import("views/secretsmanager/secrets.zig");
const SecretSortKey = SecretsView.SortKey;

/// Top-level application state. Owns the terminal raw mode, view stack, and event loop.
pub const App = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    size: Coord,
    writer: *std.Io.Writer,
    views: std.ArrayList(View),
    header: Header,
    command_bar: CommandBar,
    profile_set: ProfileSet,
    regions: std.ArrayList([]u8),
    color_support: terminal.ColorSupport,
    original_console_mode: if (builtin.os.tag == .windows) std.os.windows.DWORD else std.posix.termios,

    const Self = @This();

    /// Initializes the application.
    pub fn init(io: std.Io, writer: *std.Io.Writer, allocator: std.mem.Allocator, environ_map: *const std.process.Environ.Map, environ: std.process.Environ) !Self {
        const stdin = std.Io.File.stdin();
        const stdout = std.Io.File.stdout();
        const size = try getTerminalSize(io, stdin);

        try input.initSignals();
        const original_mode = try terminal.enableRawMode(io, stdin, stdout);

        const color_support = terminal.getColorSupport(environ_map);
        const base = BaseView.init(environ_map);

        var views: std.ArrayList(View) = .empty;
        try views.append(allocator, .{ .base = base });

        var ps = ProfileSet.init(allocator, io, environ);
        try ps.add("default");

        var regions: std.ArrayList([]u8) = .empty;
        errdefer {
            for (regions.items) |r| allocator.free(r);
            regions.deinit(allocator);
        }
        const default_region = try allocator.dupe(u8, "us-east-1");
        errdefer allocator.free(default_region);
        try regions.append(allocator, default_region);

        std.log.debug("App.init: terminal size x={d} y={d}", .{ size.x, size.y });

        return Self{
            .allocator = allocator,
            .io = io,
            .size = size,
            .writer = writer,
            .views = views,
            .header = .{ .fg_color = base.fg_color },
            .command_bar = CommandBar.init(allocator, io, environ_map),
            .profile_set = ps,
            .regions = regions,
            .color_support = color_support,
            .original_console_mode = original_mode,
        };
    }

    /// Cleans up the allocated resources and restores terminal to previous mode.
    pub fn deinit(self: *Self) void {
        const stdin = std.Io.File.stdin();
        self.command_bar.deinit();
        self.profile_set.deinit();
        for (self.regions.items) |r| self.allocator.free(r);
        self.regions.deinit(self.allocator);
        for (self.views.items) |*v| v.deinit();
        self.views.deinit(self.allocator);
        self.writer.print(terminal.ALT_SCREEN_EXIT ++ terminal.CURSOR_SHOW, .{}) catch {};
        self.writer.flush() catch {};
        terminal.disableRawMode(self.io, stdin, self.original_console_mode) catch {};
    }

    /// Runs the app event loop.
    pub fn run(self: *Self) !void {
        const stdin = std.Io.File.stdin();

        std.log.debug("run: writing alt screen enter", .{});
        try self.writer.print(terminal.ALT_SCREEN_ENTER ++ terminal.CURSOR_HIDE, .{});
        std.log.debug("run: flushing alt screen enter", .{});
        try self.writer.flush();
        std.log.debug("run: flush done", .{});

        // Push auth prompt if no credentials are available yet.
        std.log.debug("run: checking credentials", .{});
        if (self.profile_set.primaryStore().getCredentials()) |_| {
            std.log.debug("run: credentials found, fetching account id", .{});
            self.fetchAccountId(0);
            std.log.debug("run: fetchAccountId done", .{});
        } else |_| {
            std.log.debug("run: no credentials, pushing auth prompt", .{});
            try self.newView(.{ .auth_prompt = AuthPromptView.init(self.color_support) });
            std.log.debug("run: auth prompt pushed", .{});
        }

        std.log.debug("run: calling renderFrame", .{});
        try self.renderFrame();

        while (true) {
            const maybe_event = try input.readEvent(stdin);
            const event: Event = if (maybe_event) |e| e else .tick;
            const view_context = ViewContext{
                .allocator = self.allocator,
                .io = self.io,
                .credentials = self.profile_set.primaryStore(),
                .region = self.regions.items[0],
                .regions = self.regions.items,
                .color_support = self.color_support,
                .search_text = if (self.command_bar.mode == .search) self.command_bar.buf[0..self.command_bar.len] else null,
                .account_id = self.profile_set.primaryEntry().account_id,
                .profile_set = &self.profile_set,
            };
            switch (event) {
                .resize => |size| {
                    std.log.debug("event: resize x={d} y={d}", .{ size.x, size.y });
                    self.size = size;
                },
                else => {
                    switch (event) {
                        .key => self.command_bar.clearError(),
                        else => {},
                    }
                    if (self.command_bar.isActive()) {
                        const bar_result = self.command_bar.handleEvent(event);
                        switch (bar_result) {
                            .none => {
                                if (self.command_bar.mode == .search) {
                                    self.updateViewLiveFilter(self.command_bar.buf[0..self.command_bar.len]);
                                }
                            },
                            .dismiss => self.updateViewLiveFilter(""),
                            .submit => |s| {
                                if (s.mode == .search) {
                                    switch (self.currentView().*) {
                                        .s3_buckets => |*v| v.commitFilter(s.text),
                                        .s3_objects => |*v| v.commitFilter(s.text),
                                        .s3_object_content => |*v| v.commitFilter(s.text),
                                        .lambda_functions => |*v| v.commitFilter(s.text),
                                        .lambda_function_content => |*v| v.commitFilter(s.text),
                                        .logs_log_groups => |*v| v.commitFilter(s.text),
                                        .logs_log_events => |*v| v.commitFilter(s.text),
                                        .iam_policy_document => |*v| v.commitFilter(s.text),
                                        .iam_role_trust_policy => |*v| v.commitFilter(s.text),
                                        .iam_roles => |*v| v.commitFilter(s.text),
                                        .iam_policies => |*v| v.commitFilter(s.text),
                                        .iam_users => |*v| v.commitFilter(s.text),
                                        .iam_groups => |*v| v.commitFilter(s.text),
                                        .iam_identity_providers => |*v| v.commitFilter(s.text),
                                        .iam_user_inline_policy_document => |*v| v.commitFilter(s.text),
                                        .iam_group_inline_policy_document => |*v| v.commitFilter(s.text),
                                        .secretsmanager_secrets => |*v| v.commitFilter(s.text),
                                        else => {},
                                    }
                                    self.updateViewLiveFilter("");
                                } else if (s.mode == .command) {
                                    try self.handleCommand(s.text);
                                }
                            },
                        }
                    } else {
                        const intercepted = blk: {
                            if (!self.currentView().wantsRawInput()) {
                                switch (event) {
                                    .key => |k| switch (k) {
                                        .char => |c| {
                                            if (c == ':') {
                                                self.command_bar.activate(.command);
                                                break :blk true;
                                            }
                                            if (c == '?') {
                                                try self.newView(.{ .help = HelpView.init(self.currentView().fgColor(), self.currentView().bgColor(), .general) });
                                                break :blk true;
                                            }
                                            if (c == '/') {
                                                const searchable = switch (self.currentView().*) {
                                                    .s3_buckets, .s3_objects, .s3_object_content, .lambda_functions, .lambda_function_content, .logs_log_groups, .logs_log_events, .iam_policy_document, .iam_role_trust_policy, .iam_roles, .iam_policies, .iam_users, .iam_groups, .iam_identity_providers, .iam_user_inline_policy_document, .iam_group_inline_policy_document, .secretsmanager_secrets => true,
                                                    else => false,
                                                };
                                                if (searchable) {
                                                    self.command_bar.activate(.search);
                                                    break :blk true;
                                                }
                                            }
                                        },
                                        else => {},
                                    },
                                    else => {},
                                }
                            }
                            break :blk false;
                        };
                        if (!intercepted) {
                            const action = try self.currentView().handleEvent(event, view_context);
                            switch (action) {
                                .none => {},
                                .quit => return,
                                .pop => {
                                    const popping_sso = self.currentView().* == .sso_profile;
                                    self.popView();
                                    if (popping_sso) try self.refreshCurrentViewForProfileChange();
                                },
                                .push => |v| try self.newView(v),
                                .command => |cmd| switch (cmd) {
                                    .login => {
                                        self.profile_set.clearAllCredentials();
                                        try self.newView(.{ .auth_prompt = AuthPromptView.init(self.color_support) });
                                    },
                                },
                            }
                        }
                    }
                },
            }
            try self.renderFrame();
        }
    }

    fn renderFrame(self: *Self) !void {
        std.log.debug("renderFrame: size x={d} y={d}", .{ self.size.x, self.size.y });
        try self.writer.writeAll(terminal.CURSOR_HOME);
        const body_size = Coord{
            .x = self.size.x,
            .y = self.size.y - Header.height(self.size) - 1,
        };
        var creds_buf: [256]u8 = undefined;
        const creds_display: []const u8 = blk: {
            const entries = self.profile_set.entries.items;
            if (entries.len > 1) break :blk "multiple credentials";
            const entry = &entries[0];
            const source: []const u8 = if (entry.store.credentials) |c| c.source else "Not authenticated";
            if (entry.account_id) |aid| {
                break :blk std.fmt.bufPrint(&creds_buf, "{s} ({s})", .{ source, aid }) catch source;
            }
            break :blk source;
        };
        self.header.fg_color = self.currentView().fgColor();
        var region_display_buf: [128]u8 = undefined;
        var region_display_len: usize = 0;
        for (self.regions.items, 0..) |r, i| {
            if (i > 0 and region_display_len + 2 <= region_display_buf.len) {
                region_display_buf[region_display_len] = ',';
                region_display_buf[region_display_len + 1] = ' ';
                region_display_len += 2;
            }
            const n = @min(r.len, region_display_buf.len - region_display_len);
            @memcpy(region_display_buf[region_display_len .. region_display_len + n], r[0..n]);
            region_display_len += n;
            if (region_display_len >= region_display_buf.len) break;
        }
        try self.header.render(self.writer, self.size, self.currentView().name(), region_display_buf[0..region_display_len], creds_display);
        try self.currentView().render(self.writer, body_size);
        try self.writer.writeAll("\r\n");
        try self.command_bar.render(self.writer, @intCast(self.size.x));
        try self.writer.flush();
    }

    fn updateViewLiveFilter(self: *Self, text: []const u8) void {
        switch (self.currentView().*) {
            .s3_buckets => |*v| v.setLiveFilter(text),
            .s3_objects => |*v| v.setLiveFilter(text),
            .s3_object_content => |*v| v.setLiveFilter(text),
            .lambda_functions => |*v| v.setLiveFilter(text),
            .lambda_function_content => |*v| v.setLiveFilter(text),
            .logs_log_groups => |*v| v.setLiveFilter(text),
            .logs_log_events => |*v| v.setLiveFilter(text),
            .iam_policy_document => |*v| v.setLiveFilter(text),
            .iam_role_trust_policy => |*v| v.setLiveFilter(text),
            .iam_roles => |*v| v.setLiveFilter(text),
            .iam_policies => |*v| v.setLiveFilter(text),
            .iam_users => |*v| v.setLiveFilter(text),
            .iam_groups => |*v| v.setLiveFilter(text),
            .iam_identity_providers => |*v| v.setLiveFilter(text),
            .iam_user_inline_policy_document => |*v| v.setLiveFilter(text),
            .iam_group_inline_policy_document => |*v| v.setLiveFilter(text),
            .secretsmanager_secrets => |*v| v.setLiveFilter(text),
            else => {},
        }
    }

    fn currentView(self: *Self) *View {
        return &self.views.items[self.views.items.len - 1];
    }

    fn newView(self: *Self, new_view: View) !void {
        const slot = try self.views.addOne(self.allocator);
        slot.* = new_view;
    }

    fn popView(self: *Self) void {
        if (self.views.items.len > 1) {
            self.views.items[self.views.items.len - 1].deinit();
            self.views.shrinkRetainingCapacity(self.views.items.len - 1);
        }
    }

    fn fetchAccountId(self: *Self, entry_idx: usize) void {
        if (entry_idx >= self.profile_set.entries.items.len) return;
        const entry = &self.profile_set.entries.items[entry_idx];
        const creds = entry.store.getCredentials() catch return;
        var sts_client = sts.Client.init(self.allocator, .{
            .region = self.regions.items[0],
            .io = self.io,
            .source_creds = creds,
        }) catch return;
        defer sts_client.deinit();
        const identity = sts_client.getCallerIdentity() catch return;
        defer identity.deinit();
        if (entry.account_id) |a| self.allocator.free(a);
        entry.account_id = self.allocator.dupe(u8, identity.account) catch null;
    }

    fn handleCommand(self: *Self, text: []const u8) !void {
        const t = std.mem.trim(u8, text, " ");
        if (std.mem.startsWith(u8, t, "sort")) {
            switch (parseSortCommand(self.currentView(), t)) {
                .ok => {},
                .not_allowed => self.command_bar.setError("not allowed in this view"),
                .unknown => self.command_bar.setError("unknown command"),
            }
            return;
        }
        if (std.mem.startsWith(u8, t, "profile")) {
            try self.handleProfileCommand(t);
            return;
        }
        if (std.mem.startsWith(u8, t, "filter")) {
            self.handleFilterCommand(t);
            return;
        }
        if (std.mem.startsWith(u8, t, "help")) {
            try self.handleHelpCommand(t);
            return;
        }
        if (std.mem.startsWith(u8, t, "region")) {
            try self.handleRegionCommand(t);
            return;
        }
        if (std.mem.startsWith(u8, t, "goto")) {
            try self.handleGotoCommand(t);
            return;
        }
        self.command_bar.setError("unknown command");
    }

    fn handleHelpCommand(self: *Self, t: []const u8) !void {
        const rest = std.mem.trim(u8, t["help".len..], " ");
        const topic: HelpView.Topic = if (rest.len == 0)
            .general
        else if (std.mem.eql(u8, rest, "profile"))
            .profile
        else if (std.mem.eql(u8, rest, "filter"))
            .filter
        else if (std.mem.eql(u8, rest, "sort") or std.mem.eql(u8, rest, "sort-desc"))
            .sort
        else if (std.mem.eql(u8, rest, "region"))
            .region
        else {
            self.command_bar.setError("unknown topic: try profile, filter, sort, region");
            return;
        };
        try self.newView(.{ .help = HelpView.init(
            self.currentView().fgColor(),
            self.currentView().bgColor(),
            topic,
        ) });
    }

    fn handleGotoCommand(self: *Self, t: []const u8) !void {
        const rest = std.mem.trim(u8, t["goto".len..], " ");
        if (rest.len == 0) {
            self.command_bar.setError("usage: :goto <view>");
            return;
        }
        std.log.debug("goto: target='{s}' region='{s}'", .{ rest, self.regions.items[0] });
        if (std.ascii.eqlIgnoreCase(rest, "s3")) {
            const v = try s3_buckets_mod.S3BucketsView.init(self.allocator, self.io, &self.profile_set, self.regions.items[0], self.color_support);
            try self.newView(.{ .s3_buckets = v });
        } else if (std.ascii.eqlIgnoreCase(rest, "lambda")) {
            const v = try LambdasView.init(self.allocator, self.io, &self.profile_set, self.regions.items, self.color_support);
            try self.newView(.{ .lambda_functions = v });
        } else if (std.ascii.eqlIgnoreCase(rest, "logs")) {
            const v = try LogGroupsView.init(self.allocator, self.io, &self.profile_set, self.regions.items, self.color_support);
            try self.newView(.{ .logs_log_groups = v });
        } else if (std.ascii.eqlIgnoreCase(rest, "iam")) {
            try self.newView(.{ .iam_home = IamHomeView.init(self.color_support) });
        } else if (std.ascii.eqlIgnoreCase(rest, "secrets") or std.ascii.eqlIgnoreCase(rest, "secretsmanager")) {
            const v = try SecretsView.init(self.allocator, self.io, &self.profile_set, self.regions.items, self.color_support);
            try self.newView(.{ .secretsmanager_secrets = v });
        } else {
            self.command_bar.setErrorFmt("unknown view: '{s}'", .{rest});
        }
    }

    fn handleRegionCommand(self: *Self, t: []const u8) !void {
        const rest = std.mem.trim(u8, t["region".len..], " ");
        var cmd = region_cmd.parse(self.allocator, rest) catch {
            self.command_bar.setError("usage: :region add|remove|use <region> [...]");
            return;
        };
        defer cmd.deinit();

        switch (cmd.subcmd) {
            .show => {
                var pos: usize = 0;
                const ebuf = &self.command_bar.error_buf;
                for (self.regions.items, 0..) |r, i| {
                    if (i > 0 and pos + 2 <= ebuf.len) {
                        ebuf[pos] = ',';
                        ebuf[pos + 1] = ' ';
                        pos += 2;
                    }
                    const n = @min(r.len, ebuf.len - pos);
                    @memcpy(ebuf[pos .. pos + n], r[0..n]);
                    pos += n;
                    if (pos >= ebuf.len) break;
                }
                self.command_bar.error_msg = ebuf[0..pos];
                return;
            },
            else => {},
        }

        if (cmd.regions.len == 0) {
            self.command_bar.setError("usage: :region add|remove|use <region> [...]");
            return;
        }

        switch (cmd.subcmd) {
            .show => unreachable,
            .add => {
                for (cmd.regions) |r| {
                    var exists = false;
                    for (self.regions.items) |existing| {
                        if (std.mem.eql(u8, existing, r)) {
                            exists = true;
                            break;
                        }
                    }
                    if (!exists) {
                        const owned = try self.allocator.dupe(u8, r);
                        errdefer self.allocator.free(owned);
                        try self.regions.append(self.allocator, owned);
                    }
                }
            },
            .remove => {
                for (cmd.regions) |r| {
                    for (self.regions.items, 0..) |existing, i| {
                        if (std.mem.eql(u8, existing, r)) {
                            self.allocator.free(existing);
                            _ = self.regions.orderedRemove(i);
                            break;
                        }
                    }
                }
                if (self.regions.items.len == 0) {
                    const fallback = try self.allocator.dupe(u8, "us-east-1");
                    try self.regions.append(self.allocator, fallback);
                }
            },
            .use => {
                for (self.regions.items) |r| self.allocator.free(r);
                self.regions.clearRetainingCapacity();
                for (cmd.regions) |r| {
                    const owned = try self.allocator.dupe(u8, r);
                    errdefer self.allocator.free(owned);
                    try self.regions.append(self.allocator, owned);
                }
            },
        }

        try self.refreshCurrentViewForRegionChange();
    }

    fn refreshCurrentViewForProfileChange(self: *Self) !void {
        switch (self.currentView().*) {
            .s3_buckets => |*v| {
                const new_v = s3_buckets_mod.S3BucketsView.init(
                    self.allocator,
                    self.io,
                    &self.profile_set,
                    self.regions.items[0],
                    self.color_support,
                ) catch return;
                v.deinit();
                self.currentView().* = .{ .s3_buckets = new_v };
            },
            .lambda_functions => |*v| {
                const new_v = LambdasView.init(
                    self.allocator,
                    self.io,
                    &self.profile_set,
                    self.regions.items,
                    self.color_support,
                ) catch return;
                v.deinit();
                self.currentView().* = .{ .lambda_functions = new_v };
            },
            .logs_log_groups => |*v| {
                const new_v = LogGroupsView.init(self.allocator, self.io, &self.profile_set, self.regions.items, self.color_support) catch return;
                v.deinit();
                self.currentView().* = .{ .logs_log_groups = new_v };
            },
            .secretsmanager_secrets => |*v| {
                const new_v = SecretsView.init(self.allocator, self.io, &self.profile_set, self.regions.items, self.color_support) catch return;
                v.deinit();
                self.currentView().* = .{ .secretsmanager_secrets = new_v };
            },
            else => {},
        }
    }

    fn refreshCurrentViewForRegionChange(self: *Self) !void {
        switch (self.currentView().*) {
            // S3 uses a single stored region, unaffected by the region list.
            .s3_buckets, .s3_objects, .s3_object, .s3_object_content, .s3_download => {},
            // Non-data views: nothing to refresh.
            .base, .sso_profile, .manual_credentials, .auth_prompt, .message, .confirm, .help => {},
            .lambda_functions => |*v| {
                const new_v = LambdasView.init(self.allocator, self.io, &self.profile_set, self.regions.items, self.color_support) catch return;
                v.deinit();
                self.currentView().* = .{ .lambda_functions = new_v };
            },
            .logs_log_groups => |*v| {
                const new_v = LogGroupsView.init(self.allocator, self.io, &self.profile_set, self.regions.items, self.color_support) catch return;
                v.deinit();
                self.currentView().* = .{ .logs_log_groups = new_v };
            },
            .secretsmanager_secrets => |*v| {
                const new_v = SecretsView.init(self.allocator, self.io, &self.profile_set, self.regions.items, self.color_support) catch return;
                v.deinit();
                self.currentView().* = .{ .secretsmanager_secrets = new_v };
            },
            // Detail views are region-independent; no refresh needed.
            .lambda_function, .lambda_function_content, .logs_log_streams, .logs_log_events => {},
            .secretsmanager_secret, .secretsmanager_secret_value, .secretsmanager_resource_policy => {},
            // IAM is global; no region refresh needed.
            .iam_home, .iam_roles, .iam_policies, .iam_role, .iam_role_policies, .iam_role_trust_policy, .iam_policy, .iam_policy_document => {},
            .iam_users, .iam_user, .iam_user_inline_policies, .iam_user_inline_policy_document => {},
            .iam_groups, .iam_group, .iam_group_inline_policies, .iam_group_inline_policy_document => {},
            .iam_identity_providers, .iam_oidc_provider, .iam_saml_provider => {},
        }
    }

    fn handleFilterCommand(self: *Self, t: []const u8) void {
        const rest = std.mem.trim(u8, t["filter".len..], " ");
        const filterable = switch (self.currentView().*) {
            .s3_buckets, .s3_objects, .lambda_functions, .logs_log_groups, .iam_roles, .iam_policies, .iam_users, .iam_groups, .iam_identity_providers, .secretsmanager_secrets => true,
            else => false,
        };
        if (!filterable) {
            self.command_bar.setError("not allowed in this view");
            return;
        }
        if (rest.len == 0) {
            switch (self.currentView().*) {
                .s3_buckets => |*v| v.clearFilterExpr(),
                .s3_objects => |*v| v.clearFilterExpr(),
                .lambda_functions => |*v| v.clearFilterExpr(),
                .logs_log_groups => |*v| v.clearFilterExpr(),
                .iam_roles => |*v| v.clearFilterExpr(),
                .iam_policies => |*v| v.clearFilterExpr(),
                .iam_users => |*v| v.clearFilterExpr(),
                .iam_groups => |*v| v.clearFilterExpr(),
                .iam_identity_providers => |*v| v.clearFilterExpr(),
                .secretsmanager_secrets => |*v| v.clearFilterExpr(),
                else => {},
            }
            return;
        }
        var result = filter_mod.parse(self.allocator, rest) catch {
            self.command_bar.setError("invalid filter expression");
            return;
        };
        switch (self.currentView().*) {
            .s3_buckets => |*v| v.setFilterExpr(result),
            .s3_objects => |*v| v.setFilterExpr(result),
            .lambda_functions => |*v| v.setFilterExpr(result),
            .logs_log_groups => |*v| v.setFilterExpr(result),
            .iam_roles => |*v| v.setFilterExpr(result),
            .iam_policies => |*v| v.setFilterExpr(result),
            .iam_users => |*v| v.setFilterExpr(result),
            .iam_groups => |*v| v.setFilterExpr(result),
            .iam_identity_providers => |*v| v.setFilterExpr(result),
            .secretsmanager_secrets => |*v| v.setFilterExpr(result),
            else => result.deinit(),
        }
    }

    fn handleProfileCommand(self: *Self, t: []const u8) !void {
        const rest = std.mem.trim(u8, t["profile".len..], " ");
        var cmd = profile_cmd.parse(self.allocator, rest) catch {
            self.command_bar.setError("usage: :profile add|use|remove|show|logout|logout-all [name ...]");
            return;
        };
        defer cmd.deinit();

        switch (cmd.subcmd) {
            .show => {
                var pos: usize = 0;
                const ebuf = &self.command_bar.error_buf;
                for (self.profile_set.entries.items, 0..) |e, i| {
                    if (i > 0 and pos + 2 <= ebuf.len) {
                        ebuf[pos] = ',';
                        ebuf[pos + 1] = ' ';
                        pos += 2;
                    }
                    const name = e.displayName();
                    const n = @min(name.len, ebuf.len - pos);
                    @memcpy(ebuf[pos .. pos + n], name[0..n]);
                    pos += n;
                    if (pos >= ebuf.len) break;
                }
                self.command_bar.error_msg = ebuf[0..pos];
            },
            .use => {
                if (cmd.profiles.len == 0) {
                    self.command_bar.setError("usage: :profile use <profile> [...]");
                    return;
                }
                // Validate all profiles exist before replacing.
                for (cmd.profiles) |name| {
                    const info = sso.getProfileInfo(self.allocator, self.io, self.profile_set.env, name) catch {
                        self.command_bar.setError("could not read ~/.aws/config");
                        return;
                    };
                    if (!info.exists) {
                        self.command_bar.setErrorFmt("profile '{s}' not found", .{name});
                        return;
                    }
                }
                try self.profile_set.replaceWith(cmd.profiles);
                try self.activateProfiles(cmd.profiles);
                try self.refreshCurrentViewForProfileChange();
            },
            .add => {
                if (cmd.profiles.len == 0) {
                    self.command_bar.setError("usage: :profile add <profile> [...]");
                    return;
                }
                for (cmd.profiles) |name| {
                    const info = sso.getProfileInfo(self.allocator, self.io, self.profile_set.env, name) catch {
                        self.command_bar.setError("could not read ~/.aws/config");
                        return;
                    };
                    if (!info.exists) {
                        self.command_bar.setErrorFmt("profile '{s}' not found", .{name});
                        return;
                    }
                }
                for (cmd.profiles) |name| {
                    try self.profile_set.add(name);
                }
                try self.activateProfiles(cmd.profiles);
                try self.refreshCurrentViewForProfileChange();
            },
            .remove => {
                if (cmd.profiles.len == 0) {
                    self.command_bar.setError("usage: :profile remove <profile> [...]");
                    return;
                }
                const missing_names = collectMissing(cmd.profiles, &self.profile_set, .remove);
                if (self.profile_set.entries.items.len == 0) {
                    try self.profile_set.add("default");
                    try self.newView(.{ .auth_prompt = AuthPromptView.init(self.color_support) });
                }
                if (missing_names.len > 0) {
                    self.command_bar.setErrorFmt("not active: {s}", .{missing_names});
                }
                try self.refreshCurrentViewForProfileChange();
            },
            .logout => {
                if (cmd.profiles.len == 0) {
                    self.command_bar.setError("usage: :profile logout <profile> [...]");
                    return;
                }
                const missing_names = collectMissing(cmd.profiles, &self.profile_set, .logout);
                for (cmd.profiles) |name| {
                    sso.clearSsoCache(self.allocator, self.io, self.profile_set.env, name);
                }
                if (missing_names.len > 0) {
                    self.command_bar.setErrorFmt("not active: {s}", .{missing_names});
                }
                if (self.profile_set.primaryStore().credentials == null) {
                    try self.newView(.{ .auth_prompt = AuthPromptView.init(self.color_support) });
                }
                try self.refreshCurrentViewForProfileChange();
            },
            .logout_all => {
                self.profile_set.clearAllCredentials();
                for (self.profile_set.entries.items) |e| {
                    sso.clearSsoCache(self.allocator, self.io, self.profile_set.env, e.name);
                }
                try self.newView(.{ .auth_prompt = AuthPromptView.init(self.color_support) });
            },
        }
    }

    /// For each newly configured profile: push SSO login view if needed, else fetch account ID.
    fn activateProfiles(self: *Self, names: []const []const u8) !void {
        for (names) |name| {
            const idx = self.profile_set.indexOf(name) orelse continue;
            const entry = &self.profile_set.entries.items[idx];
            const info = sso.getProfileInfo(self.allocator, self.io, self.profile_set.env, name) catch continue;
            if (info.is_sso) {
                if (entry.store.getCredentials()) |_| {
                    self.fetchAccountId(idx);
                } else |_| {
                    const v = try SSOProfileView.initForProfile(
                        self.allocator,
                        self.io,
                        self.profile_set.env,
                        name,
                        self.color_support,
                    );
                    try self.newView(.{ .sso_profile = v });
                }
            } else {
                self.fetchAccountId(idx);
            }
        }
    }
};

const MissingOp = enum { remove, logout };

/// Apply remove/logout to each name in `profiles` against `ps`, return comma-separated
/// list of names that were not found, written into a static buffer. Slice is valid for
/// the duration of the call site (caller must use it before next call).
fn collectMissing(profiles: []const []const u8, ps: *ProfileSet, op: MissingOp) []const u8 {
    // Static buffer — caller must consume the returned slice before the next call.
    // Safe because collectMissing is only invoked from the single-threaded event loop.
    const S = struct {
        var buf: [128]u8 = undefined;
    };
    var pos: usize = 0;
    for (profiles) |name| {
        const found = switch (op) {
            .remove => ps.remove(name),
            .logout => ps.clearCredentials(name),
        };
        if (!found) {
            if (pos > 0 and pos + 2 <= S.buf.len) {
                S.buf[pos] = ',';
                S.buf[pos + 1] = ' ';
                pos += 2;
            }
            const n = @min(name.len, S.buf.len - pos);
            @memcpy(S.buf[pos .. pos + n], name[0..n]);
            pos += n;
        }
    }
    return S.buf[0..pos];
}

const CommandResult = enum { ok, not_allowed, unknown };

fn parseSortKeys(comptime K: type, comptime parseFn: fn ([]const u8) ?K, rest: []const u8, out: []K) usize {
    var n: usize = 0;
    var it = std.mem.splitScalar(u8, rest, ' ');
    while (it.next()) |tok| {
        if (tok.len == 0) continue;
        if (parseFn(tok)) |key| {
            if (n < out.len) {
                out[n] = key;
                n += 1;
            }
        }
    }
    return n;
}

fn parseSortCommand(view: *view_mod.View, text: []const u8) CommandResult {
    const t = std.mem.trim(u8, text, " ");
    const is_desc = std.mem.startsWith(u8, t, "sort-desc");
    const is_sort = is_desc or std.mem.startsWith(u8, t, "sort");
    if (!is_sort) return .unknown;

    const sortable = switch (view.*) {
        .s3_buckets, .s3_objects, .lambda_functions, .logs_log_groups, .iam_roles, .iam_policies, .iam_users, .iam_groups, .iam_identity_providers, .secretsmanager_secrets => true,
        else => false,
    };
    if (!sortable) return .not_allowed;

    const dir: constants.SortDir = if (is_desc) .desc else .asc;
    const cmd_len: usize = if (is_desc) "sort-desc".len else "sort".len;
    const rest = std.mem.trim(u8, t[cmd_len..], " ");

    switch (view.*) {
        .s3_buckets => |*v| {
            var keys: [4]BucketSortKey = undefined;
            const n = parseSortKeys(BucketSortKey, parseBucketSortKey, rest, &keys);
            if (n > 0) v.setSort(keys[0..n], dir);
        },
        .s3_objects => |*v| {
            var keys: [4]ObjectSortKey = undefined;
            const n = parseSortKeys(ObjectSortKey, parseObjectSortKey, rest, &keys);
            if (n > 0) v.setSort(keys[0..n], dir);
        },
        .lambda_functions => |*v| {
            var keys: [4]LambdaSortKey = undefined;
            const n = parseSortKeys(LambdaSortKey, parseLambdaSortKey, rest, &keys);
            if (n > 0) v.setSort(keys[0..n], dir);
        },
        .logs_log_groups => |*v| {
            var keys: [4]LogGroupsSortKey = undefined;
            const n = parseSortKeys(LogGroupsSortKey, parseLogGroupsSortKey, rest, &keys);
            if (n > 0) v.setSort(keys[0..n], dir);
        },
        .iam_roles => |*v| {
            var keys: [4]RoleSortKey = undefined;
            const n = parseSortKeys(RoleSortKey, parseRoleSortKey, rest, &keys);
            if (n > 0) v.setSort(keys[0..n], dir);
        },
        .iam_policies => |*v| {
            var keys: [4]PolicySortKey = undefined;
            const n = parseSortKeys(PolicySortKey, parsePolicySortKey, rest, &keys);
            if (n > 0) v.setSort(keys[0..n], dir);
        },
        .iam_users => |*v| {
            var keys: [4]UserSortKey = undefined;
            const n = parseSortKeys(UserSortKey, parseUserSortKey, rest, &keys);
            if (n > 0) v.setSort(keys[0..n], dir);
        },
        .iam_groups => |*v| {
            var keys: [4]GroupSortKey = undefined;
            const n = parseSortKeys(GroupSortKey, parseGroupSortKey, rest, &keys);
            if (n > 0) v.setSort(keys[0..n], dir);
        },
        .iam_identity_providers => |*v| {
            var keys: [4]ProviderSortKey = undefined;
            const n = parseSortKeys(ProviderSortKey, parseProviderSortKey, rest, &keys);
            if (n > 0) v.setSort(keys[0..n], dir);
        },
        .secretsmanager_secrets => |*v| {
            var keys: [4]SecretSortKey = undefined;
            const n = parseSortKeys(SecretSortKey, parseSecretSortKey, rest, &keys);
            if (n > 0) v.setSort(keys[0..n], dir);
        },
        else => {},
    }
    return .ok;
}

fn parseSecretSortKey(tok: []const u8) ?SecretSortKey {
    if (std.mem.eql(u8, tok, "name")) return .name;
    if (std.mem.eql(u8, tok, "account") or std.mem.eql(u8, tok, "account_id")) return .account;
    if (std.mem.eql(u8, tok, "region")) return .region;
    if (std.mem.eql(u8, tok, "created") or std.mem.eql(u8, tok, "created_date")) return .created;
    if (std.mem.eql(u8, tok, "accessed") or std.mem.eql(u8, tok, "last_accessed")) return .last_accessed;
    return null;
}

fn parseLogGroupsSortKey(tok: []const u8) ?LogGroupsSortKey {
    if (std.mem.eql(u8, tok, "name")) return .name;
    if (std.mem.eql(u8, tok, "region")) return .region;
    if (std.mem.eql(u8, tok, "retention")) return .retention;
    if (std.mem.eql(u8, tok, "stored") or std.mem.eql(u8, tok, "size")) return .stored;
    if (std.mem.eql(u8, tok, "class")) return .class;
    return null;
}

fn parseBucketSortKey(tok: []const u8) ?BucketSortKey {
    if (std.mem.eql(u8, tok, "name")) return .name;
    if (std.mem.eql(u8, tok, "region")) return .region;
    if (std.mem.eql(u8, tok, "created") or std.mem.eql(u8, tok, "creation_date")) return .creation_date;
    if (std.mem.eql(u8, tok, "size")) return .size;
    if (std.mem.eql(u8, tok, "account") or std.mem.eql(u8, tok, "account_id")) return .account;
    return null;
}

fn parseObjectSortKey(tok: []const u8) ?ObjectSortKey {
    if (std.mem.eql(u8, tok, "key") or std.mem.eql(u8, tok, "name")) return .key;
    if (std.mem.eql(u8, tok, "size")) return .size;
    if (std.mem.eql(u8, tok, "modified") or std.mem.eql(u8, tok, "last_modified")) return .last_modified;
    if (std.mem.eql(u8, tok, "class") or std.mem.eql(u8, tok, "storage_class")) return .storage_class;
    return null;
}

fn parseLambdaSortKey(tok: []const u8) ?LambdaSortKey {
    if (std.mem.eql(u8, tok, "name")) return .name;
    if (std.mem.eql(u8, tok, "runtime")) return .runtime;
    if (std.mem.eql(u8, tok, "region")) return .region;
    if (std.mem.eql(u8, tok, "modified") or std.mem.eql(u8, tok, "last_modified")) return .last_modified;
    if (std.mem.eql(u8, tok, "arch") or std.mem.eql(u8, tok, "architecture")) return .architecture;
    if (std.mem.eql(u8, tok, "package") or std.mem.eql(u8, tok, "package_type")) return .package_type;
    if (std.mem.eql(u8, tok, "account") or std.mem.eql(u8, tok, "account_id")) return .account_id;
    return null;
}

fn parseRoleSortKey(tok: []const u8) ?RoleSortKey {
    if (std.mem.eql(u8, tok, "name")) return .name;
    if (std.mem.eql(u8, tok, "account") or std.mem.eql(u8, tok, "account_id")) return .account;
    if (std.mem.eql(u8, tok, "created") or std.mem.eql(u8, tok, "create_date")) return .created;
    if (std.mem.eql(u8, tok, "activity") or std.mem.eql(u8, tok, "last_used")) return .activity;
    return null;
}

fn parseUserSortKey(tok: []const u8) ?UserSortKey {
    if (std.mem.eql(u8, tok, "name")) return .name;
    if (std.mem.eql(u8, tok, "account") or std.mem.eql(u8, tok, "account_id")) return .account;
    if (std.mem.eql(u8, tok, "created") or std.mem.eql(u8, tok, "create_date")) return .created;
    if (std.mem.eql(u8, tok, "activity") or std.mem.eql(u8, tok, "password_last_used")) return .activity;
    return null;
}

fn parseGroupSortKey(tok: []const u8) ?GroupSortKey {
    if (std.mem.eql(u8, tok, "name")) return .name;
    if (std.mem.eql(u8, tok, "account") or std.mem.eql(u8, tok, "account_id")) return .account;
    if (std.mem.eql(u8, tok, "path")) return .path;
    if (std.mem.eql(u8, tok, "created") or std.mem.eql(u8, tok, "create_date")) return .created;
    return null;
}

fn parseProviderSortKey(tok: []const u8) ?ProviderSortKey {
    if (std.mem.eql(u8, tok, "name")) return .name;
    if (std.mem.eql(u8, tok, "type")) return .type;
    if (std.mem.eql(u8, tok, "account") or std.mem.eql(u8, tok, "account_id")) return .account;
    if (std.mem.eql(u8, tok, "created") or std.mem.eql(u8, tok, "create_date")) return .created;
    return null;
}

fn parsePolicySortKey(tok: []const u8) ?PolicySortKey {
    if (std.mem.eql(u8, tok, "name")) return .name;
    if (std.mem.eql(u8, tok, "account") or std.mem.eql(u8, tok, "account_id")) return .account;
    if (std.mem.eql(u8, tok, "description")) return .description;
    if (std.mem.eql(u8, tok, "type")) return .type_;
    if (std.mem.eql(u8, tok, "used_as")) return .used_as;
    return null;
}
