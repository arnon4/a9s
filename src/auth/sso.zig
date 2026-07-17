const std = @import("std");
const builtin = @import("builtin");
const IniFile = @import("../sdk/utils/ini.zig").IniFile;
const time_utils = @import("../sdk/utils/time.zig");
const input = @import("../terminal/input.zig");

// ── Public types ─────────────────────────────────────────────────────────────

pub const SsoProfile = struct {
    name: []u8,

    pub fn deinit(self: SsoProfile, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
    }
};

pub const PollCtx = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    arena: std.heap.ArenaAllocator,
    // filled by beginLogin (arena-owned):
    client_id: []const u8 = "",
    client_secret: []const u8 = "",
    device_code: []const u8 = "",
    token_url: []const u8 = "",
    cache_dir_path: []const u8 = "",
    cache_file_path: []const u8 = "",
    poll_interval_s: u32 = 5,
    // outputs:
    done: std.atomic.Value(bool),
    err: ?anyerror = null,
    // cancellation:
    cancelled: std.atomic.Value(bool) = .init(false),
    sleep_futex: std.atomic.Value(u32) align(@alignOf(u32)) = .init(0),

    pub fn deinit(self: *PollCtx) void {
        self.arena.deinit();
    }

    pub fn cancel(self: *PollCtx) void {
        self.cancelled.store(true, .release);
        std.Io.futexWake(self.io, u32, &self.sleep_futex.raw, 1);
    }
};

// ── Public functions ──────────────────────────────────────────────────────────

/// Returns all profile names from ~/.aws/config that have SSO configuration.
/// Caller owns the returned slice and each element.
pub fn readProfiles(allocator: std.mem.Allocator, io: std.Io, env: std.process.Environ) ![]SsoProfile {
    const home_var = comptime if (builtin.os.tag == .windows) "USERPROFILE" else "HOME";
    const home = env.getAlloc(allocator, home_var) catch |e| switch (e) {
        error.EnvironmentVariableMissing => return try allocator.alloc(SsoProfile, 0),
        else => return e,
    };
    defer allocator.free(home);

    const config_path = try std.fmt.allocPrint(allocator, "{s}/.aws/config", .{home});
    defer allocator.free(config_path);

    var config = IniFile.parseFile(allocator, io, config_path) catch |e| switch (e) {
        error.FileNotFound => return try allocator.alloc(SsoProfile, 0),
        else => return e,
    };
    defer config.deinit();

    var list: std.ArrayList(SsoProfile) = .empty;
    errdefer {
        for (list.items) |p| p.deinit(allocator);
        list.deinit(allocator);
    }

    var it = config.sections.iterator();
    while (it.next()) |entry| {
        const section_name = entry.key_ptr.*;

        const display: []const u8 = if (std.mem.eql(u8, section_name, "default"))
            "default"
        else if (std.mem.startsWith(u8, section_name, "profile "))
            section_name["profile ".len..]
        else
            continue;

        const has_sso = config.get(section_name, "sso_session") != null or
            config.get(section_name, "sso_start_url") != null;
        if (!has_sso) continue;

        try list.append(allocator, .{ .name = try allocator.dupe(u8, display) });
    }

    return list.toOwnedSlice(allocator);
}

/// Performs RegisterClient + StartDeviceAuthorization, opens the browser, and
/// populates ctx with everything needed for pollToken.
/// Returns the verification URL (owned by ctx.arena — valid until ctx.deinit).
pub fn beginLogin(
    allocator: std.mem.Allocator,
    io: std.Io,
    env: std.process.Environ,
    profile: []const u8,
    ctx: *PollCtx,
) ![]const u8 {
    const a = ctx.arena.allocator();

    const home_var = comptime if (builtin.os.tag == .windows) "USERPROFILE" else "HOME";
    const home = try env.getAlloc(allocator, home_var);
    defer allocator.free(home);

    const config_path = try std.fmt.allocPrint(allocator, "{s}/.aws/config", .{home});
    defer allocator.free(config_path);

    var config = try IniFile.parseFile(allocator, io, config_path);
    defer config.deinit();

    const section = if (std.mem.eql(u8, profile, "default"))
        try allocator.dupe(u8, "default")
    else
        try std.fmt.allocPrint(allocator, "profile {s}", .{profile});
    defer allocator.free(section);

    const SsoParams = struct { start_url: []const u8, region: []const u8, cache_key: []const u8 };
    const sso: SsoParams = sso: {
        if (config.get(section, "sso_session")) |session_name| {
            const ss = try std.fmt.allocPrint(allocator, "sso-session {s}", .{session_name});
            defer allocator.free(ss);
            break :sso .{
                .start_url = config.get(ss, "sso_start_url") orelse return error.SsoSessionMissingStartUrl,
                .region = config.get(ss, "sso_region") orelse config.get(section, "region") orelse "us-east-1",
                .cache_key = session_name,
            };
        }
        const su = config.get(section, "sso_start_url") orelse return error.SsoConfigMissingStartUrl;
        break :sso .{
            .start_url = su,
            .region = config.get(section, "sso_region") orelse config.get(section, "region") orelse "us-east-1",
            .cache_key = su,
        };
    };

    // Dupe SSO strings into arena (config will be freed)
    const start_url = try a.dupe(u8, sso.start_url);
    const sso_region = try a.dupe(u8, sso.region);
    const cache_key = try a.dupe(u8, sso.cache_key);

    var http_client = std.http.Client{ .allocator = allocator, .io = io };
    defer http_client.deinit();

    // RegisterClient
    const register_url = try std.fmt.allocPrint(allocator, "https://oidc.{s}.amazonaws.com/client/register", .{sso_region});
    defer allocator.free(register_url);

    var reg_resp: std.Io.Writer.Allocating = .init(allocator);
    defer reg_resp.deinit();

    const reg_res = try http_client.fetch(.{
        .method = .POST,
        .location = .{ .url = register_url },
        .extra_headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
        .payload = "{\"clientName\":\"at\",\"clientType\":\"public\"}",
        .response_writer = &reg_resp.writer,
    });
    if (reg_res.status != .created and reg_res.status != .ok) return error.OidcRegisterFailed;

    const RegisterResp = struct { clientId: []const u8, clientSecret: []const u8 };
    const reg_parsed = try std.json.parseFromSlice(RegisterResp, allocator, reg_resp.writer.buffer[0..reg_resp.writer.end], .{ .ignore_unknown_fields = true });
    defer reg_parsed.deinit();
    const client_id = try a.dupe(u8, reg_parsed.value.clientId);
    const client_secret = try a.dupe(u8, reg_parsed.value.clientSecret);

    // StartDeviceAuthorization
    const device_auth_url = try std.fmt.allocPrint(allocator, "https://oidc.{s}.amazonaws.com/device_authorization", .{sso_region});
    defer allocator.free(device_auth_url);

    const device_req = try std.fmt.allocPrint(allocator, "{{\"clientId\":\"{s}\",\"clientSecret\":\"{s}\",\"startUrl\":\"{s}\"}}", .{ client_id, client_secret, start_url });
    defer allocator.free(device_req);

    var device_resp: std.Io.Writer.Allocating = .init(allocator);
    defer device_resp.deinit();

    const device_res = try http_client.fetch(.{
        .method = .POST,
        .location = .{ .url = device_auth_url },
        .extra_headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
        .payload = device_req,
        .response_writer = &device_resp.writer,
    });
    if (device_res.status != .ok) return error.OidcDeviceAuthFailed;

    const DeviceAuthResp = struct {
        deviceCode: []const u8,
        verificationUriComplete: []const u8,
        expiresIn: u32,
        interval: u32,
    };
    const device_parsed = try std.json.parseFromSlice(DeviceAuthResp, allocator, device_resp.writer.buffer[0..device_resp.writer.end], .{ .ignore_unknown_fields = true });
    defer device_parsed.deinit();

    const device_code = try a.dupe(u8, device_parsed.value.deviceCode);
    const verification_url = try a.dupe(u8, device_parsed.value.verificationUriComplete);

    // Compute cache path
    var digest: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
    std.crypto.hash.Sha1.hash(cache_key, &digest, .{});
    const hex = std.fmt.bytesToHex(&digest, .lower);
    const cache_dir_path = try std.fmt.allocPrint(a, "{s}/.aws/sso/cache", .{home});
    const cache_file_path = try std.fmt.allocPrint(a, "{s}/{s}.json", .{ cache_dir_path, hex });
    const token_url = try std.fmt.allocPrint(a, "https://oidc.{s}.amazonaws.com/token", .{sso_region});

    ctx.client_id = client_id;
    ctx.client_secret = client_secret;
    ctx.device_code = device_code;
    ctx.token_url = token_url;
    ctx.cache_dir_path = cache_dir_path;
    ctx.cache_file_path = cache_file_path;
    ctx.poll_interval_s = if (device_parsed.value.interval > 0) device_parsed.value.interval else 5;

    openBrowser(allocator, io, verification_url) catch {};

    return verification_url;
}

/// Background thread: polls CreateToken until success or error, then writes cache.
pub fn pollToken(ctx: *PollCtx) void {
    defer {
        ctx.done.store(true, .release);
        input.notify();
    }

    const allocator = ctx.allocator;
    var poll_interval_s = ctx.poll_interval_s;

    std.Io.Dir.cwd().createDirPath(ctx.io, ctx.cache_dir_path) catch |e| {
        ctx.err = e;
        return;
    };

    var http_client = std.http.Client{ .allocator = allocator, .io = ctx.io };
    defer http_client.deinit();

    while (true) {
        ctx.sleep_futex.store(0, .monotonic);
        std.Io.futexWaitTimeout(ctx.io, u32, &ctx.sleep_futex.raw, 0, .{
            .duration = .{ .raw = .{ .nanoseconds = @as(u64, poll_interval_s) * std.time.ns_per_s }, .clock = .real },
        }) catch {};
        if (ctx.cancelled.load(.acquire)) {
            ctx.err = error.Cancelled;
            return;
        }

        const token_req = std.fmt.allocPrint(
            allocator,
            "{{\"clientId\":\"{s}\",\"clientSecret\":\"{s}\",\"grantType\":\"urn:ietf:params:oauth:grant-type:device_code\",\"deviceCode\":\"{s}\"}}",
            .{ ctx.client_id, ctx.client_secret, ctx.device_code },
        ) catch |e| {
            ctx.err = e;
            return;
        };
        defer allocator.free(token_req);

        var tok_resp: std.Io.Writer.Allocating = .init(allocator);
        defer tok_resp.deinit();

        const tok_res = http_client.fetch(.{
            .method = .POST,
            .location = .{ .url = ctx.token_url },
            .extra_headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
            .payload = token_req,
            .response_writer = &tok_resp.writer,
        }) catch |e| {
            ctx.err = e;
            return;
        };

        const resp_bytes = tok_resp.writer.buffer[0..tok_resp.writer.end];

        if (tok_res.status == .ok) {
            const TokenResp = struct { accessToken: []const u8, expiresIn: u32 };
            const tp = std.json.parseFromSlice(TokenResp, allocator, resp_bytes, .{ .ignore_unknown_fields = true }) catch |e| {
                ctx.err = e;
                return;
            };
            defer tp.deinit();

            const ts = std.Io.Timestamp.now(ctx.io, .real);
            const now_s: i64 = @intCast(@divFloor(ts.nanoseconds, std.time.ns_per_s));
            const expires_at_s = now_s + @as(i64, tp.value.expiresIn);

            const expires_at_str = formatIso8601Dashed(allocator, expires_at_s) catch |e| {
                ctx.err = e;
                return;
            };
            defer allocator.free(expires_at_str);

            const json_out = std.fmt.allocPrint(
                allocator,
                "{{\"accessToken\":\"{s}\",\"expiresAt\":\"{s}\"}}",
                .{ tp.value.accessToken, expires_at_str },
            ) catch |e| {
                ctx.err = e;
                return;
            };
            defer allocator.free(json_out);

            const cache_file = std.Io.Dir.cwd().createFile(ctx.io, ctx.cache_file_path, .{ .truncate = true }) catch |e| {
                ctx.err = e;
                return;
            };
            defer cache_file.close(ctx.io);
            var write_buf: [4096]u8 = undefined;
            var fw = cache_file.writer(ctx.io, &write_buf);
            fw.interface.writeAll(json_out) catch |e| {
                ctx.err = e;
                return;
            };
            fw.flush() catch |e| {
                ctx.err = e;
                return;
            };
            return; // success
        }

        const ErrResp = struct { @"error": []const u8 };
        const ep = std.json.parseFromSlice(ErrResp, allocator, resp_bytes, .{ .ignore_unknown_fields = true }) catch continue;
        defer ep.deinit();

        const err_code = ep.value.@"error";
        if (std.mem.eql(u8, err_code, "authorization_pending")) {
            continue;
        } else if (std.mem.eql(u8, err_code, "slow_down")) {
            poll_interval_s += 5;
            continue;
        } else if (std.mem.eql(u8, err_code, "expired_token")) {
            ctx.err = error.SsoDeviceAuthExpired;
            return;
        } else {
            ctx.err = error.OidcTokenFailed;
            return;
        }
    }
}

pub const ProfileInfo = struct {
    exists: bool,
    is_sso: bool,
};

/// Returns whether a named profile exists in ~/.aws/config or ~/.aws/credentials,
/// and whether it has SSO configuration (config only).
pub fn getProfileInfo(allocator: std.mem.Allocator, io: std.Io, env: std.process.Environ, profile: []const u8) !ProfileInfo {
    const home_var = comptime if (builtin.os.tag == .windows) "USERPROFILE" else "HOME";
    const home = env.getAlloc(allocator, home_var) catch |e| switch (e) {
        error.EnvironmentVariableMissing => return .{ .exists = false, .is_sso = false },
        else => return e,
    };
    defer allocator.free(home);

    const config_path = try std.fmt.allocPrint(allocator, "{s}/.aws/config", .{home});
    defer allocator.free(config_path);

    const config_section = if (std.mem.eql(u8, profile, "default"))
        try allocator.dupe(u8, "default")
    else
        try std.fmt.allocPrint(allocator, "profile {s}", .{profile});
    defer allocator.free(config_section);

    config: {
        var config = IniFile.parseFile(allocator, io, config_path) catch |e| switch (e) {
            error.FileNotFound => break :config,
            else => return e,
        };
        defer config.deinit();

        if (config.hasSection(config_section)) {
            const is_sso = config.get(config_section, "sso_session") != null or
                config.get(config_section, "sso_start_url") != null;
            return .{ .exists = true, .is_sso = is_sso };
        }
    }

    // Fall back to credentials file (uses plain [name] sections, never SSO).
    const creds_path = if (env.getAlloc(allocator, "AWS_SHARED_CREDENTIALS_FILE")) |p|
        p
    else |_|
        try std.fmt.allocPrint(allocator, "{s}/.aws/credentials", .{home});
    defer allocator.free(creds_path);

    var creds = IniFile.parseFile(allocator, io, creds_path) catch |e| switch (e) {
        error.FileNotFound => return .{ .exists = false, .is_sso = false },
        else => return e,
    };
    defer creds.deinit();

    return .{ .exists = creds.hasSection(profile), .is_sso = false };
}

/// Deletes the SSO token cache file for the given profile, if it exists.
/// No-op if the profile has no SSO config or the cache file is absent.
pub fn clearSsoCache(allocator: std.mem.Allocator, io: std.Io, env: std.process.Environ, profile: []const u8) void {
    clearSsoCacheInner(allocator, io, env, profile) catch {};
}

fn clearSsoCacheInner(allocator: std.mem.Allocator, io: std.Io, env: std.process.Environ, profile: []const u8) !void {
    const home_var = comptime if (builtin.os.tag == .windows) "USERPROFILE" else "HOME";
    const home = try env.getAlloc(allocator, home_var);
    defer allocator.free(home);

    const config_path = try std.fmt.allocPrint(allocator, "{s}/.aws/config", .{home});
    defer allocator.free(config_path);

    var config = IniFile.parseFile(allocator, io, config_path) catch return;
    defer config.deinit();

    const section = if (std.mem.eql(u8, profile, "default"))
        try allocator.dupe(u8, "default")
    else
        try std.fmt.allocPrint(allocator, "profile {s}", .{profile});
    defer allocator.free(section);

    const cache_key: []const u8 = blk: {
        if (config.get(section, "sso_session")) |session_name| break :blk session_name;
        if (config.get(section, "sso_start_url")) |start_url| break :blk start_url;
        return; // not an SSO profile
    };

    var digest: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
    std.crypto.hash.Sha1.hash(cache_key, &digest, .{});
    const hex = std.fmt.bytesToHex(&digest, .lower);

    const cache_file_path = try std.fmt.allocPrint(allocator, "{s}/.aws/sso/cache/{s}.json", .{ home, hex });
    defer allocator.free(cache_file_path);

    std.Io.Dir.cwd().deleteFile(io, cache_file_path) catch {};
}

/// Blocking CLI login: reads config, runs the full OIDC device flow, writes cache.
pub fn login(
    allocator: std.mem.Allocator,
    io: std.Io,
    env: std.process.Environ,
    profile: []const u8,
    writer: *std.Io.Writer,
) !void {
    const ctx = try allocator.create(PollCtx);
    defer allocator.destroy(ctx);
    ctx.* = .{
        .allocator = allocator,
        .io = io,
        .arena = std.heap.ArenaAllocator.init(allocator),
        .done = std.atomic.Value(bool).init(false),
    };
    defer ctx.arena.deinit();

    const url = try beginLogin(allocator, io, env, profile, ctx);

    const msg = try std.fmt.allocPrint(allocator, "Opening browser: {s}\n", .{url});
    defer allocator.free(msg);
    try writer.writeAll(msg);
    try writer.writeAll("Waiting for authorization...\n");

    pollToken(ctx);

    if (ctx.err) |e| return e;
    try writer.writeAll("Login successful.\n");
}

// ── Private helpers ───────────────────────────────────────────────────────────

pub fn openBrowser(allocator: std.mem.Allocator, io: std.Io, url: []const u8) !void {
    var argv_buf: [5][]const u8 = undefined;
    const argv: []const []const u8 = if (builtin.os.tag == .windows) blk: {
        argv_buf[0] = "cmd";
        argv_buf[1] = "/c";
        argv_buf[2] = "start";
        argv_buf[3] = "";
        argv_buf[4] = url;
        break :blk argv_buf[0..5];
    } else if (builtin.os.tag == .macos) blk: {
        argv_buf[0] = "open";
        argv_buf[1] = url;
        break :blk argv_buf[0..2];
    } else blk: {
        argv_buf[0] = "xdg-open";
        argv_buf[1] = url;
        break :blk argv_buf[0..2];
    };
    const result = try std.process.run(allocator, io, .{ .argv = argv });
    allocator.free(result.stdout);
    allocator.free(result.stderr);
}

fn formatIso8601Dashed(allocator: std.mem.Allocator, timestamp: i64) ![]u8 {
    const compact = try time_utils.secondsToDate(allocator, timestamp);
    defer allocator.free(compact);
    if (compact.len < 16) return error.InvalidTimestamp;
    return std.fmt.allocPrint(allocator, "{s}-{s}-{s}T{s}:{s}:{s}Z", .{
        compact[0..4],
        compact[4..6],
        compact[6..8],
        compact[9..11],
        compact[11..13],
        compact[13..15],
    });
}
