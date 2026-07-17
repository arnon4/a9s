const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;

const IniFile = @import("../utils/ini.zig").IniFile;
const time = @import("../utils/time.zig");
const hasPassed = time.hasPassed;
const parseIso8601ToTimestamp = time.parseIso8601ToTimestamp;
const uri = @import("../utils/uri.zig");
const sts = @import("../clients/sts/client.zig");

pub const Credentials = struct {
    access_key_id: []const u8,
    secret_access_key: []const u8,
    session_token: ?[]const u8,
    /// which step in the chain provided the credentials
    source: []const u8,
    /// POSIX timestamp; null for long-term credentials
    expiration: ?i64 = null,

    /// Free credentials memory when done
    pub fn deinit(self: Credentials, allocator: Allocator) void {
        allocator.free(self.access_key_id);
        allocator.free(self.secret_access_key);
        if (self.session_token) |token| allocator.free(token);
        allocator.free(self.source);
    }
};

pub const CredentialsStoreOptions = struct {
    /// Explicit profile name. Overrides AWS_PROFILE / AWS_DEFAULT_PROFILE env vars.
    profile_name: ?[]const u8 = null,
    /// Override path to ~/.aws/credentials (else uses AWS_SHARED_CREDENTIALS_FILE or ~/.aws/credentials).
    credentials_file: ?[]const u8 = null,
    /// Override path to ~/.aws/config (else uses AWS_CONFIG_FILE or ~/.aws/config).
    config_file: ?[]const u8 = null,
};

pub const CredentialsStore = struct {
    credentials: ?Credentials = null,
    allocator: Allocator,
    io: std.Io,
    env: std.process.Environ,
    options: CredentialsStoreOptions,

    const Self = @This();

    pub fn init(allocator: Allocator, io: std.Io, env: std.process.Environ, options: CredentialsStoreOptions) CredentialsStore {
        return .{
            .allocator = allocator,
            .io = io,
            .env = env,
            .options = options,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.credentials) |c| c.deinit(self.allocator);
    }

    pub fn getCredentials(self: *Self) !Credentials {
        const needs_refresh = if (self.credentials) |c|
            c.expiration != null and hasPassed(self.io, c.expiration.?)
        else
            true;

        if (needs_refresh) {
            if (self.credentials) |c| c.deinit(self.allocator);
            self.credentials = try fetchCredentials(self.allocator, self.io, self.env, self.options);
        }

        return self.credentials.?;
    }
};

/// Used to fetch credentials using standard provider chain order.
/// Errors if credentials aren't found.
fn fetchCredentials(allocator: Allocator, io: std.Io, env: std.process.Environ, options: CredentialsStoreOptions) !Credentials {
    const fetchers = .{
        fetchFromEnv,
        fetchFromAssumeRoleOrder,
        fetchFromAssumeRoleWebIdentity,
        fetchFromIAMIdentityCenter,
        fetchFromSharedCredentialsFile,
        fetchFromConsoleCredentials,
        fetchFromConfigFile,
        fetchInsideContainer,
        fetchFromIMDS,
    };

    inline for (fetchers, 0..) |fetcher, i| {
        std.log.debug("fetchCredentials: trying fetcher {d} ({s})", .{ i, @typeName(@TypeOf(fetcher)) });
        if (try fetcher(allocator, io, env, options)) |creds| {
            std.log.debug("fetchCredentials: fetcher {d} succeeded", .{i});
            return creds;
        }
        std.log.debug("fetchCredentials: fetcher {d} returned null", .{i});
    }

    return error.CredentialsNotFound;
}

fn fetchFromEnv(allocator: Allocator, io: std.Io, env: std.process.Environ, options: CredentialsStoreOptions) !?Credentials {
    _ = io;
    _ = options;
    return fetchFromEnvInner(allocator, env) catch |e| switch (e) {
        error.EnvironmentVariableMissing => null,
        else => e,
    };
}

fn fetchFromEnvInner(allocator: Allocator, env: std.process.Environ) !Credentials {
    const access_key_id = try env.getAlloc(allocator, "AWS_ACCESS_KEY_ID");
    errdefer allocator.free(access_key_id);

    const secret_access_key = try env.getAlloc(allocator, "AWS_SECRET_ACCESS_KEY");
    errdefer allocator.free(secret_access_key);

    const session_token: ?[]const u8 = env.getAlloc(allocator, "AWS_SESSION_TOKEN") catch |e| switch (e) {
        error.EnvironmentVariableMissing => null,
        else => return e,
    };

    return .{
        .access_key_id = access_key_id,
        .secret_access_key = secret_access_key,
        .session_token = session_token,
        .source = try allocator.dupe(u8, "Environment"),
    };
}

fn fetchFromAssumeRoleOrder(allocator: Allocator, io: std.Io, env: std.process.Environ, options: CredentialsStoreOptions) !?Credentials {
    const config_path = try awsConfigFilePath(allocator, env, options.config_file);
    defer allocator.free(config_path);

    var config = IniFile.parseFile(allocator, io, config_path) catch |e| switch (e) {
        error.FileNotFound => return null,
        else => return e,
    };
    defer config.deinit();

    // Credentials file is optional; used to resolve source_profile static creds.
    const creds_path = try awsCredentialsFilePath(allocator, env, options.credentials_file);
    defer allocator.free(creds_path);

    var creds_file: ?IniFile = IniFile.parseFile(allocator, io, creds_path) catch |e| switch (e) {
        error.FileNotFound => null,
        else => return e,
    };
    defer if (creds_file) |*f| f.deinit();

    const profile_name = try resolveProfileName(allocator, env, options.profile_name);
    defer allocator.free(profile_name);

    const region = try resolveRegion(allocator, env, &config, profile_name);
    defer allocator.free(region);

    var visited = std.StringHashMap(void).init(allocator);
    defer visited.deinit();

    return resolveProfileChain(
        allocator,
        io,
        env,
        &config,
        if (creds_file) |*f| f else null,
        profile_name,
        region,
        &visited,
    );
}

/// Resolve credentials for a profile that has role_arn, recursing through
/// source_profile chains. Returns null if the profile has no role_arn.
/// Returns error.AssumeRoleChainCycle if a profile is visited twice.
fn resolveProfileChain(
    allocator: Allocator,
    io: std.Io,
    env: std.process.Environ,
    config: *const IniFile,
    creds_file: ?*const IniFile,
    profile_name: []const u8,
    region: []const u8,
    visited: *std.StringHashMap(void),
) anyerror!?Credentials {
    if (visited.contains(profile_name)) return error.AssumeRoleChainCycle;
    try visited.put(profile_name, {});

    const section = try configSectionName(allocator, profile_name);
    defer allocator.free(section);

    const role_arn = config.get(section, "role_arn") orelse return null;

    const source_creds = try resolveSourceCreds(
        allocator,
        io,
        env,
        config,
        creds_file,
        section,
        region,
        visited,
    ) orelse return error.NoSourceCredentialsForAssumeRole;
    defer source_creds.deinit(allocator);

    const session_name = env.getAlloc(allocator, "AWS_ROLE_SESSION_NAME") catch |e| switch (e) {
        error.EnvironmentVariableMissing => try allocator.dupe(u8, "aws-sdk-zig"),
        else => return e,
    };
    defer allocator.free(session_name);

    const duration_seconds: ?u32 = if (config.get(section, "duration_seconds")) |ds|
        std.fmt.parseInt(u32, ds, 10) catch null
    else
        null;

    var sts_client = try sts.Client.init(allocator, .{ .region = region, .io = io, .source_creds = source_creds });
    defer sts_client.deinit();
    var result = try sts_client.assumeRole(.{
        .role_arn = role_arn,
        .role_session_name = session_name,
        .external_id = config.get(section, "external_id"),
        .duration_seconds = duration_seconds,
    });
    errdefer result.deinit(allocator);

    result.source = try allocator.dupe(u8, role_arn);

    return result;
}

/// Obtain source credentials for an AssumeRole call.
fn resolveSourceCreds(
    allocator: Allocator,
    io: std.Io,
    env: std.process.Environ,
    config: *const IniFile,
    creds_file: ?*const IniFile,
    section: []const u8,
    region: []const u8,
    visited: *std.StringHashMap(void),
) !?Credentials {
    if (config.get(section, "source_profile")) |source_profile| {
        if (creds_file) |cf| {
            if (try credentialsFromSection(allocator, cf, source_profile)) |c| return c;
        }
        const source_section = try configSectionName(allocator, source_profile);
        defer allocator.free(source_section);
        if (try credentialsFromSection(allocator, config, source_section)) |c| return c;
        return resolveProfileChain(allocator, io, env, config, creds_file, source_profile, region, visited);
    }

    if (config.get(section, "credential_source")) |cs| {
        if (std.mem.eql(u8, cs, "Environment")) return fetchFromEnv(allocator, io, env, .{});
        return error.UnsupportedCredentialSource;
    }

    return null;
}

/// Extract static AWS credentials from a named INI section, or null if absent.
fn credentialsFromSection(allocator: Allocator, ini: *const IniFile, section: []const u8) !?Credentials {
    const access_key = ini.get(section, "aws_access_key_id") orelse return null;
    const secret_key = ini.get(section, "aws_secret_access_key") orelse return null;

    const access_key_copy = try allocator.dupe(u8, access_key);
    errdefer allocator.free(access_key_copy);
    const secret_key_copy = try allocator.dupe(u8, secret_key);
    errdefer allocator.free(secret_key_copy);

    const session_token: ?[]const u8 = if (ini.get(section, "aws_session_token")) |t|
        try allocator.dupe(u8, t)
    else
        null;
    errdefer if (session_token) |t| allocator.free(t);

    const source = try allocator.dupe(u8, section);
    errdefer allocator.free(source);

    return .{
        .access_key_id = access_key_copy,
        .secret_access_key = secret_key_copy,
        .session_token = session_token,
        .source = source,
    };
}

/// Config file uses "default" as-is; all other profiles are "profile <name>".
fn configSectionName(allocator: Allocator, profile_name: []const u8) ![]u8 {
    if (std.mem.eql(u8, profile_name, "default")) return allocator.dupe(u8, "default");
    return std.fmt.allocPrint(allocator, "profile {s}", .{profile_name});
}

/// Region priority: AWS_DEFAULT_REGION → AWS_REGION → config file → "us-east-1".
fn resolveRegion(allocator: Allocator, env: std.process.Environ, config: *const IniFile, profile_name: []const u8) ![]u8 {
    if (env.getAlloc(allocator, "AWS_DEFAULT_REGION")) |r| return r else |_| {}
    if (env.getAlloc(allocator, "AWS_REGION")) |r| return r else |_| {}

    const section = try configSectionName(allocator, profile_name);
    defer allocator.free(section);
    if (config.get(section, "region")) |r| return allocator.dupe(u8, r);

    return allocator.dupe(u8, "us-east-1");
}

/// Resolve the active profile name.
/// Priority: explicit override → AWS_PROFILE → AWS_DEFAULT_PROFILE → "default".
fn resolveProfileName(allocator: Allocator, env: std.process.Environ, override: ?[]const u8) ![]u8 {
    if (override) |name| return allocator.dupe(u8, name);
    return env.getAlloc(allocator, "AWS_PROFILE") catch |e| switch (e) {
        error.EnvironmentVariableMissing => env.getAlloc(allocator, "AWS_DEFAULT_PROFILE") catch |e2| switch (e2) {
            error.EnvironmentVariableMissing => allocator.dupe(u8, "default"),
            else => return e2,
        },
        else => return e,
    };
}

/// Build an absolute path to the credentials file.
/// Priority: explicit override → AWS_SHARED_CREDENTIALS_FILE → ~/.aws/credentials.
fn awsCredentialsFilePath(allocator: Allocator, env: std.process.Environ, override: ?[]const u8) ![]u8 {
    if (override) |path| return allocator.dupe(u8, path);
    if (env.getAlloc(allocator, "AWS_SHARED_CREDENTIALS_FILE")) |path| return path else |_| {}
    return awsDefaultFilePath(allocator, env, "credentials");
}

/// Build an absolute path to the config file.
/// Priority: explicit override → AWS_CONFIG_FILE → ~/.aws/config.
fn awsConfigFilePath(allocator: Allocator, env: std.process.Environ, override: ?[]const u8) ![]u8 {
    if (override) |path| return allocator.dupe(u8, path);
    if (env.getAlloc(allocator, "AWS_CONFIG_FILE")) |path| return path else |_| {}
    return awsDefaultFilePath(allocator, env, "config");
}

/// Build an absolute path to ~/.aws/<filename>, expanding the home directory.
fn awsDefaultFilePath(allocator: Allocator, env: std.process.Environ, filename: []const u8) ![]u8 {
    const home_var = comptime if (builtin.os.tag == .windows) "USERPROFILE" else "HOME";
    const home = try env.getAlloc(allocator, home_var);
    defer allocator.free(home);
    return std.fmt.allocPrint(allocator, "{s}/.aws/{s}", .{ home, filename });
}

fn fetchFromAssumeRoleWebIdentity(allocator: Allocator, io: std.Io, env: std.process.Environ, options: CredentialsStoreOptions) !?Credentials {
    _ = options;
    const role_arn = env.getAlloc(allocator, "AWS_ROLE_ARN") catch |e| switch (e) {
        error.EnvironmentVariableMissing => return null,
        else => return e,
    };
    defer allocator.free(role_arn);

    const token_file = env.getAlloc(allocator, "AWS_WEB_IDENTITY_TOKEN_FILE") catch |e| switch (e) {
        error.EnvironmentVariableMissing => return null,
        else => return e,
    };
    defer allocator.free(token_file);

    const token_raw = std.Io.Dir.cwd().readFileAlloc(io, token_file, allocator, std.Io.Limit.limited(16 * 1024)) catch |e| switch (e) {
        error.FileNotFound => return error.WebIdentityTokenFileNotFound,
        else => return e,
    };
    defer allocator.free(token_raw);
    const token = std.mem.trim(u8, token_raw, &std.ascii.whitespace);

    const session_name = env.getAlloc(allocator, "AWS_ROLE_SESSION_NAME") catch |e| switch (e) {
        error.EnvironmentVariableMissing => try allocator.dupe(u8, "aws-sdk-zig"),
        else => return e,
    };
    defer allocator.free(session_name);

    const region = blk: {
        if (env.getAlloc(allocator, "AWS_DEFAULT_REGION")) |r| break :blk r else |_| {}
        if (env.getAlloc(allocator, "AWS_REGION")) |r| break :blk r else |_| {}
        break :blk try allocator.dupe(u8, "us-east-1");
    };
    defer allocator.free(region);

    var sts_client = try sts.Client.init(allocator, .{ .region = region, .io = io });
    defer sts_client.deinit();
    var result = try sts_client.assumeRoleWithWebIdentity(.{
        .role_arn = role_arn,
        .role_session_name = session_name,
        .web_identity_token = token,
    });
    errdefer result.deinit(allocator);

    result.source = try allocator.dupe(u8, role_arn);

    return result;
}

fn fetchFromIAMIdentityCenter(allocator: Allocator, io: std.Io, env: std.process.Environ, options: CredentialsStoreOptions) !?Credentials {
    const config_path = try awsConfigFilePath(allocator, env, options.config_file);
    defer allocator.free(config_path);

    var config = IniFile.parseFile(allocator, io, config_path) catch |e| switch (e) {
        error.FileNotFound => return null,
        else => return e,
    };
    defer config.deinit();

    const profile_name = try resolveProfileName(allocator, env, options.profile_name);
    defer allocator.free(profile_name);

    const section = try configSectionName(allocator, profile_name);
    defer allocator.free(section);

    const SsoParams = struct { start_url: []const u8, region: []const u8, session_name: ?[]const u8 = null };
    const sso = sso: {
        if (config.get(section, "sso_session")) |session_name| {
            const session_section = try std.fmt.allocPrint(allocator, "sso-session {s}", .{session_name});
            defer allocator.free(session_section);
            break :sso SsoParams{
                .start_url = config.get(session_section, "sso_start_url") orelse return error.SsoSessionMissingStartUrl,
                .region = config.get(session_section, "sso_region") orelse config.get(section, "region") orelse "us-east-1",
                .session_name = session_name,
            };
        }
        break :sso SsoParams{
            .start_url = config.get(section, "sso_start_url") orelse return null,
            .region = config.get(section, "sso_region") orelse config.get(section, "region") orelse "us-east-1",
        };
    };
    const start_url = sso.start_url;
    const sso_region = sso.region;
    const account_id = config.get(section, "sso_account_id") orelse return error.SsoConfigMissingAccountId;
    const role_name = config.get(section, "sso_role_name") orelse return error.SsoConfigMissingRoleName;

    // Cache file is named after the SHA1 hex digest of the start URL.
    var digest: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
    if (sso.session_name) |name| {
        std.crypto.hash.Sha1.hash(name, &digest, .{});
    } else {
        std.crypto.hash.Sha1.hash(start_url, &digest, .{});
    }
    const hex = std.fmt.bytesToHex(&digest, .lower);

    const home_var = comptime if (builtin.os.tag == .windows) "USERPROFILE" else "HOME";
    const home = try env.getAlloc(allocator, home_var);
    defer allocator.free(home);

    const cache_path = try std.fmt.allocPrint(allocator, "{s}/.aws/sso/cache/{s}.json", .{ home, hex });
    defer allocator.free(cache_path);
    std.log.debug("sso cache_path={s}", .{cache_path});

    const cache_data = std.Io.Dir.cwd().readFileAlloc(io, cache_path, allocator, std.Io.Limit.limited(64 * 1024)) catch |e| switch (e) {
        error.FileNotFound => return error.SsoTokenCacheNotFound,
        else => return e,
    };
    defer allocator.free(cache_data);

    const SsoToken = struct {
        accessToken: []const u8,
        expiresAt: []const u8,
    };
    const parsed_token = try std.json.parseFromSlice(SsoToken, allocator, cache_data, .{ .ignore_unknown_fields = true });
    defer parsed_token.deinit();

    const exp = parseIso8601ToTimestamp(parsed_token.value.expiresAt) orelse return error.SsoTokenExpired;
    if (hasPassed(io, exp)) return error.SsoTokenExpired;

    const encoded_account = try uri.encodeStandard(allocator, account_id);
    defer allocator.free(encoded_account);
    const encoded_role = try uri.encodeStandard(allocator, role_name);
    defer allocator.free(encoded_role);

    const sso_url = try std.fmt.allocPrint(
        allocator,
        "https://portal.sso.{s}.amazonaws.com/federation/credentials?account_id={s}&role_name={s}",
        .{ sso_region, encoded_account, encoded_role },
    );
    defer allocator.free(sso_url);

    var client = std.http.Client{ .allocator = allocator, .io = io };
    defer client.deinit();

    var body_writer: std.Io.Writer.Allocating = .init(allocator);
    defer body_writer.deinit();

    const result = try client.fetch(.{
        .method = .GET,
        .location = .{ .url = sso_url },
        .extra_headers = &.{.{ .name = "x-amz-sso_bearer_token", .value = parsed_token.value.accessToken }},
        .response_writer = &body_writer.writer,
    });

    if (result.status != .ok) return error.SsoRequestFailed;

    const response_body = body_writer.writer.buffer[0..body_writer.writer.end];

    const RoleCredentials = struct {
        accessKeyId: []const u8,
        secretAccessKey: []const u8,
        sessionToken: []const u8,
        expiration: i64, // milliseconds since epoch
    };
    const SsoResponse = struct {
        roleCredentials: RoleCredentials,
    };
    const parsed_creds = try std.json.parseFromSlice(SsoResponse, allocator, response_body, .{ .ignore_unknown_fields = true });
    defer parsed_creds.deinit();

    const rc = parsed_creds.value.roleCredentials;
    const access_key = try allocator.dupe(u8, rc.accessKeyId);
    errdefer allocator.free(access_key);
    const secret_key = try allocator.dupe(u8, rc.secretAccessKey);
    errdefer allocator.free(secret_key);
    const session_token = try allocator.dupe(u8, rc.sessionToken);
    errdefer allocator.free(session_token);

    return .{
        .access_key_id = access_key,
        .secret_access_key = secret_key,
        .session_token = session_token,
        .expiration = @divFloor(rc.expiration, 1000), // ms → s
        .source = try std.fmt.allocPrint(allocator, "profile ({s})", .{profile_name}),
    };
}

fn fetchFromSharedCredentialsFile(allocator: Allocator, io: std.Io, env: std.process.Environ, options: CredentialsStoreOptions) !?Credentials {
    const path = try awsCredentialsFilePath(allocator, env, options.credentials_file);
    defer allocator.free(path);

    var ini = IniFile.parseFile(allocator, io, path) catch |e| switch (e) {
        error.FileNotFound => return null,
        else => return e,
    };
    defer ini.deinit();

    const profile_name = try resolveProfileName(allocator, env, options.profile_name);
    defer allocator.free(profile_name);

    // Credentials file uses plain profile names (no "profile " prefix).
    return credentialsFromSection(allocator, &ini, profile_name);
}

/// Implements the `credential_process` provider: runs an external command from
/// the config file and parses its JSON stdout for temporary credentials.
fn fetchFromConsoleCredentials(allocator: Allocator, io: std.Io, env: std.process.Environ, options: CredentialsStoreOptions) !?Credentials {
    const config_path = try awsConfigFilePath(allocator, env, options.config_file);
    defer allocator.free(config_path);

    var config = IniFile.parseFile(allocator, io, config_path) catch |e| switch (e) {
        error.FileNotFound => return null,
        else => return e,
    };
    defer config.deinit();

    const profile_name = try resolveProfileName(allocator, env, options.profile_name);
    defer allocator.free(profile_name);

    const section = try configSectionName(allocator, profile_name);
    defer allocator.free(section);

    const process_cmd = config.get(section, "credential_process") orelse return null;

    const argv: []const []const u8 = if (comptime builtin.os.tag == .windows)
        &[_][]const u8{ "cmd", "/c", process_cmd }
    else
        &[_][]const u8{ "sh", "-c", process_cmd };

    const run_result = std.process.run(allocator, io, .{
        .argv = argv,
    }) catch return error.CredentialProcessFailed;
    defer allocator.free(run_result.stdout);
    defer allocator.free(run_result.stderr);

    switch (run_result.term) {
        .exited => |code| if (code != 0) return error.CredentialProcessFailed,
        else => return error.CredentialProcessFailed,
    }

    const ProcessOutput = struct {
        Version: u8,
        AccessKeyId: []const u8,
        SecretAccessKey: []const u8,
        SessionToken: ?[]const u8 = null,
        Expiration: ?[]const u8 = null,
    };
    const parsed = try std.json.parseFromSlice(ProcessOutput, allocator, run_result.stdout, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    const access_key = try allocator.dupe(u8, parsed.value.AccessKeyId);
    errdefer allocator.free(access_key);
    const secret_key = try allocator.dupe(u8, parsed.value.SecretAccessKey);
    errdefer allocator.free(secret_key);
    const session_token: ?[]const u8 = if (parsed.value.SessionToken) |t|
        try allocator.dupe(u8, t)
    else
        null;
    errdefer if (session_token) |t| allocator.free(t);

    return .{
        .access_key_id = access_key,
        .secret_access_key = secret_key,
        .session_token = session_token,
        .expiration = if (parsed.value.Expiration) |e| parseIso8601ToTimestamp(e) else null,
        .source = try allocator.dupe(u8, "Process"),
    };
}

fn fetchFromConfigFile(allocator: Allocator, io: std.Io, env: std.process.Environ, options: CredentialsStoreOptions) !?Credentials {
    const path = try awsConfigFilePath(allocator, env, options.config_file);
    defer allocator.free(path);

    var ini = IniFile.parseFile(allocator, io, path) catch |e| switch (e) {
        error.FileNotFound => return null,
        else => return e,
    };
    defer ini.deinit();

    const profile_name = try resolveProfileName(allocator, env, options.profile_name);
    defer allocator.free(profile_name);

    const section = try configSectionName(allocator, profile_name);
    defer allocator.free(section);

    return credentialsFromSection(allocator, &ini, section);
}

fn fetchInsideContainer(allocator: Allocator, io: std.Io, env: std.process.Environ, options: CredentialsStoreOptions) !?Credentials {
    _ = options;
    // ECS task role: relative URI against the link-local metadata address.
    if (env.getAlloc(allocator, "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")) |rel_uri| {
        defer allocator.free(rel_uri);
        const url = try std.fmt.allocPrint(allocator, "http://169.254.170.2{s}", .{rel_uri});
        defer allocator.free(url);
        return fetchCredentialsFromEndpoint(allocator, io, url, null, "Container");
    } else |e| if (e != error.EnvironmentVariableMissing) return e;

    // EKS pod identity / Fargate: caller-supplied full URI with optional bearer token.
    if (env.getAlloc(allocator, "AWS_CONTAINER_CREDENTIALS_FULL_URI")) |full_uri| {
        defer allocator.free(full_uri);

        const auth_token: ?[]u8 = blk: {
            if (env.getAlloc(allocator, "AWS_CONTAINER_AUTHORIZATION_TOKEN")) |t| break :blk t else |e| if (e != error.EnvironmentVariableMissing) return e;
            if (env.getAlloc(allocator, "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE")) |file_path| {
                defer allocator.free(file_path);
                const raw = try std.Io.Dir.cwd().readFileAlloc(io, file_path, allocator, std.Io.Limit.limited(4 * 1024));
                defer allocator.free(raw);
                break :blk try allocator.dupe(u8, std.mem.trim(u8, raw, &std.ascii.whitespace));
            } else |e| if (e != error.EnvironmentVariableMissing) return e;
            break :blk null;
        };
        defer if (auth_token) |t| allocator.free(t);

        return fetchCredentialsFromEndpoint(allocator, io, full_uri, auth_token, "Container");
    } else |e| if (e != error.EnvironmentVariableMissing) return e;

    return null;
}

/// Returns true when running inside WSL. WSL always exports WSL_DISTRO_NAME.
/// We skip the IMDS check on WSL: 169.254.169.254 is unreachable and
/// std.http.Client with std.Io crashes (SIGBUS via io_uring) instead of
/// returning a catchable error.
fn isWsl(allocator: Allocator, env: std.process.Environ) bool {
    if (comptime builtin.os.tag != .linux) return false;
    const val = env.getAlloc(allocator, "WSL_DISTRO_NAME") catch return false;
    allocator.free(val);
    std.log.debug("isWsl: detected WSL (WSL_DISTRO_NAME is set)", .{});
    return true;
}

fn fetchFromIMDS(allocator: Allocator, io: std.Io, env: std.process.Environ, options: CredentialsStoreOptions) !?Credentials {
    _ = options;

    if (isWsl(allocator, env)) {
        std.log.debug("fetchFromIMDS: skipping — running on WSL", .{});
        return null;
    }

    const base_url = env.getAlloc(allocator, "AWS_EC2_METADATA_SERVICE_ENDPOINT") catch |e| switch (e) {
        error.EnvironmentVariableMissing => try allocator.dupe(u8, "http://169.254.169.254"),
        else => return e,
    };
    defer allocator.free(base_url);

    var client = std.http.Client{ .allocator = allocator, .io = io };
    defer client.deinit();

    // IMDSv2: exchange a TTL for a session token.
    const token_url = try std.fmt.allocPrint(allocator, "{s}/latest/api/token", .{base_url});
    defer allocator.free(token_url);

    var token_body_writer: std.Io.Writer.Allocating = .init(allocator);
    defer token_body_writer.deinit();

    const token_result = client.fetch(.{
        .method = .PUT,
        .location = .{ .url = token_url },
        .extra_headers = &.{.{ .name = "X-aws-ec2-metadata-token-ttl-seconds", .value = "21600" }},
        .response_writer = &token_body_writer.writer,
    }) catch return null; // Not on EC2: connection refused or unreachable.

    if (token_result.status != .ok) return null;
    const imds_token = token_body_writer.writer.buffer[0..token_body_writer.writer.end];

    // Retrieve the IAM role attached to this instance.
    const role_url = try std.fmt.allocPrint(allocator, "{s}/latest/meta-data/iam/security-credentials/", .{base_url});
    defer allocator.free(role_url);

    var role_body_writer: std.Io.Writer.Allocating = .init(allocator);
    defer role_body_writer.deinit();

    const role_result = try client.fetch(.{
        .method = .GET,
        .location = .{ .url = role_url },
        .extra_headers = &.{.{ .name = "X-aws-ec2-metadata-token", .value = imds_token }},
        .response_writer = &role_body_writer.writer,
    });

    if (role_result.status == .not_found) return null; // No IAM role attached.
    if (role_result.status != .ok) return error.ImdsRequestFailed;

    const role_name = std.mem.trim(u8, role_body_writer.writer.buffer[0..role_body_writer.writer.end], &std.ascii.whitespace);

    // Fetch credentials for the role.
    const creds_url = try std.fmt.allocPrint(allocator, "{s}/latest/meta-data/iam/security-credentials/{s}", .{ base_url, role_name });
    defer allocator.free(creds_url);

    var creds_body_writer: std.Io.Writer.Allocating = .init(allocator);
    defer creds_body_writer.deinit();

    const creds_result = try client.fetch(.{
        .method = .GET,
        .location = .{ .url = creds_url },
        .extra_headers = &.{.{ .name = "X-aws-ec2-metadata-token", .value = imds_token }},
        .response_writer = &creds_body_writer.writer,
    });

    if (creds_result.status != .ok) return error.ImdsRequestFailed;

    return try parseCredentialsEndpointJson(allocator, creds_body_writer.writer.buffer[0..creds_body_writer.writer.end], "Ec2InstanceMetadata");
}

/// Parse the JSON body returned by ECS container credentials and IMDS endpoints.
fn parseCredentialsEndpointJson(allocator: Allocator, body: []const u8, source: []const u8) !Credentials {
    const Json = struct {
        AccessKeyId: []const u8,
        SecretAccessKey: []const u8,
        Token: ?[]const u8 = null,
        Expiration: ?[]const u8 = null,
    };
    const parsed = try std.json.parseFromSlice(Json, allocator, body, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    const access_key = try allocator.dupe(u8, parsed.value.AccessKeyId);
    errdefer allocator.free(access_key);
    const secret_key = try allocator.dupe(u8, parsed.value.SecretAccessKey);
    errdefer allocator.free(secret_key);
    const session_token: ?[]const u8 = if (parsed.value.Token) |t|
        try allocator.dupe(u8, t)
    else
        null;
    errdefer if (session_token) |t| allocator.free(t);

    return .{
        .access_key_id = access_key,
        .secret_access_key = secret_key,
        .session_token = session_token,
        .expiration = if (parsed.value.Expiration) |e| parseIso8601ToTimestamp(e) else null,
        .source = try allocator.dupe(u8, source),
    };
}

/// GET a credentials endpoint and parse the JSON response.
fn fetchCredentialsFromEndpoint(allocator: Allocator, io: std.Io, url: []const u8, auth_token: ?[]u8, source: []const u8) !?Credentials {
    var client = std.http.Client{ .allocator = allocator, .io = io };
    defer client.deinit();

    var extra_headers: std.ArrayList(std.http.Header) = .empty;
    defer extra_headers.deinit(allocator);
    if (auth_token) |token| {
        try extra_headers.append(allocator, .{ .name = "Authorization", .value = token });
    }

    var body_writer: std.Io.Writer.Allocating = .init(allocator);
    defer body_writer.deinit();

    const result = try client.fetch(.{
        .method = .GET,
        .location = .{ .url = url },
        .extra_headers = extra_headers.items,
        .response_writer = &body_writer.writer,
    });

    if (result.status != .ok) return error.CredentialsEndpointRequestFailed;

    return try parseCredentialsEndpointJson(allocator, body_writer.writer.buffer[0..body_writer.writer.end], source);
}
