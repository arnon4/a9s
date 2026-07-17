const std = @import("std");
const Allocator = std.mem.Allocator;

const sigv4 = @import("../../../sig/sigv4.zig");
const aws_errors = @import("../../aws_errors.zig");

pub const getFunctionConfigurationError = error{
    ResourceNotFoundException,
    InvalidParameterValueException,
};

pub const Options = struct {
    /// Function name, ARN, or partial ARN.
    function_name: []const u8,
    /// Specify a version or alias. Defaults to $LATEST.
    qualifier: ?[]const u8 = null,
};

pub const Environment = struct {
    allocator: Allocator,
    variables: std.StringHashMap([]u8),

    pub fn deinit(self: *Environment) void {
        var iter = self.variables.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.variables.deinit();
    }
};

pub const Layer = struct {
    allocator: Allocator,
    arn: []u8,
    code_size: i64,
    signing_profile_version_arn: []u8,
    signing_job_arn: []u8,

    pub fn deinit(self: Layer) void {
        self.allocator.free(self.arn);
        self.allocator.free(self.signing_profile_version_arn);
        self.allocator.free(self.signing_job_arn);
    }
};

pub const LoggingConfig = struct {
    allocator: Allocator,
    log_format: []u8,
    log_group: []u8,
    application_log_level: []u8,
    system_log_level: []u8,

    pub fn deinit(self: LoggingConfig) void {
        self.allocator.free(self.log_format);
        self.allocator.free(self.log_group);
        self.allocator.free(self.application_log_level);
        self.allocator.free(self.system_log_level);
    }
};

pub const VpcConfig = struct {
    allocator: Allocator,
    vpc_id: []u8,
    subnet_ids: [][]u8,
    security_group_ids: [][]u8,
    ipv6_allowed_for_dual_stack: bool,

    pub fn deinit(self: VpcConfig) void {
        self.allocator.free(self.vpc_id);
        for (self.subnet_ids) |s| self.allocator.free(s);
        self.allocator.free(self.subnet_ids);
        for (self.security_group_ids) |s| self.allocator.free(s);
        self.allocator.free(self.security_group_ids);
    }
};

pub const ImageConfig = struct {
    allocator: Allocator,
    entry_point: [][]u8,
    command: [][]u8,
    working_directory: []u8,

    pub fn deinit(self: ImageConfig) void {
        for (self.entry_point) |s| self.allocator.free(s);
        self.allocator.free(self.entry_point);
        for (self.command) |s| self.allocator.free(s);
        self.allocator.free(self.command);
        self.allocator.free(self.working_directory);
    }
};

pub const SnapStart = struct {
    allocator: Allocator,
    apply_on: []u8,
    optimization_status: []u8,

    pub fn deinit(self: SnapStart) void {
        self.allocator.free(self.apply_on);
        self.allocator.free(self.optimization_status);
    }
};

pub const FunctionConfiguration = struct {
    allocator: Allocator,
    function_name: []u8,
    function_arn: []u8,
    runtime: []u8,
    role: []u8,
    handler: []u8,
    code_size: i64,
    description: []u8,
    timeout: u32,
    memory_size: u32,
    last_modified: []u8,
    code_sha256: []u8,
    version: []u8,
    package_type: []u8,
    architectures: [][]u8,
    state: []u8,
    state_reason: []u8,
    state_reason_code: []u8,
    last_update_status: []u8,
    last_update_status_reason: []u8,
    last_update_status_reason_code: []u8,
    revision_id: []u8,
    kms_key_arn: []u8,
    master_arn: []u8,
    signing_job_arn: []u8,
    signing_profile_version_arn: []u8,
    ephemeral_storage_size: u32,
    tracing_mode: []u8,
    dead_letter_target_arn: []u8,
    runtime_version_arn: []u8,
    environment: ?Environment,
    layers: []Layer,
    logging_config: ?LoggingConfig,
    vpc_config: ?VpcConfig,
    image_config: ?ImageConfig,
    snap_start: ?SnapStart,

    pub fn deinit(self: *FunctionConfiguration) void {
        self.allocator.free(self.function_name);
        self.allocator.free(self.function_arn);
        self.allocator.free(self.runtime);
        self.allocator.free(self.role);
        self.allocator.free(self.handler);
        self.allocator.free(self.description);
        self.allocator.free(self.last_modified);
        self.allocator.free(self.code_sha256);
        self.allocator.free(self.version);
        self.allocator.free(self.package_type);
        self.allocator.free(self.state);
        self.allocator.free(self.state_reason);
        self.allocator.free(self.state_reason_code);
        self.allocator.free(self.last_update_status);
        self.allocator.free(self.last_update_status_reason);
        self.allocator.free(self.last_update_status_reason_code);
        self.allocator.free(self.revision_id);
        self.allocator.free(self.kms_key_arn);
        self.allocator.free(self.master_arn);
        self.allocator.free(self.signing_job_arn);
        self.allocator.free(self.signing_profile_version_arn);
        self.allocator.free(self.tracing_mode);
        self.allocator.free(self.dead_letter_target_arn);
        self.allocator.free(self.runtime_version_arn);
        for (self.architectures) |a| self.allocator.free(a);
        self.allocator.free(self.architectures);
        for (self.layers) |l| l.deinit();
        self.allocator.free(self.layers);
        if (self.environment) |*e| e.deinit();
        if (self.logging_config) |lc| lc.deinit();
        if (self.vpc_config) |vc| vc.deinit();
        if (self.image_config) |ic| ic.deinit();
        if (self.snap_start) |ss| ss.deinit();
    }
};

pub fn getFunctionConfiguration(client: anytype, options: Options) !FunctionConfiguration {
    const qualifier_suffix = if (options.qualifier) |q|
        try std.fmt.allocPrint(client.allocator, "?Qualifier={s}", .{q})
    else
        try client.allocator.dupe(u8, "");
    defer client.allocator.free(qualifier_suffix);

    const request_url = try std.fmt.allocPrint(
        client.allocator,
        "{s}/2015-03-31/functions/{s}/configuration{s}",
        .{ client.endpoint, options.function_name, qualifier_suffix },
    );
    defer client.allocator.free(request_url);

    var extra_headers = std.StringHashMap([]const u8).init(client.allocator);
    defer extra_headers.deinit();
    if (client.credentials.session_token) |token| {
        try extra_headers.put("X-Amz-Security-Token", token);
    }

    var signed = try sigv4.sign(
        client.allocator,
        client.io,
        .{
            .access_key = client.credentials.access_key_id,
            .secret_key = client.credentials.secret_access_key,
            .region = client.region,
            .service = "lambda",
        },
        .GET,
        request_url,
        extra_headers,
        "",
        null,
    );
    defer signed.deinit();

    var header_list: std.ArrayList(std.http.Header) = .empty;
    defer header_list.deinit(client.allocator);
    var iter = signed.headers.iterator();
    while (iter.next()) |entry| {
        if (std.ascii.eqlIgnoreCase(entry.key_ptr.*, "host")) continue;
        try header_list.append(client.allocator, .{ .name = entry.key_ptr.*, .value = entry.value_ptr.* });
    }

    var http_client = std.http.Client{ .allocator = client.allocator, .io = client.io };
    defer http_client.deinit();

    var resp_writer: std.Io.Writer.Allocating = .init(client.allocator);
    defer resp_writer.deinit();

    const result = try http_client.fetch(.{
        .method = .GET,
        .location = .{ .url = request_url },
        .extra_headers = header_list.items,
        .response_writer = &resp_writer.writer,
    });

    const resp_body = resp_writer.writer.buffer[0..resp_writer.writer.end];

    if (result.status != .ok) {
        const code_str = extractJsonString(client.allocator, resp_body, "Type") catch
            extractJsonString(client.allocator, resp_body, "Code") catch null;
        defer if (code_str) |c| client.allocator.free(c);
        if (code_str) |c| {
            std.log.err("Lambda GetFunctionConfiguration error: {s} (status {d})", .{ c, @intFromEnum(result.status) });
            inline for (@typeInfo(getFunctionConfigurationError).error_set.?) |entry| {
                if (std.mem.eql(u8, entry.name, c)) return @field(getFunctionConfigurationError, entry.name);
            }
            return aws_errors.fromCode(c) orelse aws_errors.fromStatus(result.status);
        }
        return aws_errors.fromStatus(result.status);
    }

    return parseFunctionConfiguration(client.allocator, resp_body);
}

fn extractJsonString(allocator: Allocator, json: []const u8, key: []const u8) ![]u8 {
    const needle = try std.fmt.allocPrint(allocator, "\"{s}\"", .{key});
    defer allocator.free(needle);

    const pos = std.mem.indexOf(u8, json, needle) orelse return error.KeyNotFound;
    const after_key = json[pos + needle.len ..];
    const colon = std.mem.indexOfScalar(u8, after_key, ':') orelse return error.KeyNotFound;
    const after_colon = std.mem.trimStart(u8, after_key[colon + 1 ..], " \t\r\n");
    if (after_colon.len == 0 or after_colon[0] != '"') return error.KeyNotFound;
    const content = after_colon[1..];
    const end = std.mem.indexOfScalar(u8, content, '"') orelse return error.KeyNotFound;
    return allocator.dupe(u8, content[0..end]);
}

fn jsonStr(obj: std.json.ObjectMap, key: []const u8) []const u8 {
    const v = obj.get(key) orelse return "";
    return switch (v) {
        .string => |s| s,
        else => "",
    };
}

fn jsonInt(comptime T: type, obj: std.json.ObjectMap, key: []const u8) T {
    const v = obj.get(key) orelse return 0;
    return switch (v) {
        .integer => |i| @intCast(i),
        else => 0,
    };
}

fn jsonBool(obj: std.json.ObjectMap, key: []const u8) bool {
    const v = obj.get(key) orelse return false;
    return switch (v) {
        .bool => |b| b,
        else => false,
    };
}

fn parseStringArray(allocator: Allocator, val: std.json.Value) ![][]u8 {
    var list: std.ArrayList([]u8) = .empty;
    errdefer {
        for (list.items) |s| allocator.free(s);
        list.deinit(allocator);
    }
    switch (val) {
        .array => |arr| {
            for (arr.items) |item| {
                switch (item) {
                    .string => |s| try list.append(allocator, try allocator.dupe(u8, s)),
                    else => {},
                }
            }
        },
        else => {},
    }
    return list.toOwnedSlice(allocator);
}

fn parseFunctionConfiguration(allocator: Allocator, body: []const u8) !FunctionConfiguration {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return error.UnexpectedJsonType,
    };

    const function_name = try allocator.dupe(u8, jsonStr(obj, "FunctionName"));
    errdefer allocator.free(function_name);
    const function_arn = try allocator.dupe(u8, jsonStr(obj, "FunctionArn"));
    errdefer allocator.free(function_arn);
    const runtime = try allocator.dupe(u8, jsonStr(obj, "Runtime"));
    errdefer allocator.free(runtime);
    const role = try allocator.dupe(u8, jsonStr(obj, "Role"));
    errdefer allocator.free(role);
    const handler = try allocator.dupe(u8, jsonStr(obj, "Handler"));
    errdefer allocator.free(handler);
    const description = try allocator.dupe(u8, jsonStr(obj, "Description"));
    errdefer allocator.free(description);
    const last_modified = try allocator.dupe(u8, jsonStr(obj, "LastModified"));
    errdefer allocator.free(last_modified);
    const code_sha256 = try allocator.dupe(u8, jsonStr(obj, "CodeSha256"));
    errdefer allocator.free(code_sha256);
    const version = try allocator.dupe(u8, jsonStr(obj, "Version"));
    errdefer allocator.free(version);
    const package_type = try allocator.dupe(u8, jsonStr(obj, "PackageType"));
    errdefer allocator.free(package_type);
    const state = try allocator.dupe(u8, jsonStr(obj, "State"));
    errdefer allocator.free(state);
    const state_reason = try allocator.dupe(u8, jsonStr(obj, "StateReason"));
    errdefer allocator.free(state_reason);
    const state_reason_code = try allocator.dupe(u8, jsonStr(obj, "StateReasonCode"));
    errdefer allocator.free(state_reason_code);
    const last_update_status = try allocator.dupe(u8, jsonStr(obj, "LastUpdateStatus"));
    errdefer allocator.free(last_update_status);
    const last_update_status_reason = try allocator.dupe(u8, jsonStr(obj, "LastUpdateStatusReason"));
    errdefer allocator.free(last_update_status_reason);
    const last_update_status_reason_code = try allocator.dupe(u8, jsonStr(obj, "LastUpdateStatusReasonCode"));
    errdefer allocator.free(last_update_status_reason_code);
    const revision_id = try allocator.dupe(u8, jsonStr(obj, "RevisionId"));
    errdefer allocator.free(revision_id);
    const kms_key_arn = try allocator.dupe(u8, jsonStr(obj, "KMSKeyArn"));
    errdefer allocator.free(kms_key_arn);
    const master_arn = try allocator.dupe(u8, jsonStr(obj, "MasterArn"));
    errdefer allocator.free(master_arn);
    const signing_job_arn = try allocator.dupe(u8, jsonStr(obj, "SigningJobArn"));
    errdefer allocator.free(signing_job_arn);
    const signing_profile_version_arn = try allocator.dupe(u8, jsonStr(obj, "SigningProfileVersionArn"));
    errdefer allocator.free(signing_profile_version_arn);

    const tracing_mode: []u8 = blk: {
        const v = obj.get("TracingConfig") orelse break :blk try allocator.dupe(u8, "");
        switch (v) {
            .object => |tc| break :blk try allocator.dupe(u8, jsonStr(tc, "Mode")),
            else => break :blk try allocator.dupe(u8, ""),
        }
    };
    errdefer allocator.free(tracing_mode);

    const dead_letter_target_arn: []u8 = blk: {
        const v = obj.get("DeadLetterConfig") orelse break :blk try allocator.dupe(u8, "");
        switch (v) {
            .object => |dlc| break :blk try allocator.dupe(u8, jsonStr(dlc, "TargetArn")),
            else => break :blk try allocator.dupe(u8, ""),
        }
    };
    errdefer allocator.free(dead_letter_target_arn);

    const runtime_version_arn: []u8 = blk: {
        const v = obj.get("RuntimeVersionConfig") orelse break :blk try allocator.dupe(u8, "");
        switch (v) {
            .object => |rvc| break :blk try allocator.dupe(u8, jsonStr(rvc, "RuntimeVersionArn")),
            else => break :blk try allocator.dupe(u8, ""),
        }
    };
    errdefer allocator.free(runtime_version_arn);

    var arch_list: std.ArrayList([]u8) = .empty;
    errdefer {
        for (arch_list.items) |a| allocator.free(a);
        arch_list.deinit(allocator);
    }
    if (obj.get("Architectures")) |arch_val| {
        switch (arch_val) {
            .array => |arr| {
                for (arr.items) |item| {
                    switch (item) {
                        .string => |s| try arch_list.append(allocator, try allocator.dupe(u8, s)),
                        else => {},
                    }
                }
            },
            else => {},
        }
    }

    var layer_list: std.ArrayList(Layer) = .empty;
    errdefer {
        for (layer_list.items) |l| l.deinit();
        layer_list.deinit(allocator);
    }
    if (obj.get("Layers")) |layers_val| {
        switch (layers_val) {
            .array => |arr| {
                for (arr.items) |item| {
                    switch (item) {
                        .object => |lobj| {
                            const l = try parseLayer(allocator, lobj);
                            errdefer l.deinit();
                            try layer_list.append(allocator, l);
                        },
                        else => {},
                    }
                }
            },
            else => {},
        }
    }

    var environment: ?Environment = null;
    errdefer if (environment) |*e| e.deinit();
    if (obj.get("Environment")) |env_val| {
        switch (env_val) {
            .object => |env_obj| {
                if (env_obj.get("Variables")) |vars_val| {
                    switch (vars_val) {
                        .object => |vars_obj| {
                            environment = try parseEnvironment(allocator, vars_obj);
                        },
                        else => {},
                    }
                }
            },
            else => {},
        }
    }

    var logging_config: ?LoggingConfig = null;
    errdefer if (logging_config) |lc| lc.deinit();
    if (obj.get("LoggingConfig")) |lc_val| {
        switch (lc_val) {
            .object => |lc_obj| logging_config = try parseLoggingConfig(allocator, lc_obj),
            else => {},
        }
    }

    var vpc_config: ?VpcConfig = null;
    errdefer if (vpc_config) |vc| vc.deinit();
    if (obj.get("VpcConfig")) |v| {
        switch (v) {
            .object => |o| vpc_config = try parseVpcConfig(allocator, o),
            else => {},
        }
    }

    var image_config: ?ImageConfig = null;
    errdefer if (image_config) |ic| ic.deinit();
    if (obj.get("ImageConfigResponse")) |v| {
        switch (v) {
            .object => |outer| {
                if (outer.get("ImageConfig")) |ic_val| {
                    switch (ic_val) {
                        .object => |o| image_config = try parseImageConfig(allocator, o),
                        else => {},
                    }
                }
            },
            else => {},
        }
    }

    var snap_start: ?SnapStart = null;
    errdefer if (snap_start) |ss| ss.deinit();
    if (obj.get("SnapStart")) |v| {
        switch (v) {
            .object => |o| snap_start = try parseSnapStart(allocator, o),
            else => {},
        }
    }

    const ephemeral_storage_size: u32 = blk: {
        const v = obj.get("EphemeralStorage") orelse break :blk 512;
        switch (v) {
            .object => |es| break :blk jsonInt(u32, es, "Size"),
            else => break :blk 512,
        }
    };

    return .{
        .allocator = allocator,
        .function_name = function_name,
        .function_arn = function_arn,
        .runtime = runtime,
        .role = role,
        .handler = handler,
        .code_size = jsonInt(i64, obj, "CodeSize"),
        .description = description,
        .timeout = jsonInt(u32, obj, "Timeout"),
        .memory_size = jsonInt(u32, obj, "MemorySize"),
        .last_modified = last_modified,
        .code_sha256 = code_sha256,
        .version = version,
        .package_type = package_type,
        .architectures = try arch_list.toOwnedSlice(allocator),
        .state = state,
        .state_reason = state_reason,
        .state_reason_code = state_reason_code,
        .last_update_status = last_update_status,
        .last_update_status_reason = last_update_status_reason,
        .last_update_status_reason_code = last_update_status_reason_code,
        .revision_id = revision_id,
        .kms_key_arn = kms_key_arn,
        .master_arn = master_arn,
        .signing_job_arn = signing_job_arn,
        .signing_profile_version_arn = signing_profile_version_arn,
        .ephemeral_storage_size = ephemeral_storage_size,
        .tracing_mode = tracing_mode,
        .dead_letter_target_arn = dead_letter_target_arn,
        .runtime_version_arn = runtime_version_arn,
        .environment = environment,
        .layers = try layer_list.toOwnedSlice(allocator),
        .logging_config = logging_config,
        .vpc_config = vpc_config,
        .image_config = image_config,
        .snap_start = snap_start,
    };
}

fn parseLayer(allocator: Allocator, obj: std.json.ObjectMap) !Layer {
    const arn = try allocator.dupe(u8, jsonStr(obj, "Arn"));
    errdefer allocator.free(arn);
    const signing_profile_version_arn = try allocator.dupe(u8, jsonStr(obj, "SigningProfileVersionArn"));
    errdefer allocator.free(signing_profile_version_arn);
    const signing_job_arn = try allocator.dupe(u8, jsonStr(obj, "SigningJobArn"));
    errdefer allocator.free(signing_job_arn);
    return .{
        .allocator = allocator,
        .arn = arn,
        .code_size = jsonInt(i64, obj, "CodeSize"),
        .signing_profile_version_arn = signing_profile_version_arn,
        .signing_job_arn = signing_job_arn,
    };
}

fn parseLoggingConfig(allocator: Allocator, obj: std.json.ObjectMap) !LoggingConfig {
    const log_format = try allocator.dupe(u8, jsonStr(obj, "LogFormat"));
    errdefer allocator.free(log_format);
    const log_group = try allocator.dupe(u8, jsonStr(obj, "LogGroup"));
    errdefer allocator.free(log_group);
    const application_log_level = try allocator.dupe(u8, jsonStr(obj, "ApplicationLogLevel"));
    errdefer allocator.free(application_log_level);
    const system_log_level = try allocator.dupe(u8, jsonStr(obj, "SystemLogLevel"));
    errdefer allocator.free(system_log_level);
    return .{
        .allocator = allocator,
        .log_format = log_format,
        .log_group = log_group,
        .application_log_level = application_log_level,
        .system_log_level = system_log_level,
    };
}

fn parseVpcConfig(allocator: Allocator, obj: std.json.ObjectMap) !VpcConfig {
    const vpc_id = try allocator.dupe(u8, jsonStr(obj, "VpcId"));
    errdefer allocator.free(vpc_id);

    var subnet_ids: [][]u8 = &.{};
    errdefer {
        for (subnet_ids) |s| allocator.free(s);
        allocator.free(subnet_ids);
    }
    if (obj.get("SubnetIds")) |v| subnet_ids = try parseStringArray(allocator, v);

    var security_group_ids: [][]u8 = &.{};
    errdefer {
        for (security_group_ids) |s| allocator.free(s);
        allocator.free(security_group_ids);
    }
    if (obj.get("SecurityGroupIds")) |v| security_group_ids = try parseStringArray(allocator, v);

    return .{
        .allocator = allocator,
        .vpc_id = vpc_id,
        .subnet_ids = subnet_ids,
        .security_group_ids = security_group_ids,
        .ipv6_allowed_for_dual_stack = jsonBool(obj, "Ipv6AllowedForDualStack"),
    };
}

fn parseImageConfig(allocator: Allocator, obj: std.json.ObjectMap) !ImageConfig {
    var entry_point: [][]u8 = &.{};
    errdefer {
        for (entry_point) |s| allocator.free(s);
        allocator.free(entry_point);
    }
    if (obj.get("EntryPoint")) |v| entry_point = try parseStringArray(allocator, v);

    var command: [][]u8 = &.{};
    errdefer {
        for (command) |s| allocator.free(s);
        allocator.free(command);
    }
    if (obj.get("Command")) |v| command = try parseStringArray(allocator, v);

    const working_directory = try allocator.dupe(u8, jsonStr(obj, "WorkingDirectory"));
    errdefer allocator.free(working_directory);

    return .{
        .allocator = allocator,
        .entry_point = entry_point,
        .command = command,
        .working_directory = working_directory,
    };
}

fn parseSnapStart(allocator: Allocator, obj: std.json.ObjectMap) !SnapStart {
    const apply_on = try allocator.dupe(u8, jsonStr(obj, "ApplyOn"));
    errdefer allocator.free(apply_on);
    const optimization_status = try allocator.dupe(u8, jsonStr(obj, "OptimizationStatus"));
    errdefer allocator.free(optimization_status);
    return .{ .allocator = allocator, .apply_on = apply_on, .optimization_status = optimization_status };
}

fn parseEnvironment(allocator: Allocator, vars: std.json.ObjectMap) !Environment {
    var map = std.StringHashMap([]u8).init(allocator);
    errdefer {
        var iter = map.iterator();
        while (iter.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        map.deinit();
    }
    var iter = vars.iterator();
    while (iter.next()) |entry| {
        const k = try allocator.dupe(u8, entry.key_ptr.*);
        errdefer allocator.free(k);
        const v = switch (entry.value_ptr.*) {
            .string => |s| try allocator.dupe(u8, s),
            else => try allocator.dupe(u8, ""),
        };
        errdefer allocator.free(v);
        try map.put(k, v);
    }
    return .{ .allocator = allocator, .variables = map };
}

// ============================================================================
// Tests
// ============================================================================

test "parseFunctionConfiguration basic" {
    const body =
        \\{
        \\  "FunctionName": "my-function",
        \\  "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:my-function",
        \\  "Runtime": "python3.12",
        \\  "Role": "arn:aws:iam::123456789012:role/lambda-role",
        \\  "Handler": "index.handler",
        \\  "CodeSize": 2048,
        \\  "Description": "My function",
        \\  "Timeout": 60,
        \\  "MemorySize": 256,
        \\  "LastModified": "2024-01-15T10:30:00.000+0000",
        \\  "CodeSha256": "abc123",
        \\  "Version": "$LATEST",
        \\  "PackageType": "Zip",
        \\  "Architectures": ["x86_64"],
        \\  "State": "Active",
        \\  "StateReason": "",
        \\  "StateReasonCode": "",
        \\  "LastUpdateStatus": "Successful",
        \\  "LastUpdateStatusReason": "",
        \\  "LastUpdateStatusReasonCode": "",
        \\  "RevisionId": "rev-001",
        \\  "EphemeralStorage": { "Size": 512 },
        \\  "TracingConfig": { "Mode": "PassThrough" }
        \\}
    ;
    var cfg = try parseFunctionConfiguration(std.testing.allocator, body);
    defer cfg.deinit();

    try std.testing.expectEqualStrings("my-function", cfg.function_name);
    try std.testing.expectEqualStrings("python3.12", cfg.runtime);
    try std.testing.expectEqual(@as(i64, 2048), cfg.code_size);
    try std.testing.expectEqual(@as(u32, 60), cfg.timeout);
    try std.testing.expectEqual(@as(u32, 256), cfg.memory_size);
    try std.testing.expectEqualStrings("Active", cfg.state);
    try std.testing.expectEqualStrings("Successful", cfg.last_update_status);
    try std.testing.expectEqualStrings("rev-001", cfg.revision_id);
    try std.testing.expectEqual(@as(u32, 512), cfg.ephemeral_storage_size);
    try std.testing.expectEqualStrings("PassThrough", cfg.tracing_mode);
    try std.testing.expect(cfg.environment == null);
    try std.testing.expectEqual(@as(usize, 0), cfg.layers.len);
    try std.testing.expect(cfg.logging_config == null);
    try std.testing.expect(cfg.vpc_config == null);
    try std.testing.expect(cfg.snap_start == null);
    try std.testing.expect(cfg.image_config == null);
}

test "parseFunctionConfiguration full" {
    const body =
        \\{
        \\  "FunctionName": "full-fn",
        \\  "FunctionArn": "arn:aws:lambda:us-east-1:123:function:full-fn",
        \\  "Runtime": "nodejs20.x",
        \\  "Role": "arn:aws:iam::123:role/r",
        \\  "Handler": "index.handler",
        \\  "CodeSize": 512,
        \\  "Description": "",
        \\  "Timeout": 30,
        \\  "MemorySize": 128,
        \\  "LastModified": "2024-06-01T00:00:00.000+0000",
        \\  "CodeSha256": "def456",
        \\  "Version": "$LATEST",
        \\  "PackageType": "Zip",
        \\  "Architectures": ["arm64"],
        \\  "State": "Active",
        \\  "StateReason": "",
        \\  "StateReasonCode": "",
        \\  "LastUpdateStatus": "Successful",
        \\  "LastUpdateStatusReason": "",
        \\  "LastUpdateStatusReasonCode": "EniLimitExceeded",
        \\  "RevisionId": "rev-002",
        \\  "KMSKeyArn": "arn:aws:kms:us-east-1:123:key/abc",
        \\  "MasterArn": "",
        \\  "SigningJobArn": "arn:aws:signer:us-east-1:123:signing-jobs/xyz",
        \\  "SigningProfileVersionArn": "arn:aws:signer:us-east-1:123:signing-profiles/p/v",
        \\  "DeadLetterConfig": { "TargetArn": "arn:aws:sqs:us-east-1:123:dlq" },
        \\  "TracingConfig": { "Mode": "Active" },
        \\  "RuntimeVersionConfig": { "RuntimeVersionArn": "arn:aws:lambda:us-east-1::runtime:abc" },
        \\  "VpcConfig": {
        \\    "VpcId": "vpc-abc123",
        \\    "SubnetIds": ["subnet-1", "subnet-2"],
        \\    "SecurityGroupIds": ["sg-1"],
        \\    "Ipv6AllowedForDualStack": false
        \\  },
        \\  "Environment": {
        \\    "Variables": { "FOO": "bar", "DB_HOST": "localhost" }
        \\  },
        \\  "Layers": [
        \\    {
        \\      "Arn": "arn:aws:lambda:us-east-1:123:layer:my-layer:1",
        \\      "CodeSize": 4096,
        \\      "SigningProfileVersionArn": "",
        \\      "SigningJobArn": ""
        \\    }
        \\  ],
        \\  "LoggingConfig": {
        \\    "LogFormat": "JSON",
        \\    "LogGroup": "/aws/lambda/full-fn",
        \\    "ApplicationLogLevel": "INFO",
        \\    "SystemLogLevel": "WARN"
        \\  },
        \\  "SnapStart": { "ApplyOn": "PublishedVersions", "OptimizationStatus": "On" },
        \\  "ImageConfigResponse": {
        \\    "ImageConfig": {
        \\      "EntryPoint": ["/bin/sh"],
        \\      "Command": ["-c", "echo hi"],
        \\      "WorkingDirectory": "/var/task"
        \\    }
        \\  }
        \\}
    ;
    var cfg = try parseFunctionConfiguration(std.testing.allocator, body);
    defer cfg.deinit();

    try std.testing.expectEqualStrings("arm64", cfg.architectures[0]);
    try std.testing.expectEqualStrings("EniLimitExceeded", cfg.last_update_status_reason_code);
    try std.testing.expectEqualStrings("arn:aws:kms:us-east-1:123:key/abc", cfg.kms_key_arn);
    try std.testing.expectEqualStrings("arn:aws:signer:us-east-1:123:signing-jobs/xyz", cfg.signing_job_arn);
    try std.testing.expectEqualStrings("Active", cfg.tracing_mode);
    try std.testing.expectEqualStrings("arn:aws:lambda:us-east-1::runtime:abc", cfg.runtime_version_arn);
    try std.testing.expectEqualStrings("arn:aws:sqs:us-east-1:123:dlq", cfg.dead_letter_target_arn);

    const vc = cfg.vpc_config.?;
    try std.testing.expectEqualStrings("vpc-abc123", vc.vpc_id);
    try std.testing.expectEqual(@as(usize, 2), vc.subnet_ids.len);
    try std.testing.expectEqualStrings("subnet-1", vc.subnet_ids[0]);
    try std.testing.expectEqualStrings("subnet-2", vc.subnet_ids[1]);
    try std.testing.expectEqual(@as(usize, 1), vc.security_group_ids.len);
    try std.testing.expectEqualStrings("sg-1", vc.security_group_ids[0]);
    try std.testing.expectEqual(false, vc.ipv6_allowed_for_dual_stack);

    try std.testing.expect(cfg.environment != null);
    try std.testing.expectEqualStrings("bar", cfg.environment.?.variables.get("FOO").?);

    try std.testing.expectEqual(@as(usize, 1), cfg.layers.len);
    try std.testing.expectEqual(@as(i64, 4096), cfg.layers[0].code_size);

    const lc = cfg.logging_config.?;
    try std.testing.expectEqualStrings("JSON", lc.log_format);
    try std.testing.expectEqualStrings("/aws/lambda/full-fn", lc.log_group);

    const ss = cfg.snap_start.?;
    try std.testing.expectEqualStrings("PublishedVersions", ss.apply_on);
    try std.testing.expectEqualStrings("On", ss.optimization_status);

    const ic = cfg.image_config.?;
    try std.testing.expectEqual(@as(usize, 1), ic.entry_point.len);
    try std.testing.expectEqualStrings("/bin/sh", ic.entry_point[0]);
    try std.testing.expectEqual(@as(usize, 2), ic.command.len);
    try std.testing.expectEqualStrings("/var/task", ic.working_directory);
}
