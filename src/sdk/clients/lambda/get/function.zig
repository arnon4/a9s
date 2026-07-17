const std = @import("std");
const Allocator = std.mem.Allocator;

const sigv4 = @import("../../../sig/sigv4.zig");
const aws_errors = @import("../../aws_errors.zig");

pub const getFunctionError = error{ResourceNotFoundException};

pub const Options = struct {
    function_name: []const u8,
    qualifier: ?[]const u8 = null,
};

pub const FunctionCodeLocation = struct {
    allocator: Allocator,
    /// Presigned URL for the deployment package ZIP. Empty for container image functions.
    location: []u8,
    repository_type: []u8,
    /// Container image URI (container image functions only).
    image_uri: []u8,
    resolved_image_uri: []u8,
    source_kms_key_arn: []u8,

    pub fn deinit(self: FunctionCodeLocation) void {
        self.allocator.free(self.location);
        self.allocator.free(self.repository_type);
        self.allocator.free(self.image_uri);
        self.allocator.free(self.resolved_image_uri);
        self.allocator.free(self.source_kms_key_arn);
    }
};

pub const GetFunctionResult = struct {
    allocator: Allocator,
    code: FunctionCodeLocation,
    /// null means no reserved concurrency limit is set.
    reserved_concurrent_executions: ?i64,
    tags: std.StringHashMap([]u8),
    tags_error_code: []u8,
    tags_error_message: []u8,
    // Note: GetFunction also returns a Configuration object identical to
    // GetFunctionConfiguration. Use getFunctionConfiguration for that data.

    pub fn deinit(self: *GetFunctionResult) void {
        self.code.deinit();
        var iter = self.tags.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.tags.deinit();
        self.allocator.free(self.tags_error_code);
        self.allocator.free(self.tags_error_message);
    }
};

pub fn getFunction(client: anytype, options: Options) !GetFunctionResult {
    const qualifier_suffix = if (options.qualifier) |q|
        try std.fmt.allocPrint(client.allocator, "?Qualifier={s}", .{q})
    else
        try client.allocator.dupe(u8, "");
    defer client.allocator.free(qualifier_suffix);

    const request_url = try std.fmt.allocPrint(
        client.allocator,
        "{s}/2015-03-31/functions/{s}{s}",
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
        return aws_errors.fromStatus(result.status);
    }

    return parseGetFunctionResult(client.allocator, resp_body);
}

fn jsonStr(obj: std.json.ObjectMap, key: []const u8) []const u8 {
    const v = obj.get(key) orelse return "";
    return switch (v) {
        .string => |s| s,
        else => "",
    };
}

fn jsonOptInt(comptime T: type, obj: std.json.ObjectMap, key: []const u8) ?T {
    const v = obj.get(key) orelse return null;
    return switch (v) {
        .integer => |n| @intCast(n),
        .float => |f| @intFromFloat(f),
        else => null,
    };
}

fn parseGetFunctionResult(allocator: Allocator, body: []const u8) !GetFunctionResult {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    const root = switch (parsed.value) {
        .object => |o| o,
        else => return error.UnexpectedJsonType,
    };

    // Parse Code object
    const code_obj: ?std.json.ObjectMap = if (root.get("Code")) |v| switch (v) {
        .object => |o| o,
        else => null,
    } else null;

    const location = try allocator.dupe(u8, if (code_obj) |o| jsonStr(o, "Location") else "");
    errdefer allocator.free(location);
    const repository_type = try allocator.dupe(u8, if (code_obj) |o| jsonStr(o, "RepositoryType") else "");
    errdefer allocator.free(repository_type);
    const image_uri = try allocator.dupe(u8, if (code_obj) |o| jsonStr(o, "ImageUri") else "");
    errdefer allocator.free(image_uri);
    const resolved_image_uri = try allocator.dupe(u8, if (code_obj) |o| jsonStr(o, "ResolvedImageUri") else "");
    errdefer allocator.free(resolved_image_uri);
    const source_kms_key_arn = try allocator.dupe(u8, if (code_obj) |o| jsonStr(o, "SourceKMSKeyArn") else "");
    errdefer allocator.free(source_kms_key_arn);

    // Parse Concurrency
    const reserved_concurrent_executions: ?i64 = if (root.get("Concurrency")) |v| switch (v) {
        .object => |o| jsonOptInt(i64, o, "ReservedConcurrentExecutions"),
        else => null,
    } else null;

    // Parse Tags
    var tags = std.StringHashMap([]u8).init(allocator);
    errdefer {
        var ti = tags.iterator();
        while (ti.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        tags.deinit();
    }
    if (root.get("Tags")) |v| {
        if (v == .object) {
            var ti = v.object.iterator();
            while (ti.next()) |entry| {
                const k = try allocator.dupe(u8, entry.key_ptr.*);
                errdefer allocator.free(k);
                const val_str = switch (entry.value_ptr.*) {
                    .string => |s| s,
                    else => "",
                };
                const tv = try allocator.dupe(u8, val_str);
                errdefer allocator.free(tv);
                try tags.put(k, tv);
            }
        }
    }

    // Parse TagsError
    const tags_error_code = try allocator.dupe(u8, if (root.get("TagsError")) |v| switch (v) {
        .object => |o| jsonStr(o, "ErrorCode"),
        else => "",
    } else "");
    errdefer allocator.free(tags_error_code);
    const tags_error_message = try allocator.dupe(u8, if (root.get("TagsError")) |v| switch (v) {
        .object => |o| jsonStr(o, "Message"),
        else => "",
    } else "");
    errdefer allocator.free(tags_error_message);

    return .{
        .allocator = allocator,
        .code = .{
            .allocator = allocator,
            .location = location,
            .repository_type = repository_type,
            .image_uri = image_uri,
            .resolved_image_uri = resolved_image_uri,
            .source_kms_key_arn = source_kms_key_arn,
        },
        .reserved_concurrent_executions = reserved_concurrent_executions,
        .tags = tags,
        .tags_error_code = tags_error_code,
        .tags_error_message = tags_error_message,
    };
}
