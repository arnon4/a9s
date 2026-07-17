const std = @import("std");
const Allocator = std.mem.Allocator;

const sigv4 = @import("../../../sig/sigv4.zig");
const aws_errors = @import("../../aws_errors.zig");

pub const listFunctionsError = error{ResourceNotFoundException};

pub const Params = struct {
    /// Pass "ALL" to include all published versions plus $LATEST.
    function_version: ?[]const u8 = null,
    marker: ?[]const u8 = null,
    master_region: ?[]const u8 = null,
    max_items: ?u32 = null,
};

pub const Options = struct {
    query_params: Params = .{},
};

pub const Function = struct {
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

    pub fn deinit(self: Function) void {
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
        for (self.architectures) |a| self.allocator.free(a);
        self.allocator.free(self.architectures);
    }

    pub fn clone(self: Function, allocator: Allocator) !Function {
        const function_name = try allocator.dupe(u8, self.function_name);
        errdefer allocator.free(function_name);
        const function_arn = try allocator.dupe(u8, self.function_arn);
        errdefer allocator.free(function_arn);
        const runtime = try allocator.dupe(u8, self.runtime);
        errdefer allocator.free(runtime);
        const role = try allocator.dupe(u8, self.role);
        errdefer allocator.free(role);
        const handler = try allocator.dupe(u8, self.handler);
        errdefer allocator.free(handler);
        const description = try allocator.dupe(u8, self.description);
        errdefer allocator.free(description);
        const last_modified = try allocator.dupe(u8, self.last_modified);
        errdefer allocator.free(last_modified);
        const code_sha256 = try allocator.dupe(u8, self.code_sha256);
        errdefer allocator.free(code_sha256);
        const version = try allocator.dupe(u8, self.version);
        errdefer allocator.free(version);
        const package_type = try allocator.dupe(u8, self.package_type);
        errdefer allocator.free(package_type);
        const state = try allocator.dupe(u8, self.state);
        errdefer allocator.free(state);

        var archs = try allocator.alloc([]u8, self.architectures.len);
        var archs_count: usize = 0;
        errdefer {
            for (archs[0..archs_count]) |a| allocator.free(a);
            allocator.free(archs);
        }
        for (self.architectures) |a| {
            archs[archs_count] = try allocator.dupe(u8, a);
            archs_count += 1;
        }

        return .{
            .allocator = allocator,
            .function_name = function_name,
            .function_arn = function_arn,
            .runtime = runtime,
            .role = role,
            .handler = handler,
            .code_size = self.code_size,
            .description = description,
            .timeout = self.timeout,
            .memory_size = self.memory_size,
            .last_modified = last_modified,
            .code_sha256 = code_sha256,
            .version = version,
            .package_type = package_type,
            .architectures = archs,
            .state = state,
        };
    }
};

pub const Result = struct {
    allocator: Allocator,
    functions: []Function,
    next_marker: ?[]u8,

    pub fn deinit(self: Result) void {
        for (self.functions) |f| f.deinit();
        self.allocator.free(self.functions);
        if (self.next_marker) |m| self.allocator.free(m);
    }
};

pub fn listFunctions(client: anytype, options: Options) !Result {
    var query: std.ArrayList(u8) = .empty;
    defer query.deinit(client.allocator);

    var first = true;
    const p = options.query_params;

    inline for (.{
        .{ "FunctionVersion", p.function_version },
        .{ "Marker", p.marker },
        .{ "MasterRegion", p.master_region },
    }) |pair| {
        if (pair[1]) |v| {
            try query.appendSlice(client.allocator, if (first) "?" else "&");
            first = false;
            try query.appendSlice(client.allocator, pair[0]);
            try query.append(client.allocator, '=');
            try query.appendSlice(client.allocator, v);
        }
    }

    if (p.max_items) |mi| {
        try query.appendSlice(client.allocator, if (first) "?" else "&");
        first = false;
        const s = try std.fmt.allocPrint(client.allocator, "MaxItems={d}", .{mi});
        defer client.allocator.free(s);
        try query.appendSlice(client.allocator, s);
    }

    const request_url = try std.fmt.allocPrint(
        client.allocator,
        "{s}/2015-03-31/functions{s}",
        .{ client.endpoint, query.items },
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
            std.log.err("Lambda ListFunctions error: {s} (status {d})", .{ c, @intFromEnum(result.status) });
            inline for (@typeInfo(listFunctionsError).error_set.?) |entry| {
                if (std.mem.eql(u8, entry.name, c)) return @field(listFunctionsError, entry.name);
            }
            return aws_errors.fromCode(c) orelse aws_errors.fromStatus(result.status);
        }
        return aws_errors.fromStatus(result.status);
    }

    return parseFunctions(client.allocator, resp_body);
}

/// Extract a string field value from a flat JSON object.
/// Returns a caller-owned duplicate, or error if not found.
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

fn parseFunctions(allocator: Allocator, body: []const u8) !Result {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    const root = switch (parsed.value) {
        .object => |o| o,
        else => return error.UnexpectedJsonType,
    };

    var functions: std.ArrayList(Function) = .empty;
    errdefer {
        for (functions.items) |f| f.deinit();
        functions.deinit(allocator);
    }

    if (root.get("Functions")) |funcs_val| {
        switch (funcs_val) {
            .array => |arr| {
                for (arr.items) |item| {
                    switch (item) {
                        .object => |obj| {
                            const f = try parseFunction(allocator, obj);
                            errdefer f.deinit();
                            try functions.append(allocator, f);
                        },
                        else => {},
                    }
                }
            },
            else => {},
        }
    }

    const next_marker: ?[]u8 = blk: {
        const v = root.get("NextMarker") orelse break :blk null;
        switch (v) {
            .string => |s| break :blk try allocator.dupe(u8, s),
            else => break :blk null,
        }
    };
    errdefer if (next_marker) |m| allocator.free(m);

    return .{
        .allocator = allocator,
        .functions = try functions.toOwnedSlice(allocator),
        .next_marker = next_marker,
    };
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

fn parseFunction(allocator: Allocator, obj: std.json.ObjectMap) !Function {
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
    };
}

// ============================================================================
// Tests
// ============================================================================

test "parseFunctions basic" {
    const body =
        \\{
        \\  "Functions": [
        \\    {
        \\      "FunctionName": "my-function",
        \\      "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:my-function",
        \\      "Runtime": "python3.12",
        \\      "Role": "arn:aws:iam::123456789012:role/lambda-role",
        \\      "Handler": "index.handler",
        \\      "CodeSize": 1024,
        \\      "Description": "A test function",
        \\      "Timeout": 30,
        \\      "MemorySize": 128,
        \\      "LastModified": "2024-01-15T10:30:00.000+0000",
        \\      "CodeSha256": "abc123",
        \\      "Version": "$LATEST",
        \\      "PackageType": "Zip",
        \\      "Architectures": ["x86_64"],
        \\      "State": "Active"
        \\    }
        \\  ]
        \\}
    ;
    const result = try parseFunctions(std.testing.allocator, body);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.functions.len);
    const f = result.functions[0];
    try std.testing.expectEqualStrings("my-function", f.function_name);
    try std.testing.expectEqualStrings("python3.12", f.runtime);
    try std.testing.expectEqualStrings("index.handler", f.handler);
    try std.testing.expectEqual(@as(i64, 1024), f.code_size);
    try std.testing.expectEqual(@as(u32, 30), f.timeout);
    try std.testing.expectEqual(@as(u32, 128), f.memory_size);
    try std.testing.expectEqualStrings("$LATEST", f.version);
    try std.testing.expectEqualStrings("Active", f.state);
    try std.testing.expectEqual(@as(usize, 1), f.architectures.len);
    try std.testing.expectEqualStrings("x86_64", f.architectures[0]);
    try std.testing.expect(result.next_marker == null);
}

test "parseFunctions with NextMarker" {
    const body =
        \\{
        \\  "Functions": [],
        \\  "NextMarker": "token-xyz"
        \\}
    ;
    const result = try parseFunctions(std.testing.allocator, body);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 0), result.functions.len);
    try std.testing.expect(result.next_marker != null);
    try std.testing.expectEqualStrings("token-xyz", result.next_marker.?);
}

test "parseFunctions multiple architectures" {
    const body =
        \\{
        \\  "Functions": [
        \\    {
        \\      "FunctionName": "arm-fn",
        \\      "FunctionArn": "arn:aws:lambda:us-east-1:123:function:arm-fn",
        \\      "Runtime": "nodejs20.x",
        \\      "Role": "arn:aws:iam::123:role/r",
        \\      "Handler": "index.handler",
        \\      "CodeSize": 512,
        \\      "Description": "",
        \\      "Timeout": 15,
        \\      "MemorySize": 256,
        \\      "LastModified": "2024-06-01T00:00:00.000+0000",
        \\      "CodeSha256": "def456",
        \\      "Version": "$LATEST",
        \\      "PackageType": "Zip",
        \\      "Architectures": ["arm64"],
        \\      "State": "Active"
        \\    }
        \\  ]
        \\}
    ;
    const result = try parseFunctions(std.testing.allocator, body);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.functions.len);
    try std.testing.expectEqualStrings("arm64", result.functions[0].architectures[0]);
}
