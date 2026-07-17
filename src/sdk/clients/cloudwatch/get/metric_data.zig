const std = @import("std");
const Allocator = std.mem.Allocator;

const sigv4 = @import("../../../sig/sigv4.zig");
const uri_utils = @import("../../../utils/uri.zig");
const Credentials = @import("../../../credentials/fetcher.zig").Credentials;
const xml = @import("../../../utils/xml.zig");
const time_utils = @import("../../../utils/time.zig");

// ============================================================================
// Types
// ============================================================================

pub const Dimension = struct {
    name: []const u8,
    value: []const u8,
};

pub const Metric = struct {
    namespace: []const u8,
    metric_name: []const u8,
    dimensions: []const Dimension = &.{},
};

pub const Unit = enum {
    seconds,
    microseconds,
    milliseconds,
    bytes,
    kilobytes,
    megabytes,
    gigabytes,
    terabytes,
    bits,
    kilobits,
    megabits,
    gigabits,
    terabits,
    percent,
    count,
    bytes_per_second,
    kilobytes_per_second,
    megabytes_per_second,
    gigabytes_per_second,
    terabytes_per_second,
    bits_per_second,
    kilobits_per_second,
    megabits_per_second,
    gigabits_per_second,
    terabits_per_second,
    count_per_second,
    none,

    pub fn wireValue(self: Unit) []const u8 {
        return switch (self) {
            .seconds => "Seconds",
            .microseconds => "Microseconds",
            .milliseconds => "Milliseconds",
            .bytes => "Bytes",
            .kilobytes => "Kilobytes",
            .megabytes => "Megabytes",
            .gigabytes => "Gigabytes",
            .terabytes => "Terabytes",
            .bits => "Bits",
            .kilobits => "Kilobits",
            .megabits => "Megabits",
            .gigabits => "Gigabits",
            .terabits => "Terabits",
            .percent => "Percent",
            .count => "Count",
            .bytes_per_second => "Bytes/Second",
            .kilobytes_per_second => "Kilobytes/Second",
            .megabytes_per_second => "Megabytes/Second",
            .gigabytes_per_second => "Gigabytes/Second",
            .terabytes_per_second => "Terabytes/Second",
            .bits_per_second => "Bits/Second",
            .kilobits_per_second => "Kilobits/Second",
            .megabits_per_second => "Megabits/Second",
            .gigabits_per_second => "Gigabits/Second",
            .terabits_per_second => "Terabits/Second",
            .count_per_second => "Count/Second",
            .none => "None",
        };
    }
};

pub const ScanBy = enum {
    timestamp_ascending,
    timestamp_descending,

    pub fn wireValue(self: ScanBy) []const u8 {
        return switch (self) {
            .timestamp_ascending => "TimestampAscending",
            .timestamp_descending => "TimestampDescending",
        };
    }
};

pub const StatusCode = enum {
    complete,
    partial_data,
    internal_error,
    forbidden,
    unknown,

    fn parse(s: []const u8) StatusCode {
        if (std.mem.eql(u8, s, "Complete")) return .complete;
        if (std.mem.eql(u8, s, "PartialData")) return .partial_data;
        if (std.mem.eql(u8, s, "InternalError")) return .internal_error;
        if (std.mem.eql(u8, s, "Forbidden")) return .forbidden;
        return .unknown;
    }
};

pub const MetricStat = struct {
    metric: Metric,
    period: u32,
    stat: []const u8,
    unit: ?Unit = null,
};

pub const MetricDataQuery = struct {
    id: []const u8,
    /// Exactly one of metric_stat or expression must be set.
    metric_stat: ?MetricStat = null,
    expression: ?[]const u8 = null,
    label: ?[]const u8 = null,
    period: ?u32 = null,
    return_data: bool = true,
    account_id: ?[]const u8 = null,
};

pub const Options = struct {
    start_time: i64,
    end_time: i64,
    queries: []const MetricDataQuery,
    max_datapoints: ?u32 = null,
    next_token: ?[]const u8 = null,
    scan_by: ?ScanBy = null,
    label_options_timezone: ?[]const u8 = null,
};

pub const MessageData = struct {
    code: []u8,
    value: []u8,

    pub fn deinit(self: MessageData, allocator: Allocator) void {
        allocator.free(self.code);
        allocator.free(self.value);
    }
};

pub const MetricDataResult = struct {
    id: []u8,
    label: []u8,
    status_code: StatusCode,
    timestamps: []i64,
    values: []f64,
    messages: []MessageData,

    pub fn deinit(self: MetricDataResult, allocator: Allocator) void {
        allocator.free(self.id);
        allocator.free(self.label);
        allocator.free(self.timestamps);
        allocator.free(self.values);
        for (self.messages) |m| m.deinit(allocator);
        allocator.free(self.messages);
    }
};

pub const Result = struct {
    allocator: Allocator,
    metric_data_results: []MetricDataResult,
    next_token: ?[]u8 = null,

    pub fn deinit(self: Result) void {
        for (self.metric_data_results) |r| r.deinit(self.allocator);
        self.allocator.free(self.metric_data_results);
        if (self.next_token) |t| self.allocator.free(t);
    }
};

// ============================================================================
// Public API
// ============================================================================

pub fn getMetricData(client: anytype, options: Options) !Result {
    return getMetricDataWithIo(
        client.allocator,
        client.io,
        client.credentials,
        client.region,
        client.endpoint,
        options,
    );
}

pub fn getMetricDataWithIo(
    allocator: Allocator,
    io: std.Io,
    credentials: Credentials,
    region: []const u8,
    endpoint: []const u8,
    options: Options,
) !Result {
    const body = try buildBody(allocator, options);
    defer allocator.free(body);

    var extra_headers = std.StringHashMap([]const u8).init(allocator);
    defer extra_headers.deinit();
    try extra_headers.put("Content-Type", "application/x-www-form-urlencoded");
    if (credentials.session_token) |token| {
        try extra_headers.put("X-Amz-Security-Token", token);
    }

    var signed = try sigv4.sign(
        allocator,
        io,
        .{
            .access_key = credentials.access_key_id,
            .secret_key = credentials.secret_access_key,
            .region = region,
            .service = "monitoring",
        },
        .POST,
        endpoint,
        extra_headers,
        body,
        null,
    );
    defer signed.deinit();

    var header_list: std.ArrayList(std.http.Header) = .empty;
    defer header_list.deinit(allocator);
    var it = signed.headers.iterator();
    while (it.next()) |entry| {
        if (std.ascii.eqlIgnoreCase(entry.key_ptr.*, "host")) continue;
        try header_list.append(allocator, .{ .name = entry.key_ptr.*, .value = entry.value_ptr.* });
    }

    var http_client = std.http.Client{ .allocator = allocator, .io = io };
    defer http_client.deinit();

    var body_writer: std.Io.Writer.Allocating = .init(allocator);
    defer body_writer.deinit();

    const result = try http_client.fetch(.{
        .method = .POST,
        .location = .{ .url = endpoint },
        .extra_headers = header_list.items,
        .payload = body,
        .response_writer = &body_writer.writer,
    });

    const response_body = body_writer.writer.buffer[0..body_writer.writer.end];

    if (result.status != .ok) {
        std.log.err("CloudWatch GetMetricData failed: status={} body={s}", .{ result.status, response_body });
        return error.CloudWatchRequestFailed;
    }

    return parseResponse(allocator, response_body);
}

// ============================================================================
// Request body builder
// ============================================================================

fn formatIso8601(allocator: Allocator, ts: i64) ![]u8 {
    const compact = try time_utils.secondsToDate(allocator, ts);
    defer allocator.free(compact);
    // compact = "YYYYMMDDTHHMMSSZ"
    return std.fmt.allocPrint(allocator, "{s}-{s}-{s}T{s}:{s}:{s}Z", .{
        compact[0..4],  compact[4..6],   compact[6..8],
        compact[9..11], compact[11..13], compact[13..15],
    });
}

fn appendParam(body: *std.ArrayList(u8), allocator: Allocator, key: []const u8, value: []const u8) !void {
    const enc = try uri_utils.encodeStandard(allocator, value);
    defer allocator.free(enc);
    try body.appendSlice(allocator, "&");
    try body.appendSlice(allocator, key);
    try body.appendSlice(allocator, "=");
    try body.appendSlice(allocator, enc);
}

fn buildBody(allocator: Allocator, options: Options) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);

    var kbuf: [512]u8 = undefined;

    try body.appendSlice(allocator, "Action=GetMetricData&Version=2010-08-01");

    {
        const s = try formatIso8601(allocator, options.start_time);
        defer allocator.free(s);
        try appendParam(&body, allocator, "StartTime", s);
    }
    {
        const s = try formatIso8601(allocator, options.end_time);
        defer allocator.free(s);
        try appendParam(&body, allocator, "EndTime", s);
    }

    for (options.queries, 1..) |q, qi| {
        try appendParam(&body, allocator, try std.fmt.bufPrint(&kbuf, "MetricDataQueries.member.{d}.Id", .{qi}), q.id);

        if (q.metric_stat) |ms| {
            try appendParam(&body, allocator, try std.fmt.bufPrint(&kbuf, "MetricDataQueries.member.{d}.MetricStat.Metric.Namespace", .{qi}), ms.metric.namespace);
            try appendParam(&body, allocator, try std.fmt.bufPrint(&kbuf, "MetricDataQueries.member.{d}.MetricStat.Metric.MetricName", .{qi}), ms.metric.metric_name);
            for (ms.metric.dimensions, 1..) |dim, di| {
                try appendParam(&body, allocator, try std.fmt.bufPrint(&kbuf, "MetricDataQueries.member.{d}.MetricStat.Metric.Dimensions.member.{d}.Name", .{ qi, di }), dim.name);
                try appendParam(&body, allocator, try std.fmt.bufPrint(&kbuf, "MetricDataQueries.member.{d}.MetricStat.Metric.Dimensions.member.{d}.Value", .{ qi, di }), dim.value);
            }
            {
                const p = try std.fmt.allocPrint(allocator, "{d}", .{ms.period});
                defer allocator.free(p);
                try appendParam(&body, allocator, try std.fmt.bufPrint(&kbuf, "MetricDataQueries.member.{d}.MetricStat.Period", .{qi}), p);
            }
            try appendParam(&body, allocator, try std.fmt.bufPrint(&kbuf, "MetricDataQueries.member.{d}.MetricStat.Stat", .{qi}), ms.stat);
            if (ms.unit) |u| {
                try appendParam(&body, allocator, try std.fmt.bufPrint(&kbuf, "MetricDataQueries.member.{d}.MetricStat.Unit", .{qi}), u.wireValue());
            }
        }

        if (q.expression) |expr| {
            try appendParam(&body, allocator, try std.fmt.bufPrint(&kbuf, "MetricDataQueries.member.{d}.Expression", .{qi}), expr);
        }
        if (q.label) |lbl| {
            try appendParam(&body, allocator, try std.fmt.bufPrint(&kbuf, "MetricDataQueries.member.{d}.Label", .{qi}), lbl);
        }
        if (q.period) |p| {
            const p_str = try std.fmt.allocPrint(allocator, "{d}", .{p});
            defer allocator.free(p_str);
            try appendParam(&body, allocator, try std.fmt.bufPrint(&kbuf, "MetricDataQueries.member.{d}.Period", .{qi}), p_str);
        }
        if (!q.return_data) {
            try appendParam(&body, allocator, try std.fmt.bufPrint(&kbuf, "MetricDataQueries.member.{d}.ReturnData", .{qi}), "false");
        }
        if (q.account_id) |aid| {
            try appendParam(&body, allocator, try std.fmt.bufPrint(&kbuf, "MetricDataQueries.member.{d}.AccountId", .{qi}), aid);
        }
    }

    if (options.max_datapoints) |md| {
        const s = try std.fmt.allocPrint(allocator, "{d}", .{md});
        defer allocator.free(s);
        try appendParam(&body, allocator, "MaxDatapoints", s);
    }
    if (options.next_token) |nt| {
        try appendParam(&body, allocator, "NextToken", nt);
    }
    if (options.scan_by) |sb| {
        try appendParam(&body, allocator, "ScanBy", sb.wireValue());
    }
    if (options.label_options_timezone) |tz| {
        try appendParam(&body, allocator, "LabelOptions.Timezone", tz);
    }

    return body.toOwnedSlice(allocator);
}

// ============================================================================
// Response parser
// ============================================================================

// Returns the content of the next top-level <member>...</member> block,
// advancing pos past it. Handles nested <member> tags correctly.
fn nextMember(text: []const u8, pos: *usize) ?[]const u8 {
    const open = "<member>";
    const close = "</member>";

    const start = std.mem.indexOfPos(u8, text, pos.*, open) orelse return null;
    var depth: usize = 1;
    var i = start + open.len;

    while (i < text.len and depth > 0) {
        if (std.mem.startsWith(u8, text[i..], open)) {
            depth += 1;
            i += open.len;
        } else if (std.mem.startsWith(u8, text[i..], close)) {
            depth -= 1;
            if (depth == 0) {
                pos.* = i + close.len;
                return text[start + open.len .. i];
            }
            i += close.len;
        } else {
            i += 1;
        }
    }
    return null;
}

fn parseMessage(allocator: Allocator, block: []const u8) !MessageData {
    const code = xml.extractTagContent(allocator, block, "Code") catch try allocator.dupe(u8, "");
    errdefer allocator.free(code);
    const value = xml.extractTagContent(allocator, block, "Value") catch try allocator.dupe(u8, "");
    return .{ .code = code, .value = value };
}

fn parseMetricDataResult(allocator: Allocator, block: []const u8) !MetricDataResult {
    const id = try xml.extractTagContent(allocator, block, "Id");
    errdefer allocator.free(id);

    const label = xml.extractTagContent(allocator, block, "Label") catch try allocator.dupe(u8, "");
    errdefer allocator.free(label);

    const status_code = blk: {
        const s = xml.extractTagContent(allocator, block, "StatusCode") catch break :blk StatusCode.unknown;
        defer allocator.free(s);
        break :blk StatusCode.parse(s);
    };

    var timestamps: std.ArrayList(i64) = .empty;
    errdefer timestamps.deinit(allocator);
    if (xml.extractTagContent(allocator, block, "Timestamps")) |ts_block| {
        defer allocator.free(ts_block);
        var pos: usize = 0;
        while (nextMember(ts_block, &pos)) |m| {
            const ts = time_utils.parseIso8601ToTimestamp(std.mem.trim(u8, m, " \t\r\n")) orelse continue;
            try timestamps.append(allocator, ts);
        }
    } else |_| {}

    var values: std.ArrayList(f64) = .empty;
    errdefer values.deinit(allocator);
    if (xml.extractTagContent(allocator, block, "Values")) |vals_block| {
        defer allocator.free(vals_block);
        var pos: usize = 0;
        while (nextMember(vals_block, &pos)) |m| {
            const v = std.fmt.parseFloat(f64, std.mem.trim(u8, m, " \t\r\n")) catch continue;
            try values.append(allocator, v);
        }
    } else |_| {}

    var messages: std.ArrayList(MessageData) = .empty;
    errdefer {
        for (messages.items) |m| m.deinit(allocator);
        messages.deinit(allocator);
    }
    if (xml.extractTagContent(allocator, block, "Messages")) |msgs_block| {
        defer allocator.free(msgs_block);
        var pos: usize = 0;
        while (nextMember(msgs_block, &pos)) |m| {
            const msg = parseMessage(allocator, m) catch continue;
            messages.append(allocator, msg) catch |e| {
                msg.deinit(allocator);
                return e;
            };
        }
    } else |_| {}

    return .{
        .id = id,
        .label = label,
        .status_code = status_code,
        .timestamps = try timestamps.toOwnedSlice(allocator),
        .values = try values.toOwnedSlice(allocator),
        .messages = try messages.toOwnedSlice(allocator),
    };
}

fn parseResponse(allocator: Allocator, body: []const u8) !Result {
    var results: std.ArrayList(MetricDataResult) = .empty;
    errdefer {
        for (results.items) |r| r.deinit(allocator);
        results.deinit(allocator);
    }

    if (xml.extractTagContent(allocator, body, "MetricDataResults")) |results_block| {
        defer allocator.free(results_block);
        var pos: usize = 0;
        while (nextMember(results_block, &pos)) |member| {
            const r = try parseMetricDataResult(allocator, member);
            results.append(allocator, r) catch |e| {
                r.deinit(allocator);
                return e;
            };
        }
    } else |_| {}

    const next_token = xml.extractTagContent(allocator, body, "NextToken") catch null;
    errdefer if (next_token) |t| allocator.free(t);

    return .{
        .allocator = allocator,
        .metric_data_results = try results.toOwnedSlice(allocator),
        .next_token = next_token,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "buildBody basic MetricStat query" {
    const allocator = std.testing.allocator;
    const body = try buildBody(allocator, .{
        .start_time = 0,
        .end_time = 3600,
        .queries = &.{.{
            .id = "m1",
            .metric_stat = .{
                .metric = .{
                    .namespace = "AWS/EC2",
                    .metric_name = "CPUUtilization",
                    .dimensions = &.{.{ .name = "InstanceId", .value = "i-1234567890abcdef0" }},
                },
                .period = 300,
                .stat = "Average",
            },
        }},
    });
    defer allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "Action=GetMetricData") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "MetricDataQueries.member.1.Id=m1") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "MetricStat.Metric.Namespace=AWS%2FEC2") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "MetricStat.Metric.MetricName=CPUUtilization") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "Dimensions.member.1.Name=InstanceId") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "MetricStat.Period=300") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "MetricStat.Stat=Average") != null);
}

test "buildBody expression query" {
    const allocator = std.testing.allocator;
    const body = try buildBody(allocator, .{
        .start_time = 0,
        .end_time = 3600,
        .queries = &.{.{
            .id = "q1",
            .expression = "SELECT AVG(CPUUtilization) FROM SCHEMA(\"AWS/EC2\", InstanceId)",
            .period = 300,
        }},
        .scan_by = .timestamp_ascending,
    });
    defer allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "MetricDataQueries.member.1.Expression=") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "ScanBy=TimestampAscending") != null);
}

test "parseResponse parses MetricDataResults" {
    const allocator = std.testing.allocator;
    const response =
        \\<GetMetricDataResponse>
        \\  <GetMetricDataResult>
        \\    <MetricDataResults>
        \\      <member>
        \\        <Id>m1</Id>
        \\        <Label>CPUUtilization</Label>
        \\        <StatusCode>Complete</StatusCode>
        \\        <Timestamps>
        \\          <member>2021-01-01T00:05:00Z</member>
        \\          <member>2021-01-01T00:00:00Z</member>
        \\        </Timestamps>
        \\        <Values>
        \\          <member>0.5</member>
        \\          <member>1.25</member>
        \\        </Values>
        \\        <Messages/>
        \\      </member>
        \\    </MetricDataResults>
        \\  </GetMetricDataResult>
        \\</GetMetricDataResponse>
    ;
    const result = try parseResponse(allocator, response);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.metric_data_results.len);
    const r = result.metric_data_results[0];
    try std.testing.expectEqualStrings("m1", r.id);
    try std.testing.expectEqualStrings("CPUUtilization", r.label);
    try std.testing.expectEqual(StatusCode.complete, r.status_code);
    try std.testing.expectEqual(@as(usize, 2), r.timestamps.len);
    try std.testing.expectEqual(@as(usize, 2), r.values.len);
    try std.testing.expectApproxEqAbs(@as(f64, 0.5), r.values[0], 1e-10);
    try std.testing.expectApproxEqAbs(@as(f64, 1.25), r.values[1], 1e-10);
    try std.testing.expectEqual(@as(?[]u8, null), result.next_token);
}

test "parseResponse handles NextToken" {
    const allocator = std.testing.allocator;
    const response =
        \\<GetMetricDataResponse>
        \\  <GetMetricDataResult>
        \\    <MetricDataResults/>
        \\    <NextToken>abc123token</NextToken>
        \\  </GetMetricDataResult>
        \\</GetMetricDataResponse>
    ;
    const result = try parseResponse(allocator, response);
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 0), result.metric_data_results.len);
    try std.testing.expect(result.next_token != null);
    try std.testing.expectEqualStrings("abc123token", result.next_token.?);
}
