const std = @import("std");
const Allocator = std.mem.Allocator;

const sigv4 = @import("../../../sig/sigv4.zig");
const xml = @import("../../../utils/xml.zig");
const aws_errors = @import("../../aws_errors.zig");

pub const IamGenerateCredentialReportError = error{
    LimitExceededException,
    ServiceFailureException,
};

pub const ReportState = enum { STARTED, INPROGRESS, COMPLETE, UNKNOWN };

pub const GenerateCredentialReportResult = struct {
    allocator: Allocator,
    state: ReportState,
    description: []u8,

    pub fn deinit(self: GenerateCredentialReportResult) void {
        self.allocator.free(self.description);
    }
};

pub fn generateCredentialReport(client: anytype) !GenerateCredentialReportResult {
    const body = "Action=GenerateCredentialReport&Version=2010-05-08";

    var extra_headers = std.StringHashMap([]const u8).init(client.allocator);
    defer extra_headers.deinit();
    try extra_headers.put("Content-Type", "application/x-www-form-urlencoded");
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
            .service = "iam",
            .include_sha256_header = false,
        },
        .POST,
        client.endpoint,
        extra_headers,
        body,
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
        .method = .POST,
        .location = .{ .url = client.endpoint },
        .extra_headers = header_list.items,
        .payload = body,
        .response_writer = &resp_writer.writer,
    });

    const resp_body = resp_writer.writer.buffer[0..resp_writer.writer.end];

    if (result.status != .ok) {
        const code = xml.extractTagContent(client.allocator, resp_body, "Code") catch {
            std.log.err("IAM GenerateCredentialReport error: status {d}", .{@intFromEnum(result.status)});
            return aws_errors.fromStatus(result.status);
        };
        defer client.allocator.free(code);
        std.log.err("IAM GenerateCredentialReport error: {s} (status {d})", .{ code, @intFromEnum(result.status) });
        inline for (@typeInfo(IamGenerateCredentialReportError).error_set.?) |entry| {
            if (std.mem.eql(u8, entry.name, code)) return @field(IamGenerateCredentialReportError, entry.name);
        }
        return aws_errors.fromCode(code) orelse aws_errors.fromStatus(result.status);
    }

    return parseResponse(client.allocator, resp_body);
}

fn parseState(s: []const u8) ReportState {
    if (std.mem.eql(u8, s, "STARTED")) return .STARTED;
    if (std.mem.eql(u8, s, "INPROGRESS")) return .INPROGRESS;
    if (std.mem.eql(u8, s, "COMPLETE")) return .COMPLETE;
    return .UNKNOWN;
}

fn parseResponse(allocator: Allocator, body: []const u8) !GenerateCredentialReportResult {
    const state_str = xml.extractTagContent(allocator, body, "State") catch try allocator.dupe(u8, "");
    defer allocator.free(state_str);
    const description = xml.extractTagContent(allocator, body, "Description") catch try allocator.dupe(u8, "");

    return .{
        .allocator = allocator,
        .state = parseState(state_str),
        .description = description,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "parseResponse started" {
    const body =
        \\<GenerateCredentialReportResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        \\  <GenerateCredentialReportResult>
        \\    <State>STARTED</State>
        \\    <Description>No report exists. Starting a new report generation task</Description>
        \\  </GenerateCredentialReportResult>
        \\</GenerateCredentialReportResponse>
    ;
    const result = try parseResponse(std.testing.allocator, body);
    defer result.deinit();
    try std.testing.expectEqual(ReportState.STARTED, result.state);
}

test "parseResponse complete" {
    const body =
        \\<GenerateCredentialReportResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        \\  <GenerateCredentialReportResult>
        \\    <State>COMPLETE</State>
        \\  </GenerateCredentialReportResult>
        \\</GenerateCredentialReportResponse>
    ;
    const result = try parseResponse(std.testing.allocator, body);
    defer result.deinit();
    try std.testing.expectEqual(ReportState.COMPLETE, result.state);
}
