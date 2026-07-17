const std = @import("std");
const Allocator = std.mem.Allocator;

const sigv4 = @import("../../../sig/sigv4.zig");
const xml = @import("../../../utils/xml.zig");
const aws_errors = @import("../../aws_errors.zig");

pub const IamGetCredentialReportError = error{
    ReportNotPresentException,
    ReportInProgressException,
    ReportExpiredException,
    ServiceFailureException,
};

pub const GetCredentialReportResult = struct {
    allocator: Allocator,
    /// Decoded CSV content (the API returns it base64-encoded).
    content: []u8,
    report_format: []u8,
    generated_time: []u8,

    pub fn deinit(self: GetCredentialReportResult) void {
        self.allocator.free(self.content);
        self.allocator.free(self.report_format);
        self.allocator.free(self.generated_time);
    }
};

pub fn getCredentialReport(client: anytype) !GetCredentialReportResult {
    const body = "Action=GetCredentialReport&Version=2010-05-08";

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
            std.log.err("IAM GetCredentialReport error: status {d}", .{@intFromEnum(result.status)});
            return aws_errors.fromStatus(result.status);
        };
        defer client.allocator.free(code);
        std.log.err("IAM GetCredentialReport error: {s} (status {d})", .{ code, @intFromEnum(result.status) });
        inline for (@typeInfo(IamGetCredentialReportError).error_set.?) |entry| {
            if (std.mem.eql(u8, entry.name, code)) return @field(IamGetCredentialReportError, entry.name);
        }
        return aws_errors.fromCode(code) orelse aws_errors.fromStatus(result.status);
    }

    return parseResponse(client.allocator, resp_body);
}

fn xmlStr(allocator: Allocator, src: []const u8, tag: []const u8) ![]u8 {
    return xml.extractTagContent(allocator, src, tag) catch try allocator.dupe(u8, "");
}

fn decodeBase64(allocator: Allocator, encoded: []const u8) ![]u8 {
    const decoder = std.base64.standard.Decoder;
    const size = try decoder.calcSizeForSlice(encoded);
    const out = try allocator.alloc(u8, size);
    errdefer allocator.free(out);
    try decoder.decode(out, encoded);
    return out;
}

fn parseResponse(allocator: Allocator, body: []const u8) !GetCredentialReportResult {
    const encoded_content = try xmlStr(allocator, body, "Content");
    defer allocator.free(encoded_content);
    const content = try decodeBase64(allocator, encoded_content);
    errdefer allocator.free(content);

    const report_format = try xmlStr(allocator, body, "ReportFormat");
    errdefer allocator.free(report_format);
    const generated_time = try xmlStr(allocator, body, "GeneratedTime");
    errdefer allocator.free(generated_time);

    return .{
        .allocator = allocator,
        .content = content,
        .report_format = report_format,
        .generated_time = generated_time,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "parseResponse decodes base64 csv content" {
    // "user,arn\nalice,arn:aws:iam::123:user/alice\n" base64-encoded.
    const body =
        \\<GetCredentialReportResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        \\  <GetCredentialReportResult>
        \\    <Content>dXNlcixhcm4KYWxpY2UsYXJuOmF3czppYW06OjEyMzp1c2VyL2FsaWNlCg==</Content>
        \\    <ReportFormat>text/csv</ReportFormat>
        \\    <GeneratedTime>2024-01-01T00:00:00Z</GeneratedTime>
        \\  </GetCredentialReportResult>
        \\</GetCredentialReportResponse>
    ;
    const result = try parseResponse(std.testing.allocator, body);
    defer result.deinit();
    try std.testing.expectEqualStrings("user,arn\nalice,arn:aws:iam::123:user/alice\n", result.content);
    try std.testing.expectEqualStrings("text/csv", result.report_format);
    try std.testing.expectEqualStrings("2024-01-01T00:00:00Z", result.generated_time);
}
