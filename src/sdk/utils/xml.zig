const std = @import("std");
const Allocator = std.mem.Allocator;

/// Extract the text content of the first matching tag in xml.
/// Handles attributes (<Tag attr="val">content</Tag>) and self-closing tags
/// (<Tag .../> returns empty string). Returns a caller-owned,
/// XML-entity-unescaped duplicate, or error.XmlTagNotFound.
pub fn extractTagContent(allocator: Allocator, xml: []const u8, tag: []const u8) ![]u8 {
    const open_prefix = try std.fmt.allocPrint(allocator, "<{s}", .{tag});
    defer allocator.free(open_prefix);
    const close = try std.fmt.allocPrint(allocator, "</{s}>", .{tag});
    defer allocator.free(close);

    // Find <Tag followed immediately by '>', whitespace, or '/'
    var search = xml;
    const tag_start = while (std.mem.indexOf(u8, search, open_prefix)) |idx| {
        const after = idx + open_prefix.len;
        if (after >= search.len) break null;
        const next = search[after];
        if (next == '>' or next == '/' or std.ascii.isWhitespace(next)) break idx;
        search = search[idx + 1 ..];
    } else null;

    const start = tag_start orelse return error.XmlTagNotFound;
    const after_name = search[start + open_prefix.len ..];

    // Skip to end of opening tag
    const gt = std.mem.indexOfScalar(u8, after_name, '>') orelse return error.XmlTagNotFound;
    // Self-closing: <Tag ... />
    if (gt > 0 and after_name[gt - 1] == '/') return unescapeEntities(allocator, "");

    const content_start = gt + 1;
    const end = std.mem.indexOf(u8, after_name[content_start..], close) orelse return error.XmlTagNotFound;

    return unescapeEntities(allocator, after_name[content_start .. content_start + end]);
}

fn unescapeEntities(allocator: Allocator, input: []const u8) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    var i: usize = 0;
    while (i < input.len) {
        if (input[i] != '&') {
            try out.append(allocator, input[i]);
            i += 1;
            continue;
        }
        const semi = std.mem.indexOfScalarPos(u8, input, i + 1, ';') orelse {
            try out.append(allocator, input[i]);
            i += 1;
            continue;
        };
        const entity = input[i + 1 .. semi];
        const replacement: ?u8 = if (std.mem.eql(u8, entity, "amp"))
            '&'
        else if (std.mem.eql(u8, entity, "lt"))
            '<'
        else if (std.mem.eql(u8, entity, "gt"))
            '>'
        else if (std.mem.eql(u8, entity, "quot"))
            '"'
        else if (std.mem.eql(u8, entity, "apos"))
            '\''
        else
            null;

        if (replacement) |r| {
            try out.append(allocator, r);
            i = semi + 1;
        } else {
            try out.append(allocator, input[i]);
            i += 1;
        }
    }
    return out.toOwnedSlice(allocator);
}

// ============================================================================
// Tests
// ============================================================================

test "extractTagContent finds content" {
    const allocator = std.testing.allocator;
    const xml = "<Foo>hello</Foo><Bar>world</Bar>";
    const val = try extractTagContent(allocator, xml, "Bar");
    defer allocator.free(val);
    try std.testing.expectEqualStrings("world", val);
}

test "extractTagContent missing tag returns error" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.XmlTagNotFound, extractTagContent(allocator, "<A>x</A>", "B"));
}

test "extractTagContent returns first match" {
    const allocator = std.testing.allocator;
    const xml = "<X>first</X><X>second</X>";
    const val = try extractTagContent(allocator, xml, "X");
    defer allocator.free(val);
    try std.testing.expectEqualStrings("first", val);
}

test "extractTagContent unescapes entities" {
    const allocator = std.testing.allocator;
    const xml = "<ETag>&quot;abc123&quot;</ETag>";
    const val = try extractTagContent(allocator, xml, "ETag");
    defer allocator.free(val);
    try std.testing.expectEqualStrings("\"abc123\"", val);
}

test "unescapeEntities all standard entities" {
    const allocator = std.testing.allocator;
    const val = try unescapeEntities(allocator, "&amp;&lt;&gt;&quot;&apos;");
    defer allocator.free(val);
    try std.testing.expectEqualStrings("&<>\"'", val);
}

test "unescapeEntities unknown entity left as-is" {
    const allocator = std.testing.allocator;
    const val = try unescapeEntities(allocator, "&unknown;text");
    defer allocator.free(val);
    try std.testing.expectEqualStrings("&unknown;text", val);
}

test "extractTagContent handles tag with attributes" {
    const allocator = std.testing.allocator;
    const doc = "<LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">eu-west-1</LocationConstraint>";
    const val = try extractTagContent(allocator, doc, "LocationConstraint");
    defer allocator.free(val);
    try std.testing.expectEqualStrings("eu-west-1", val);
}

test "extractTagContent handles self-closing tag" {
    const allocator = std.testing.allocator;
    const doc = "<LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"/>";
    const val = try extractTagContent(allocator, doc, "LocationConstraint");
    defer allocator.free(val);
    try std.testing.expectEqualStrings("", val);
}

test "extractTagContent does not match tag prefix" {
    const allocator = std.testing.allocator;
    const doc = "<FooBar>wrong</FooBar><Foo>right</Foo>";
    const val = try extractTagContent(allocator, doc, "Foo");
    defer allocator.free(val);
    try std.testing.expectEqualStrings("right", val);
}
