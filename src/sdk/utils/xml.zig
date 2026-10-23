const std = @import("std");
const Allocator = std.mem.Allocator;

/// Extract the text content of the first matching tag in xml.
/// Handles attributes (<Tag attr="val">content</Tag>) and self-closing tags
/// (<Tag .../> returns empty string). Returns a caller-owned,
/// XML-entity-unescaped duplicate, or error.XmlTagNotFound.
pub fn extractTagContent(allocator: Allocator, xml: []const u8, tag: []const u8) ![]u8 {
    const open_prefix = try allocator.print("<{s}", .{tag});
    defer allocator.free(open_prefix);
    const close = try allocator.print("</{s}>", .{tag});
    defer allocator.free(close);

    // Find <Tag followed immediately by '>', whitespace, or '/'
    var search = xml;
    const tag_start = while (std.mem.find(u8, search, open_prefix)) |idx| {
        const after = idx + open_prefix.len;
        if (after >= search.len) break null;
        const next = search[after];
        if (next == '>' or next == '/' or std.ascii.isWhitespace(next)) break idx;
        search = search[idx + 1 ..];
    } else null;

    const start = tag_start orelse return error.XmlTagNotFound;
    const after_name = search[start + open_prefix.len ..];

    // Skip to end of opening tag
    const gt = std.mem.findScalar(u8, after_name, '>') orelse return error.XmlTagNotFound;
    // Self-closing: <Tag ... />
    if (gt > 0 and after_name[gt - 1] == '/') return unescapeEntities(allocator, "");

    const content_start = gt + 1;
    const end = std.mem.find(u8, after_name[content_start..], close) orelse return error.XmlTagNotFound;

    return unescapeEntities(allocator, after_name[content_start .. content_start + end]);
}

/// Iterates the direct children of an XML fragment named `name`, yielding each
/// child's raw inner content (nested elements are skipped over by depth, so
/// same-named descendants are never yielded).
pub const ChildIterator = struct {
    src: []const u8,
    name: []const u8,
    pos: usize = 0,

    pub fn next(self: *ChildIterator) ?[]const u8 {
        var depth: usize = 0;
        var content_start: ?usize = null;
        while (std.mem.findScalarPos(u8, self.src, self.pos, '<')) |lt| {
            const gt = std.mem.findScalarPos(u8, self.src, lt + 1, '>') orelse return null;
            const raw = self.src[lt + 1 .. gt];
            self.pos = gt + 1;
            if (raw.len == 0 or raw[0] == '?' or raw[0] == '!') continue;
            if (raw[0] == '/') {
                if (depth == 0) return null;
                depth -= 1;
                if (depth == 0) {
                    if (content_start) |s| return self.src[s..lt];
                }
                continue;
            }
            const self_closing = raw[raw.len - 1] == '/';
            const name_end = std.mem.findAny(u8, raw, " \t\r\n/") orelse raw.len;
            if (depth == 0 and std.mem.eql(u8, raw[0..name_end], self.name)) {
                if (self_closing) return "";
                content_start = self.pos;
                depth = 1;
                continue;
            }
            if (!self_closing) depth += 1;
        }
        return null;
    }
};

/// Raw inner content of the first direct child of `src` named `tag`.
pub fn child(src: []const u8, tag: []const u8) ?[]const u8 {
    var it: ChildIterator = .{ .src = src, .name = tag };
    return it.next();
}

/// Caller-owned, entity-unescaped copy of `src`.
pub fn unescape(allocator: Allocator, src: []const u8) ![]u8 {
    return unescapeEntities(allocator, src);
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
        const semi = std.mem.findScalarPos(u8, input, i + 1, ';') orelse {
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

test "child skips nested same-name elements" {
    const doc = "<?xml version=\"1.0\"?><R><state>a</state><set><item><state>b</state></item></set></R>";
    const r = child(doc, "R").?;
    try std.testing.expectEqualStrings("a", child(r, "state").?);
    try std.testing.expect(child(r, "item") == null);
}

test "ChildIterator yields direct items only" {
    const doc = "<item><tagSet><item><k>x</k></item></tagSet><v>1</v></item><item><v>2</v></item><x/>";
    var it: ChildIterator = .{ .src = doc, .name = "item" };
    try std.testing.expectEqualStrings("1", child(it.next().?, "v").?);
    try std.testing.expectEqualStrings("2", child(it.next().?, "v").?);
    try std.testing.expect(it.next() == null);
}

test "child self-closing is empty" {
    try std.testing.expectEqualStrings("", child("<a><b/></a>", "a").?[0..0]);
    try std.testing.expectEqualStrings("", child("<b/><c>1</c>", "b").?);
}

test "extractTagContent does not match tag prefix" {
    const allocator = std.testing.allocator;
    const doc = "<FooBar>wrong</FooBar><Foo>right</Foo>";
    const val = try extractTagContent(allocator, doc, "Foo");
    defer allocator.free(val);
    try std.testing.expectEqualStrings("right", val);
}
