const std = @import("std");
const Allocator = std.mem.Allocator;

/// A simple INI file parser for AWS credential and config files.
/// Supports the standard AWS format:
/// ```
/// [profile_name]
/// key = value
/// key2 = value2
///
/// [another_profile]
/// key = value
/// ```
pub const IniFile = struct {
    allocator: Allocator,
    sections: std.StringHashMap(Section),

    pub const Section = std.StringHashMap([]const u8);

    fn init(allocator: Allocator) IniFile {
        return .{
            .allocator = allocator,
            .sections = std.StringHashMap(Section).init(allocator),
        };
    }

    /// Parse INI content from a string.
    pub fn parse(allocator: Allocator, content: []const u8) !IniFile {
        var ini = IniFile.init(allocator);
        errdefer ini.deinit();

        var current_section: ?[]const u8 = null;
        var lines = std.mem.splitSequence(u8, content, "\n");

        while (lines.next()) |raw_line| {
            // Handle Windows line endings
            const line = std.mem.trimEnd(u8, raw_line, "\r");

            // Skip empty lines and comments
            const trimmed = std.mem.trim(u8, line, " \t");
            if (trimmed.len == 0 or trimmed[0] == '#' or trimmed[0] == ';') {
                continue;
            }

            // Check for section header
            if (trimmed[0] == '[') {
                if (std.mem.indexOfScalar(u8, trimmed, ']')) |end| {
                    const section_name = std.mem.trim(u8, trimmed[1..end], " \t");
                    const section_key = try allocator.dupe(u8, section_name);
                    errdefer allocator.free(section_key);

                    try ini.sections.put(section_key, Section.init(allocator));
                    current_section = section_key;
                }
                continue;
            }

            // Parse key = value
            if (current_section) |section_name| {
                if (std.mem.indexOfScalar(u8, trimmed, '=')) |eq_pos| {
                    const key = std.mem.trim(u8, trimmed[0..eq_pos], " \t");
                    const value = std.mem.trim(u8, trimmed[eq_pos + 1 ..], " \t");

                    if (key.len > 0) {
                        const key_copy = try allocator.dupe(u8, key);
                        errdefer allocator.free(key_copy);

                        const value_copy = try allocator.dupe(u8, value);
                        errdefer allocator.free(value_copy);

                        if (ini.sections.getPtr(section_name)) |section| {
                            try section.put(key_copy, value_copy);
                        }
                    }
                }
            }
        }

        return ini;
    }

    /// Parse INI content from a file.
    pub fn parseFile(allocator: Allocator, io: std.Io, path: []const u8) !IniFile {
        const content = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, std.Io.Limit.limited(1024 * 1024)) catch |err| {
            return switch (err) {
                error.FileNotFound => error.FileNotFound,
                error.OutOfMemory => error.OutOfMemory,
                else => error.AccessDenied,
            };
        };
        defer allocator.free(content);

        return parse(allocator, content);
    }

    /// Get a value from a specific section.
    pub fn get(self: *const IniFile, section: []const u8, key: []const u8) ?[]const u8 {
        if (self.sections.get(section)) |sec| {
            return sec.get(key);
        }
        return null;
    }

    /// Get a section by name.
    pub fn getSection(self: *const IniFile, section: []const u8) ?*const Section {
        return self.sections.getPtr(section);
    }

    /// Check if a section exists.
    pub fn hasSection(self: *const IniFile, section: []const u8) bool {
        return self.sections.contains(section);
    }

    /// Get all section names.
    pub fn getSectionNames(self: *const IniFile, allocator: Allocator) ![][]const u8 {
        var names: std.ArrayList([]const u8) = .empty;
        errdefer names.deinit(allocator);

        var iter = self.sections.keyIterator();
        while (iter.next()) |key| {
            try names.append(allocator, key.*);
        }

        return names.toOwnedSlice(allocator);
    }

    /// Clean up all resources.
    pub fn deinit(self: *IniFile) void {
        var section_iter = self.sections.iterator();
        while (section_iter.next()) |entry| {
            // Free all keys and values in this section
            var kv_iter = entry.value_ptr.iterator();
            while (kv_iter.next()) |kv| {
                self.allocator.free(kv.key_ptr.*);
                self.allocator.free(kv.value_ptr.*);
            }
            entry.value_ptr.deinit();
            // Free section name
            self.allocator.free(entry.key_ptr.*);
        }
        self.sections.deinit();
    }
};

test "IniFile parses simple INI content" {
    const allocator = std.testing.allocator;

    const content =
        \\[default]
        \\aws_access_key_id = AKIAIOSFODNN7EXAMPLE
        \\aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
        \\
        \\[profile dev]
        \\aws_access_key_id = AKIAI44QH8DHBEXAMPLE
        \\aws_secret_access_key = je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY
        \\region = us-west-2
    ;

    var ini = try IniFile.parse(allocator, content);
    defer ini.deinit();

    // Check default section
    try std.testing.expect(ini.hasSection("default"));
    try std.testing.expectEqualStrings(
        "AKIAIOSFODNN7EXAMPLE",
        ini.get("default", "aws_access_key_id").?,
    );
    try std.testing.expectEqualStrings(
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        ini.get("default", "aws_secret_access_key").?,
    );

    // Check dev profile
    try std.testing.expect(ini.hasSection("profile dev"));
    try std.testing.expectEqualStrings(
        "AKIAI44QH8DHBEXAMPLE",
        ini.get("profile dev", "aws_access_key_id").?,
    );
    try std.testing.expectEqualStrings(
        "us-west-2",
        ini.get("profile dev", "region").?,
    );
}

test "IniFile handles comments" {
    const allocator = std.testing.allocator;

    const content =
        \\# This is a comment
        \\[default]
        \\; Another comment
        \\key = value
        \\# Comment after value
    ;

    var ini = try IniFile.parse(allocator, content);
    defer ini.deinit();

    try std.testing.expectEqualStrings("value", ini.get("default", "key").?);
}

test "IniFile handles whitespace" {
    const allocator = std.testing.allocator;

    const content =
        \\[ default ]
        \\  key  =  value with spaces
        \\key2=no_spaces
    ;

    var ini = try IniFile.parse(allocator, content);
    defer ini.deinit();

    try std.testing.expect(ini.hasSection("default"));
    try std.testing.expectEqualStrings("value with spaces", ini.get("default", "key").?);
    try std.testing.expectEqualStrings("no_spaces", ini.get("default", "key2").?);
}

test "IniFile returns null for missing keys" {
    const allocator = std.testing.allocator;

    const content =
        \\[default]
        \\key = value
    ;

    var ini = try IniFile.parse(allocator, content);
    defer ini.deinit();

    try std.testing.expect(ini.get("default", "missing") == null);
    try std.testing.expect(ini.get("missing_section", "key") == null);
}

test "IniFile handles empty sections" {
    const allocator = std.testing.allocator;

    const content =
        \\[empty]
        \\
        \\[with_data]
        \\key = value
    ;

    var ini = try IniFile.parse(allocator, content);
    defer ini.deinit();

    try std.testing.expect(ini.hasSection("empty"));
    try std.testing.expect(ini.hasSection("with_data"));
    try std.testing.expect(ini.get("empty", "anything") == null);
}

test "IniFile.getSectionNames returns all sections" {
    const allocator = std.testing.allocator;

    const content =
        \\[alpha]
        \\key = value
        \\[beta]
        \\key = value
        \\[gamma]
        \\key = value
    ;

    var ini = try IniFile.parse(allocator, content);
    defer ini.deinit();

    const names = try ini.getSectionNames(allocator);
    defer allocator.free(names);

    try std.testing.expectEqual(@as(usize, 3), names.len);
}

test "IniFile handles Windows line endings" {
    const allocator = std.testing.allocator;

    const content = "[default]\r\nkey = value\r\nkey2 = value2\r\n";

    var ini = try IniFile.parse(allocator, content);
    defer ini.deinit();

    try std.testing.expectEqualStrings("value", ini.get("default", "key").?);
    try std.testing.expectEqualStrings("value2", ini.get("default", "key2").?);
}
