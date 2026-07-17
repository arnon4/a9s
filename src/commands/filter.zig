const std = @import("std");
const Allocator = std.mem.Allocator;

// ============================================================================
// Lexer
// ============================================================================

pub const TokenKind = enum { ident, quoted, lbracket, rbracket, lparen, rparen, comma, eof };

pub const Token = struct {
    kind: TokenKind,
    text: []const u8,
};

pub const Lexer = struct {
    src: []const u8,
    pos: usize = 0,

    pub fn next(self: *Lexer) Token {
        while (self.pos < self.src.len and std.ascii.isWhitespace(self.src[self.pos])) self.pos += 1;
        if (self.pos >= self.src.len) return .{ .kind = .eof, .text = "" };
        const c = self.src[self.pos];
        switch (c) {
            '[' => {
                self.pos += 1;
                return .{ .kind = .lbracket, .text = "[" };
            },
            ']' => {
                self.pos += 1;
                return .{ .kind = .rbracket, .text = "]" };
            },
            '(' => {
                self.pos += 1;
                return .{ .kind = .lparen, .text = "(" };
            },
            ')' => {
                self.pos += 1;
                return .{ .kind = .rparen, .text = ")" };
            },
            ',' => {
                self.pos += 1;
                return .{ .kind = .comma, .text = "," };
            },
            '"', '\'' => {
                const q = c;
                self.pos += 1;
                const start = self.pos;
                while (self.pos < self.src.len and self.src[self.pos] != q) self.pos += 1;
                const text = self.src[start..self.pos];
                if (self.pos < self.src.len) self.pos += 1;
                return .{ .kind = .quoted, .text = text };
            },
            else => {
                const start = self.pos;
                while (self.pos < self.src.len) {
                    const ch = self.src[self.pos];
                    if (std.ascii.isWhitespace(ch) or ch == '[' or ch == ']' or
                        ch == '(' or ch == ')' or ch == ',') break;
                    self.pos += 1;
                }
                return .{ .kind = .ident, .text = self.src[start..self.pos] };
            },
        }
    }

    pub fn peek(self: *Lexer) Token {
        const saved = self.pos;
        const tok = self.next();
        self.pos = saved;
        return tok;
    }
};

// ============================================================================
// AST
// ============================================================================

pub const Op = enum { gt, gte, lt, lte, eq, contains, begins_with, ends_with, in };

pub const Value = union(enum) {
    string: []const u8,
    list: []const Value,
};

pub const Predicate = struct {
    field: []const u8,
    negated: bool,
    op: Op,
    value: Value,
};

pub const Expr = union(enum) {
    and_: [2]*Expr,
    or_: [2]*Expr,
    not_: *Expr,
    predicate: Predicate,
};

// ============================================================================
// ParseResult
// ============================================================================

pub const ParseResult = struct {
    arena: std.heap.ArenaAllocator,
    expr: *Expr,

    pub fn deinit(self: *ParseResult) void {
        self.arena.deinit();
    }

    pub fn eval(self: *const ParseResult, resolver: anytype) bool {
        return evalExpr(self.expr, resolver);
    }
};

// ============================================================================
// Parser
// ============================================================================

pub const ParseError = error{ UnexpectedToken, UnexpectedEnd, OutOfMemory };

pub fn parse(allocator: Allocator, src: []const u8) ParseError!ParseResult {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    var p = Parser{ .arena = arena.allocator(), .lex = .{ .src = src } };
    const expr = try p.parseOr();
    if (p.lex.peek().kind != .eof) return error.UnexpectedToken;
    return ParseResult{ .arena = arena, .expr = expr };
}

const Parser = struct {
    arena: Allocator,
    lex: Lexer,

    fn parseOr(self: *Parser) ParseError!*Expr {
        var left = try self.parseAnd();
        while (true) {
            const tok = self.lex.peek();
            if (tok.kind != .ident or !std.mem.eql(u8, tok.text, "or")) break;
            _ = self.lex.next();
            const right = try self.parseAnd();
            const node = try self.arena.create(Expr);
            node.* = .{ .or_ = .{ left, right } };
            left = node;
        }
        return left;
    }

    fn parseAnd(self: *Parser) ParseError!*Expr {
        var left = try self.parseUnary();
        while (true) {
            const tok = self.lex.peek();
            if (tok.kind != .ident or !std.mem.eql(u8, tok.text, "and")) break;
            _ = self.lex.next();
            const right = try self.parseUnary();
            const node = try self.arena.create(Expr);
            node.* = .{ .and_ = .{ left, right } };
            left = node;
        }
        return left;
    }

    fn parseUnary(self: *Parser) ParseError!*Expr {
        const tok = self.lex.peek();
        if (tok.kind == .ident and std.mem.eql(u8, tok.text, "not")) {
            _ = self.lex.next();
            // "not" followed by a predicate field? Then it's prefix-not on a sub-expression.
            const inner = try self.parseUnary();
            const node = try self.arena.create(Expr);
            node.* = .{ .not_ = inner };
            return node;
        }
        return self.parseAtom();
    }

    fn parseAtom(self: *Parser) ParseError!*Expr {
        if (self.lex.peek().kind == .lparen) {
            _ = self.lex.next();
            const inner = try self.parseOr();
            const close = self.lex.next();
            if (close.kind != .rparen) return error.UnexpectedToken;
            return inner;
        }
        return self.parsePredicate();
    }

    fn parsePredicate(self: *Parser) ParseError!*Expr {
        const field_tok = self.lex.next();
        if (field_tok.kind != .ident) return error.UnexpectedToken;

        // optional inline "not" before the op
        var negated = false;
        const maybe_not = self.lex.peek();
        if (maybe_not.kind == .ident and std.mem.eql(u8, maybe_not.text, "not")) {
            _ = self.lex.next();
            negated = true;
        }

        const op_tok = self.lex.next();
        if (op_tok.kind != .ident) return error.UnexpectedToken;
        const op = parseOp(op_tok.text) orelse return error.UnexpectedToken;

        const val = try self.parseValue();
        const node = try self.arena.create(Expr);
        node.* = .{ .predicate = .{
            .field = field_tok.text,
            .negated = negated,
            .op = op,
            .value = val,
        } };
        return node;
    }

    fn parseValue(self: *Parser) ParseError!Value {
        if (self.lex.peek().kind == .lbracket) {
            _ = self.lex.next();
            var items: std.ArrayList(Value) = .empty;
            var first = true;
            while (true) {
                const pk = self.lex.peek();
                if (pk.kind == .rbracket) {
                    _ = self.lex.next();
                    break;
                }
                if (pk.kind == .eof) return error.UnexpectedEnd;
                if (!first) {
                    const comma = self.lex.next();
                    if (comma.kind != .comma) return error.UnexpectedToken;
                }
                first = false;
                const item = try self.parseScalarValue();
                try items.append(self.arena, item);
            }
            return .{ .list = try items.toOwnedSlice(self.arena) };
        }
        return self.parseScalarValue();
    }

    fn parseScalarValue(self: *Parser) ParseError!Value {
        const tok = self.lex.next();
        if (tok.kind == .quoted or tok.kind == .ident) return .{ .string = tok.text };
        return error.UnexpectedToken;
    }
};

fn parseOp(s: []const u8) ?Op {
    if (std.mem.eql(u8, s, "gt")) return .gt;
    if (std.mem.eql(u8, s, "gte")) return .gte;
    if (std.mem.eql(u8, s, "lt")) return .lt;
    if (std.mem.eql(u8, s, "lte")) return .lte;
    if (std.mem.eql(u8, s, "eq")) return .eq;
    if (std.mem.eql(u8, s, "contains")) return .contains;
    if (std.mem.eql(u8, s, "beginswith")) return .begins_with;
    if (std.mem.eql(u8, s, "endswith")) return .ends_with;
    if (std.mem.eql(u8, s, "in")) return .in;
    return null;
}

// ============================================================================
// FieldValue and evaluator
// ============================================================================

pub const FieldValue = union(enum) {
    string: []const u8,
    bytes: u64,
    unknown,
};

pub fn evalExpr(expr: *const Expr, resolver: anytype) bool {
    return switch (expr.*) {
        .and_ => |ch| evalExpr(ch[0], resolver) and evalExpr(ch[1], resolver),
        .or_ => |ch| evalExpr(ch[0], resolver) or evalExpr(ch[1], resolver),
        .not_ => |ch| !evalExpr(ch, resolver),
        .predicate => |p| blk: {
            const fv = resolver.resolve(p.field);
            const result = applyOp(p.op, fv, p.value);
            break :blk if (p.negated) !result else result;
        },
    };
}

fn applyOp(op: Op, fv: FieldValue, val: Value) bool {
    return switch (op) {
        .eq => scalarEq(fv, val),
        .gt => fieldCompare(fv, val) == .gt,
        .gte => fieldCompare(fv, val) != .lt,
        .lt => fieldCompare(fv, val) == .lt,
        .lte => fieldCompare(fv, val) != .gt,
        .contains => blk: {
            const s = fieldAsString(fv) orelse break :blk false;
            const needle = valueAsString(val) orelse break :blk false;
            break :blk std.mem.indexOf(u8, s, needle) != null;
        },
        .begins_with => blk: {
            const s = fieldAsString(fv) orelse break :blk false;
            const needle = valueAsString(val) orelse break :blk false;
            break :blk std.mem.startsWith(u8, s, needle);
        },
        .ends_with => blk: {
            const s = fieldAsString(fv) orelse break :blk false;
            const needle = valueAsString(val) orelse break :blk false;
            break :blk std.mem.endsWith(u8, s, needle);
        },
        .in => blk: {
            const items = switch (val) {
                .list => |l| l,
                .string => break :blk scalarEq(fv, val),
            };
            for (items) |item| if (scalarEq(fv, item)) break :blk true;
            break :blk false;
        },
    };
}

fn scalarEq(fv: FieldValue, val: Value) bool {
    return switch (fv) {
        .string => |s| std.mem.eql(u8, s, valueAsString(val) orelse return false),
        .bytes => |b| b == (parseSize(valueAsString(val) orelse return false) orelse return false),
        .unknown => false,
    };
}

fn fieldCompare(fv: FieldValue, val: Value) std.math.Order {
    return switch (fv) {
        .string => |s| std.mem.order(u8, s, valueAsString(val) orelse return .lt),
        .bytes => |b| std.math.order(b, parseSize(valueAsString(val) orelse return .lt) orelse return .lt),
        .unknown => .lt,
    };
}

fn fieldAsString(fv: FieldValue) ?[]const u8 {
    return switch (fv) {
        .string => |s| s,
        else => null,
    };
}

fn valueAsString(val: Value) ?[]const u8 {
    return switch (val) {
        .string => |s| s,
        .list => null,
    };
}

/// Parse "100", "1K", "1KB", "2.5M", "2.5MB", "1G", "1GB", "1T", "1TB" → bytes. Case-insensitive suffix.
pub fn parseSize(s: []const u8) ?u64 {
    if (s.len == 0) return null;
    var rest = s;
    if (rest.len >= 2 and std.ascii.toUpper(rest[rest.len - 1]) == 'B') {
        rest = rest[0 .. rest.len - 1];
    }
    if (rest.len == 0) return null;
    const last = rest[rest.len - 1];
    const mult: u64 = switch (std.ascii.toUpper(last)) {
        'K' => 1024,
        'M' => 1024 * 1024,
        'G' => 1024 * 1024 * 1024,
        'T' => 1024 * 1024 * 1024 * 1024,
        else => 1,
    };
    const num = if (mult != 1) rest[0 .. rest.len - 1] else rest;
    if (std.fmt.parseInt(u64, num, 10)) |n| return n * mult else |_| {}
    if (std.fmt.parseFloat(f64, num)) |f| return @intFromFloat(f * @as(f64, @floatFromInt(mult))) else |_| {}
    return null;
}

// ============================================================================
// Tests
// ============================================================================

test "parse simple eq" {
    const allocator = std.testing.allocator;
    var result = try parse(allocator, "name eq foo");
    defer result.deinit();
    const p = result.expr.predicate;
    try std.testing.expectEqualStrings("name", p.field);
    try std.testing.expect(p.op == .eq);
    try std.testing.expect(!p.negated);
    try std.testing.expectEqualStrings("foo", p.value.string);
}

test "parse and/or precedence" {
    const allocator = std.testing.allocator;
    // "a eq 1 or b eq 2 and c eq 3" -> or(eq(a,1), and(eq(b,2), eq(c,3)))
    var result = try parse(allocator, "a eq 1 or b eq 2 and c eq 3");
    defer result.deinit();
    try std.testing.expect(result.expr.* == .or_);
}

test "parse not inline" {
    const allocator = std.testing.allocator;
    var result = try parse(allocator, "name not beginswith tmp");
    defer result.deinit();
    const p = result.expr.predicate;
    try std.testing.expect(p.negated);
    try std.testing.expect(p.op == .begins_with);
}

test "parse prefix not" {
    const allocator = std.testing.allocator;
    var result = try parse(allocator, "not name eq foo");
    defer result.deinit();
    try std.testing.expect(result.expr.* == .not_);
}

test "parse in list" {
    const allocator = std.testing.allocator;
    var result = try parse(allocator, "region in [us-east-1, eu-west-1]");
    defer result.deinit();
    const p = result.expr.predicate;
    try std.testing.expect(p.op == .in);
    try std.testing.expect(p.value.list.len == 2);
}

test "parse quoted value" {
    const allocator = std.testing.allocator;
    var result = try parse(allocator, "name eq \"hello world\"");
    defer result.deinit();
    try std.testing.expectEqualStrings("hello world", result.expr.predicate.value.string);
}

test "parseSize" {
    try std.testing.expectEqual(@as(?u64, 1024), parseSize("1K"));
    try std.testing.expectEqual(@as(?u64, 1024), parseSize("1KB"));
    try std.testing.expectEqual(@as(?u64, 1024 * 1024), parseSize("1M"));
    try std.testing.expectEqual(@as(?u64, 1024 * 1024), parseSize("1MB"));
    try std.testing.expectEqual(@as(?u64, 100), parseSize("100"));
    try std.testing.expectEqual(@as(?u64, @intFromFloat(1.5 * 1024 * 1024)), parseSize("1.5M"));
    try std.testing.expectEqual(@as(?u64, @intFromFloat(1.5 * 1024 * 1024)), parseSize("1.5MB"));
    try std.testing.expectEqual(@as(?u64, null), parseSize(""));
    try std.testing.expectEqual(@as(?u64, null), parseSize("abc"));
}

test "eval string eq" {
    const allocator = std.testing.allocator;
    var result = try parse(allocator, "region eq us-east-1");
    defer result.deinit();
    const Resolver = struct {
        pub fn resolve(_: @This(), field: []const u8) FieldValue {
            if (std.mem.eql(u8, field, "region")) return .{ .string = "us-east-1" };
            return .unknown;
        }
    };
    try std.testing.expect(result.eval(Resolver{}));
}

test "eval bytes gt" {
    const allocator = std.testing.allocator;
    var result = try parse(allocator, "size gt 1M");
    defer result.deinit();
    const Resolver = struct {
        pub fn resolve(_: @This(), field: []const u8) FieldValue {
            if (std.mem.eql(u8, field, "size")) return .{ .bytes = 2 * 1024 * 1024 };
            return .unknown;
        }
    };
    try std.testing.expect(result.eval(Resolver{}));
}

test "eval parens override precedence" {
    const allocator = std.testing.allocator;
    // "(a eq 1 or a eq 2) and b eq 3"
    var result = try parse(allocator, "(a eq 1 or a eq 2) and b eq 3");
    defer result.deinit();
    try std.testing.expect(result.expr.* == .and_);
}

/// Case-insensitive substring search. Returns true if `needle` appears anywhere in `haystack`.
pub fn matchesText(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (needle.len > haystack.len) return false;
    var i: usize = 0;
    outer: while (i <= haystack.len - needle.len) : (i += 1) {
        for (needle, 0..) |nc, j| {
            if (std.ascii.toLower(haystack[i + j]) != std.ascii.toLower(nc)) continue :outer;
        }
        return true;
    }
    return false;
}
