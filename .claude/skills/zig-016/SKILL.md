---
name: zig016
description: >
  Use this skill whenever you are writing, editing, reviewing, or discussing Zig code.
  This is mandatory — your training data predates Zig 0.16.0 and contains breaking API
  changes. This skill corrects your knowledge. Always apply it for any Zig task,
  including build.zig changes, stdlib usage, data structures, I/O, and new language
  builtins. Do not rely on pre-0.16.0 Zig patterns without checking this skill first.
---

# Zig 0.16.0 — Authoritative Reference for Claude Code

Your training data covers Zig prior to 0.16.0. This release contains **breaking changes**
that will produce compilation errors if you use old patterns. Follow this skill precisely.

## Core Principle: When in Doubt, Ask

**Do NOT:**
- Speculatively read the user's Zig source files to infer API usage
- Browse the stdlib source unless explicitly asked to
- Guess at an API you don't recognise — it may have changed

**DO:** Ask the user to clarify any API or usage you're uncertain about.

---

## 1. std.Io — The New I/O Interface

std.fs, std.net, std.process (for I/O purposes), and related OS-level APIs have
been unified into std.Io — a cross-platform interface that abstracts all I/O
and concurrency. The old std.fs namespace is **gone**.

### Getting an Io instance

std.Io is passed in through main (see §4 Juicy Main). Never construct one yourself.

`zig
pub fn main(io: std.Io, args: std.Args) !void {
    // io is your handle to everything I/O
}
`

### std.Io Types Reference

| Type | Purpose |
|------|---------|
| Io.File | File handle (replaces std.fs.File) |
| Io.Dir | Directory handle (replaces std.fs.Dir) |
| Io.Reader | Buffered/unbuffered reader |
| Io.Writer | Buffered/unbuffered writer |
| Io.LockedStderr | Locked access to stderr |
| Io.Terminal | Terminal interaction |
| Io.Duration | Time duration (see §6) |
| Io.Timestamp | Point in time |
| Io.Clock | Clock source |
| Io.Future | Async future |
| Io.AnyFuture | Type-erased future |
| Io.Group | Await a group of futures |
| Io.Batch | Batch of operations |
| Io.CancelProtection | Scoped cancel guard |
| Io.Condition | Condition variable |
| Io.Dispatch | Work dispatch |
| Io.Event | Signalling event |
| Io.Evented | Evented I/O wrapper |
| Io.Mutex | Mutex |
| Io.RwLock | Reader-writer lock |
| Io.Semaphore | Semaphore |
| Io.Limit | I/O rate limiter |
| Io.Operation | Represents a pending I/O op |
| Io.Queue / Io.TypeErasedQueue | Concurrent queues |
| Io.Select | Select over multiple futures |
| Io.Threaded | Threaded executor |
| Io.Timeout | Future with a timeout |
| Io.Kqueue / Io.Uring | Platform-specific backends |
| Io.VTable | Io interface vtable |

### Common Access Patterns

**Standard streams** — static methods on std.Io.File, all return File:
`zig
const stdin  = std.Io.File.stdin();
const stdout = std.Io.File.stdout();
const stderr = std.Io.File.stderr();
`
Note: stderr returns a plain File, but std.Io.LockedStderr exists for locked access.

**Current working directory:**
`zig
const cwd: std.Io.Dir = std.Io.Dir.cwd();
`

**Opening files:**
`zig
// Relative to a Dir:
const file = try cwd.openFile(io, "path/to/file.txt", .{});

// Absolute path (no Dir needed):
const file = try std.Io.Dir.openFileAbsolute(io, "/etc/hosts", .{});
`
Both return Io.File.OpenError!File. Note that io is passed as a parameter, not a receiver.

**Getting a Reader or Writer from a File:**
`zig
var read_buf: [4096]u8 = undefined;
var reader = file.reader(io, &read_buf);   // returns Io.Reader

var write_buf: [4096]u8 = undefined;
var writer = file.writer(io, &write_buf);  // returns Io.Writer (not Io.Writer directly!)
`
Reader and Writer here are Io.Reader/buffer wrappers — **not** Io.Writer itself.
Access the underlying Io.Writer via .interface:
`zig
try writer.interface.print("Hello, {s}!\n", .{"world"});
try writer.interface.writeAll("raw bytes\n");
`

**Full example — write to stdout:**
`zig
pub fn main(io: std.Io, _: std.Args) !void {
    const stdout_file = std.Io.File.stdout();
    var buf: [4096]u8 = undefined;
    var writer = stdout_file.writer(io, &buf);
    try writer.interface.print("Hello, world!\n", .{});
}
`

**Full example — read a file:**
`zig
pub fn main(io: std.Io, _: std.Args) !void {
    const cwd = std.Io.Dir.cwd();
    const file = try cwd.openFile(io, "hello.txt", .{});
    defer file.close();

    var buf: [4096]u8 = undefined;
    var reader = file.reader(io, &buf);
    // use reader to read...
}
`

### Deleted from std.io (lowercase)

GenericReader, AnyReader, and FixedBufferStream have been **removed**.
Use Io.Reader and Io.Writer instead.

---

## 2. Data Structures — Allocator-on-Use Pattern

All standard library containers have migrated to the "unmanaged" pattern. The allocator
is **not** stored in the struct; it is passed at every call site.

### ArrayList

`zig
// ✅ 0.16.0 — initialise with .empty, no allocator
var list: std.ArrayList(u8) = .empty;
defer list.deinit(allocator);

try list.append(allocator, 42);
try list.appendSlice(allocator, "hello");
`

`zig
// ❌ OLD — do not use
var list = std.ArrayList(u8).init(allocator);
`

Key signatures:
`zig
pub fn append(self: *Self, gpa: Allocator, elem: T) Allocator.Error!void
pub fn appendSlice(self: *Self, gpa: Allocator, items: []const T) Allocator.Error!void
pub fn deinit(self: *Self, gpa: Allocator) void
pub fn ensureTotalCapacity(self: *Self, gpa: Allocator, new_capacity: usize) Allocator.Error!void
`

### ArrayListUnmanaged

**Deprecated.** std.ArrayList now *is* the unmanaged variant. Do not use
ArrayListUnmanaged in new code.

### Other Containers (HashMap, etc.)

The same pattern applies across all stdlib containers — .empty initialisation,
allocator passed per-call. If you are unsure of the exact signature for a specific
container method, **ask the user** rather than guessing.

---

## 3. @Type Removed — New Type-Creating Builtins

@Type is removed. Use the individual builtins:

| Old | New |
|-----|-----|
| @Type(.{ .int = .{ .signedness = .unsigned, .bits = N } }) | @Int(.unsigned, N) |
| @Type(.{ .@"struct" = ... }) | @Struct(layout, BackingInt, names, types, attrs) |
| @Type(.{ .@"union" = ... }) | @Union(layout, ArgType, names, types, attrs) |
| @Type(.{ .@"enum" = ... }) | @Enum(TagInt, mode, names, values) |
| @Type(.{ .pointer = ... }) | @Pointer(size, attrs, Child, sentinel) |
| @Type(.{ .@"fn" = ... }) | @Fn(param_types, param_attrs, ReturnType, attrs) |
| @TypeOf(.something) (as a type) | @EnumLiteral() |
| std.meta.Tuple(types) | @Tuple(types) |
| std.meta.Int(sign, bits) | @Int(sign, bits) |

Tip: use &@splat(.{}) to supply default attributes for all fields/params.

---

## 4. "Juicy Main" — New Entry Point Signature

main now receives environment and platform context via parameters, rather than
accessing global state.

`zig
pub fn main(io: std.Io, args: std.Args) !void { ... }
`

- io — your std.Io instance; pass it down to anything doing I/O
- rgs — process arguments and environment variables (no longer global)

Old patterns like std.process.args() or std.os.argv as global access are gone.

---

## 5. @cImport Deprecated

@cImport is deprecated. C headers should be translated via the build system:

`zig
// build.zig
const translate_c = b.addTranslateC(.{
    .root_source_file = b.path("src/c.h"),
    .target = target,
    .optimize = optimize,
});
`

Then import as a module: const c = @import("c");

---

## 6. Duration Format

The {D} format specifier is removed. Use Io.Duration's format method instead.

---

## 7. Other Notable Removals / Renames

| Removed / Renamed | Replacement |
|-------------------|-------------|
| std.fs.* | std.Io (via io parameter) |
| std.fs.getAppDataDir | Removed, no direct replacement |
| heap.ThreadSafeAllocator | Removed; heap.ArenaAllocator is now thread-safe and lock-free |
| Thread.Pool | Removed |
| std.mem.indexOf* functions | Renamed to std.mem.find* |
| std.mem.lastIndexOf* | Renamed to std.mem.findLast* |
| uiltin.subsystem | Removed; use zig.Subsystem |
| Target.SubSystem | Moved to zig.Subsystem |

std.mem also gains cut / cutSuffix / cutPrefix functions for splitting slices
around a delimiter.

---

## 8. What Has NOT Changed

- General language syntax, comptime, error handling, optionals, unions, enums
- uild.zig structure (modules, steps, dependencies) — same overall shape
- The type system fundamentals (with the exception of the @Type → builtin migration above)
- Standard allocator interfaces (std.mem.Allocator)

---

## Quick Checklist Before Writing Any Zig Code

- [ ] Am I using std.Io for any file/network/process I/O, not std.fs?
- [ ] Is main accepting io: std.Io and rgs: std.Args?
- [ ] Are data structures initialised with .empty and allocator passed per-call?
- [ ] Have I replaced any @Type(...) with the correct specific builtin?
- [ ] Am I avoiding ArrayListUnmanaged and GenericReader/AnyReader?
- [ ] If I'm unsure about an API, have I asked the user rather than guessing?
