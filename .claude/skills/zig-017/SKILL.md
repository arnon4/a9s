---
name: zig-017
description: >
  Use this skill whenever you are writing, editing, reviewing, or discussing Zig code
  that targets Zig 0.17.0. This is mandatory — your training data predates 0.17.0 and
  contains breaking changes (bitCast, enum builtins, array `**`, type reflection,
  allocator renames, build system). Always apply it for any Zig 0.17 task, including
  build.zig changes, stdlib usage, I/O, and new builtins.
---

# Zig 0.17.0 — Authoritative Reference for Claude Code

Source: https://ziglang.org/download/0.17.0/release-notes.html

0.17 builds on 0.16. Section 0 recaps the 0.16 baseline (still valid); the rest is new in 0.17.

## 0. 0.16 Baseline (still applies)

- **std.Io replaces std.fs / std.net.** `io: std.Io` is passed in; never construct one.
  `std.Io.File`, `Io.Dir`, `Io.Reader`, `Io.Writer`, `Io.Mutex`, `Io.Group`, `Io.Threaded`, etc.
  ```zig
  const cwd = std.Io.Dir.cwd();
  const file = try cwd.openFile(io, "path", .{});   // io is a param, not receiver
  defer file.close();
  var buf: [4096]u8 = undefined;
  var w = std.Io.File.stdout().writer(io, &buf);
  try w.interface.print("hi {s}\n", .{"x"});         // write via .interface
  try w.interface.flush();
  ```
  Removed: `GenericReader`, `AnyReader`, `FixedBufferStream`, `{D}` duration format
  (use `Io.Duration` format), `Thread.Pool`, `heap.ThreadSafeAllocator`
  (`ArenaAllocator` is thread-safe now).
- **Juicy main:** `pub fn main(io: std.Io, args: std.Args) !void`. No global args/env.
  (Check the project's `src/main.zig` for the exact signature in use.)
- **Containers are unmanaged:** `var l: std.ArrayList(u8) = .empty;`
  `l.append(gpa, x)`, `l.deinit(gpa)`. `ArrayListUnmanaged` deprecated. Same for HashMap etc.
- **`@Type` removed:** `@Int`, `@Struct`, `@Union`, `@Enum`, `@Pointer`, `@Fn`,
  `@Tuple`, `@EnumLiteral`.
- **`std.mem`:** `indexOf*` → `find*`, `lastIndexOf*` → `findLast*`; `cut`, `cutPrefix`, `cutSuffix` added.
- `builtin.subsystem` → `zig.Subsystem`.

## Core Principle: When in Doubt, Ask

**Do NOT:**
- Speculatively read the user's Zig source to infer API usage
- Browse the stdlib source unless explicitly asked
- Guess at an API you don't recognise — it may have changed

**DO:** Ask the user, or point at the release notes.

---

## 1. Language Changes

### `@bitCast` redefined
Now reinterprets the *logical bit representation*, not in-memory bytes. Endian-agnostic.
Breaks use on `extern struct` / `extern union`. Use `@ptrCast` for byte reinterpretation:

```zig
// ❌ 0.16
const int: u16 = @bitCast(bytes);

// ✅ 0.17
const int_ptr: *align(1) const u16 = @ptrCast(&bytes);
const int = int_ptr.*;
```

### `@intFromEnum` / `@enumFromInt` deprecated
Use `@backingInt` and `@fromBackingInt`. Both also work on bitpacks.
`@fromBackingInt` infers its result type.

```zig
// ❌ return @enumFromInt(n - 1);
// ✅
return @fromBackingInt(@intCast(n - 1));
const tag_int = @backingInt(my_enum);
```

### Array repetition `**` removed
Use `@splat`:

```zig
// ❌ var r = [1]u8{0} ** window_size;
var r: [window_size]u8 = @splat(0);
```

### Other removals
| Removed | Replacement |
|---------|-------------|
| `void{}` | `{}` |
| `errdefer \|err\| { ... }` capture | Split into separate functions / handle at call site |
| `i0` type | `u0` |
| `internal`, `link_once` in `std.lang.GlobalLinkage` | `weak` for `link_once`; or just don't `@export` |
| `@cImport` | `translate-c` package dependency (`Step.TranslateC` deprecated) |

`@hasDecl` now returns `true` only for **public** declarations, from any file.

### New builtins
- `@backingInt`, `@fromBackingInt` — see above
- `@divCeil(a, b)` — integer division rounded toward +inf
- `@SpirvType` — SPIR-V-only types (sampler, image, …)

---

## 2. Type Reflection: Struct-of-Arrays

`@typeInfo` struct/union/enum field data is now parallel arrays, not arrays of field objects.

```zig
// ❌ inline for (@typeInfo(S).@"struct".fields) |f| { ... f.name, f.type ... }

// ✅
const info = @typeInfo(S).@"struct";
inline for (info.field_names, info.field_types) |name, T| { ... }
```

Also: `field_attrs` (comptime/align/default), `decl_names`.

Error sets: `@typeInfo(E).error_set` is now `{ error_names: ?[]const [:0]const u8 }`.
Elements are plain strings, no `.name`:

```zig
// ❌ for (@typeInfo(E).error_set.?) |entry| entry.name
// ✅ for (@typeInfo(E).error_set.error_names.?) |name| name
```

Deprecated: `std.meta.fieldInfo`, `fieldNames`, `fieldTypes` → use `@typeInfo`.

---

## 3. Standard Library

### Namespaces
- `std.builtin` → `std.lang` (deprecated alias)
- `std.gpu` → `std.spirv`
- `std.builtin.OptimizeMode` → `Optimize`, tags renamed:
  `Debug`→`.debug`, `ReleaseSafe`→`.safe`, `ReleaseFast`→`.fast`, `ReleaseSmall`→`.small`
- `@import("builtin")` fields `cpu`, `os`, `abi`, `object_format` deprecated →
  `builtin.target.cpu`, `.os`, `.abi`, `.ofmt`

### Allocators
```zig
// ❌ 0.16
var stack = std.heap.stackFallback(@sizeOf(Item), gpa);
const a = stack.get();

// ✅ 0.17 — StackFallbackAllocator → BufferFirstAllocator
var stack_buf: [1]Item = undefined;
var stack: std.heap.BufferFirstAllocator = .init(@ptrCast(&stack_buf), gpa);
const a = stack.allocator();
```

- `std.heap.DebugAllocator` deprecated → `std.heap.SafeAllocator` (thread-safe, canary checks).
  Not drop-in: `var sa: std.heap.SafeAllocator = .init(backing, .{});` and `deinit()`
  returns a `usize` leak count (`leaks != 0`).
- `std.mem.indexOf*` / `lastIndexOf*` are deprecated aliases of `find*`;
  `lastIndexOfScalar` → `findScalarLast` (not `findLastScalar`).
- `std.lang.Optimize` tags are `.debug/.safe/.fast/.small`; old `OptimizeMode`/`ReleaseSmall`
  names still compile as aliases (removed after 0.18).
- `ArrayList.getLast()` still exists, not deprecated.
- `" " ** N` → `const s: *const [N]u8 = &@splat(' ');` (pointer needed to coerce to `[]const u8`).
- `std.fmt.allocPrint(a, ...)` → `a.print(...)` (method on `Allocator`)
- `std.heap.memory_pool.AlignedManaged` / `ExtraManaged` removed

```zig
// ❌ try std.fmt.allocPrint(arena, "{s}={d}", .{ x, y });
try arena.print("{s}={d}", .{ x, y });
```

### ArrayList
| Old | New |
|-----|-----|
| `getLastOrNull()` | `last()` (returns `?T`) |
| `getLast()` | `last().?` |
| — | `lastPtr()` returns `?*T` |

### Bit sets
| Old | New |
|-----|-----|
| `IntegerBitSet` | `bit_set.Integer` |
| `ArrayBitSet` | `bit_set.Array` |
| `StaticBitset` | `bit_set.Static` |
| `DynamicBitSetUnmanaged` | `bit_set.Dynamic` |
| `DynamicBitSet` (managed) | `bit_set.DynamicManaged` (deprecated) |

### ZON
```zig
// ❌ std.zon.parse.fromSliceAlloc(T, gpa, source, &diag, .{})
const v = try std.zon.parse.fromSlice(T, .{
    .gpa = gpa,
    .arena = arena,
    .source = source,
    .diagnostics = &diag,
});
```
`updateFromSlice` variants merge into an existing value (config layering).

### Misc renames / removals
| Old | New |
|-----|-----|
| `std.mem.readPackedIntNative/Foreign` | `std.mem.readPackedInt` |
| `std.mem.writePackedIntNative/Foreign` | `std.mem.writePackedInt` |
| `std.ascii.indexOfIgnoreCase*` | `std.ascii.findIgnoreCase*` |
| `std.DoublyLinkedList.pop` | `popLast` |
| `std.mem.containsAtLeastScalar` | **parameter order swapped** (element ↔ minimum) — recheck call sites |

---

## 4. Build System (`build.zig`)

- Build now runs as **configurer** (your `build.zig`) + **maker** (executes graph).
  Binary cache format, `--print-configuration` available.
- `b.build_root` (Directory) → `b.root` (Path).
- `LazyPath.getDisplayName()` → format with `"{f}"`. `LazyPath.basename` removed.
- `b.findProgram` poisons cache; new `findProgramLazy` returns a `LazyPath` and doesn't.
- `Run.addPassthruArgs()` replaces reading `b.args` at build time.
- `ConfigHeader.include_guard_override` → `include_guard`.
- All `add*Arg` / `addPrefixed*Arg` variants consolidated into `add*Arg2` methods.
- `Fmt` step: `paths` / `exclude_paths` take `LazyPath` lists via `b.pathList()`.
- `addOptionPath` split: `addOptionPath` (files), `addOptionPathDirectory`, `addOptionPathUntracked`.
- Cannot override the build runner anymore; use the Build Server Protocol (`--listen=-`).
- `zig fetch` alone → global cache; `--save` also fetches locally; `zig build` always local.
  `--pkg-path` / `ZIG_LOCAL_PKG_DIR` respected.
- `zig fetch`, `zig init`, `zig libc`, `zig cache-cat` are now part of the build system.

---

## 5. Toolchain

- LLVM 22. Loop vectorization still disabled (until LLVM 23).
- `zig objdump` added.
- Removed targets: `powerpc-linux-gnueabi[hf]`, `powerpc64-linux-gnu`.
- C backend added: `arc[eb]-linux`, `csky-linux`, `m88k-openbsd`.

---

## 6. What Has NOT Changed

- std.Io model, juicy main, `.empty` containers (0.16 baseline above)
- Core syntax, comptime, errors, optionals, unions
- `std.mem.Allocator` interface

---

## Quick Checklist

- [ ] No `**` array repetition — use `@splat`
- [ ] No `@intFromEnum` / `@enumFromInt` — use `@backingInt` / `@fromBackingInt`
- [ ] `@bitCast` not used on `extern` types or for byte reinterpretation
- [ ] `@typeInfo` field loops use `field_names` / `field_types`
- [ ] `allocPrint` → `allocator.print`
- [ ] No `errdefer |err|`, `i0`, `void{}`, `@cImport`
- [ ] `build.zig`: `b.root`, `*Arg2`, `findProgramLazy` where applicable
- [ ] Unsure of an API? Ask, don't guess

## Windows console gotcha

`std.os.windows.CONSOLE.USER_IO.GET_SCREEN_BUFFER_INFO` must be run on the **stdout**
handle. Running it on stdin returned a zero size in some terminals (blank TUI).
