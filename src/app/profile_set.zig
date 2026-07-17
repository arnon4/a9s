const std = @import("std");
const Allocator = std.mem.Allocator;
const fetcher = @import("../sdk/credentials/fetcher.zig");
const CredentialsStore = fetcher.CredentialsStore;

pub const ProfileEntry = struct {
    allocator: Allocator,
    /// Heap-owned. "" means use env/default credential chain.
    name: []u8,
    store: CredentialsStore,
    account_id: ?[]u8 = null,

    pub fn deinit(self: *ProfileEntry) void {
        self.allocator.free(self.name);
        if (self.account_id) |a| self.allocator.free(a);
        self.store.deinit();
    }

    pub fn displayName(self: *const ProfileEntry) []const u8 {
        return self.name;
    }
};

pub const ProfileSet = struct {
    allocator: Allocator,
    io: std.Io,
    env: std.process.Environ,
    entries: std.ArrayList(ProfileEntry),

    pub fn init(allocator: Allocator, io: std.Io, env: std.process.Environ) ProfileSet {
        return .{
            .allocator = allocator,
            .io = io,
            .env = env,
            .entries = .empty,
        };
    }

    pub fn deinit(self: *ProfileSet) void {
        for (self.entries.items) |*e| e.deinit();
        self.entries.deinit(self.allocator);
    }

    /// Pointer to the first entry's store. Caller must ensure at least one entry exists.
    pub fn primaryStore(self: *ProfileSet) *CredentialsStore {
        return &self.entries.items[0].store;
    }

    /// Pointer to the first entry.
    pub fn primaryEntry(self: *ProfileSet) *ProfileEntry {
        return &self.entries.items[0];
    }

    pub fn contains(self: *const ProfileSet, name: []const u8) bool {
        for (self.entries.items) |e| {
            if (std.mem.eql(u8, e.name, name)) return true;
        }
        return false;
    }

    pub fn indexOf(self: *const ProfileSet, name: []const u8) ?usize {
        for (self.entries.items, 0..) |e, i| {
            if (std.mem.eql(u8, e.name, name)) return i;
        }
        return null;
    }

    /// Add profile by name. No-op if already present. "" = env/default chain.
    pub fn add(self: *ProfileSet, name: []const u8) !void {
        if (self.contains(name)) return;
        var entry = try self.makeEntry(name);
        self.entries.append(self.allocator, entry) catch |err| {
            entry.deinit();
            return err;
        };
    }

    /// Replace all entries with the given names. All-or-nothing: rolls back on error.
    pub fn replaceWith(self: *ProfileSet, names: []const []const u8) !void {
        var new_list: std.ArrayList(ProfileEntry) = .empty;
        for (names) |name| {
            var entry = self.makeEntry(name) catch |err| {
                for (new_list.items) |*e| e.deinit();
                new_list.deinit(self.allocator);
                return err;
            };
            new_list.append(self.allocator, entry) catch |err| {
                entry.deinit();
                for (new_list.items) |*e| e.deinit();
                new_list.deinit(self.allocator);
                return err;
            };
        }
        for (self.entries.items) |*e| e.deinit();
        self.entries.deinit(self.allocator);
        self.entries = new_list;
    }

    /// Remove profile by name. Returns false if not found.
    pub fn remove(self: *ProfileSet, name: []const u8) bool {
        for (self.entries.items, 0..) |*e, i| {
            if (std.mem.eql(u8, e.name, name)) {
                e.deinit();
                _ = self.entries.orderedRemove(i);
                return true;
            }
        }
        return false;
    }

    /// Clear cached credentials for a named profile. Returns false if not found.
    pub fn clearCredentials(self: *ProfileSet, name: []const u8) bool {
        for (self.entries.items) |*e| {
            if (std.mem.eql(u8, e.name, name)) {
                if (e.store.credentials) |c| c.deinit(self.allocator);
                e.store.credentials = null;
                return true;
            }
        }
        return false;
    }

    pub fn clearAllCredentials(self: *ProfileSet) void {
        for (self.entries.items) |*e| {
            if (e.store.credentials) |c| c.deinit(self.allocator);
            e.store.credentials = null;
        }
    }

    fn makeEntry(self: *ProfileSet, name: []const u8) !ProfileEntry {
        const owned_name = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned_name);
        const profile_override: ?[]const u8 = if (name.len > 0 and !std.mem.eql(u8, name, "default")) owned_name else null;
        return .{
            .allocator = self.allocator,
            .name = owned_name,
            .store = CredentialsStore.init(self.allocator, self.io, self.env, .{
                .profile_name = profile_override,
            }),
        };
    }
};
