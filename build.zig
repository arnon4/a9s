const std = @import("std");

pub fn build(b: *std.Build) void {
    const optimize = std.builtin.OptimizeMode.ReleaseSmall;

    const targets: []const std.Target.Query = &.{
        .{ .cpu_arch = .x86_64, .os_tag = .windows, .abi = .gnu },
        .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .musl },
        // TODO: add Mac
    };

    for (targets) |t| {
        const target = b.resolveTargetQuery(t);
        const exe = b.addExecutable(.{
            .name = "a9s",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/main.zig"),
                .target = target,
                .optimize = optimize,
            }),
        });
        if (t.os_tag == .macos) {
            exe.root_module.link_libc = true;
        }
        b.installArtifact(exe);
    }

    // Tests run against the native target
    const native_target = b.standardTargetOptions(.{});
    const exe_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = native_target,
            .optimize = optimize,
        }),
    });
    const run_exe_tests = b.addRunArtifact(exe_tests);
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_exe_tests.step);
}
