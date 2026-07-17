const std = @import("std");

pub fn build(b: *std.Build) void {
    const optimize = std.builtin.OptimizeMode.ReleaseSmall;
    const target = b.standardTargetOptions(.{});

    const exe = b.addExecutable(.{
        .name = "a9s",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    if (target.result.os.tag == .macos) {
        exe.root_module.link_libc = true;
    }
    b.installArtifact(exe);

    const exe_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_exe_tests = b.addRunArtifact(exe_tests);
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_exe_tests.step);
}
