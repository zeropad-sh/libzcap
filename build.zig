const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("libzcap", .{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addLibrary(.{
        .linkage = .dynamic,
        .name = "zcap",
        .root_module = mod,
    });
    lib.linker_allow_shlib_undefined = true;
    if (optimize == .ReleaseFast) {
        lib.root_module.strip = true;
    }
    lib.installHeadersDirectory(b.path("include"), "", .{});
    b.installArtifact(lib);

    const cli = b.addExecutable(.{
        .name = "zigdump",
        .root_module = b.createModule(.{
            .root_source_file = b.path("cli/main.zig"),
            .imports = &.{.{ .name = "libzcap", .module = mod }},
            .target = target,
            .optimize = optimize,
        }),
    });
    if (optimize == .ReleaseFast) {
        cli.root_module.strip = true;
    }
    b.installArtifact(cli);

    const run_step = b.step("run", "Run zigdump");
    const run_cmd = b.addRunArtifact(cli);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);

    const tests = b.addTest(.{
        .root_module = mod,
    });
    const test_step = b.step("test", "Run tests");
    const run_tests = b.addRunArtifact(tests);
    if (b.args) |args| {
        run_tests.addArgs(args);
    }
    test_step.dependOn(&run_tests.step);

    const feature_probe = b.addExecutable(.{
        .name = "linux-feature-probe",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/linux_feature_probe.zig"),
            .imports = &.{.{ .name = "libzcap", .module = mod }},
            .target = target,
            .optimize = optimize,
        }),
    });

    const run_feature_probe = b.addRunArtifact(feature_probe);
    const feature_probe_step = b.step("feature-probe", "Run linux kernel feature probe");
    if (b.args) |args| {
        run_feature_probe.addArgs(args);
    }
    feature_probe_step.dependOn(&run_feature_probe.step);
}
