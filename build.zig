const pkgs = @import("deps.zig").pkgs;
const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const mode = b.standardReleaseOptions();
    const target = b.standardTargetOptions(.{});

    const lib = b.addStaticLibrary("nats", "src/main.zig");
    lib.setBuildMode(mode);
    lib.install();
    pkgs.addAllTo(lib);

    var main_tests = b.addTest("src/main.zig");
    main_tests.setBuildMode(mode);
    pkgs.addAllTo(main_tests);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests.step);

    const example = b.addExecutable("example", "example/main.zig");
    example.setBuildMode(mode);
    example.setTarget(target);
    pkgs.addAllTo(example);
    example.addPackage(.{
        .name = b.dupe("nats"),
        .path = .{ .path = b.dupe("src/main.zig") },
        .dependencies = &[_]std.build.Pkg{
            pkgs.nkeys,
            pkgs.uri,
            pkgs.iguanaTLS,
        },
    });

    const example_install = b.addInstallArtifact(example);

    const example_step = b.step("example", "Build example");
    example_step.dependOn(&example_install.step);

    const example_run_cmd = example.run();
    example_run_cmd.step.dependOn(&example_install.step);
    if (b.args) |args| {
        example_run_cmd.addArgs(args);
    }

    const example_run_step = b.step("run-example", "Run example");
    example_run_step.dependOn(&example_run_cmd.step);
}
