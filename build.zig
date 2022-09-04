const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const mode = b.standardReleaseOptions();

    const lib = b.addStaticLibrary("xxhash-simple", "src/xxhash.zig");
    setup_xxhash(lib);
    lib.setBuildMode(mode);
    lib.install();

    const main_tests = b.addTest("src/xxhash.zig");
    setup_xxhash(main_tests);
    main_tests.setBuildMode(mode);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests.step);
}

fn setup_xxhash(step: *std.build.LibExeObjStep) void {
    step.addPackage(.{ .name = "xxhash-simple", .source = std.build.FileSource{ .path = "./src/xxhash.zig" } });
}
