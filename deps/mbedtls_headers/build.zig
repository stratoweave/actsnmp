// Headers-only shim for the mbedtls that Acton's base library already links.
//
// libActon links mbedcrypto/mbedtls/mbedx509 as static archives into every
// Acton program, so the mbedtls functions used by src/usmcrypto.ext.c are
// already present at link time. This package only installs <mbedtls/*.h> and
// <psa/*.h> from the toolchain's own mbedtls tree, so the headers always match
// the linked objects. It does NOT compile or link mbedtls itself.
//
// Build.act passes the toolchain deps dir as a LazyPath:
//   options={"acton_sysdeps": "actonbase_dep.path(\"../deps\")"}
// which resolves to <acton dist>/deps wherever the compiler is installed.
// A plain string also works: -Dacton_sysdeps=/path/to/acton/dist/deps
const std = @import("std");

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});
    const target = b.standardTargetOptions(.{});
    const acton_sysdeps = b.option(std.Build.LazyPath, "acton_sysdeps", "The Acton toolchain deps dir (<acton dist>/deps)");

    const lib = b.addLibrary(.{
        .name = "mbedtls_headers",
        .linkage = .static,
        .root_module = b.createModule(.{ .target = target, .optimize = optimize }),
    });
    lib.root_module.addCSourceFile(.{ .file = b.path("empty.c"), .flags = &.{} });
    lib.root_module.link_libc = true;
    if (acton_sysdeps) |deps| {
        lib.installHeadersDirectory(deps.path(b, "mbedtls/include/mbedtls"), "mbedtls", .{});
        lib.installHeadersDirectory(deps.path(b, "mbedtls/include/psa"), "psa", .{});
    } else {
        const fail = b.addFail("mbedtls_headers: -Dacton_sysdeps is required (set it via options= in Build.act)");
        lib.step.dependOn(&fail.step);
    }
    b.installArtifact(lib);
}
