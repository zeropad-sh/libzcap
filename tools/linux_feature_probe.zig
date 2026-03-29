const std = @import("std");
const builtin = @import("builtin");
const libzcap = @import("libzcap");
const kernel = libzcap.kernel;

const BufferMode = libzcap.BufferMode;

const ProbeError = error{AssertionFailed};

fn resolveBufferModeForProbe(
    kernel_features: u32,
    requested: BufferMode,
    fallback_to_copy: bool,
) !BufferMode {
    if (requested != .ring_mmap) return .copy;
    if (kernel_features & @intFromEnum(kernel.KernelFeatures.ring_v3) == 0) {
        if (!fallback_to_copy) return libzcap.Error.RingSetupFailed;
        return .copy;
    }
    return .ring_mmap;
}

fn printFeatureLine(
    label: []const u8,
    version: kernel.KernelVersion,
    features: u32,
) void {
    std.debug.print(
        "{s}: {d}.{d}.{d} ring={any} fanout={any} busy_poll={any}\n",
        .{
            label,
            version.major,
            version.minor,
            version.patch,
            features & @intFromEnum(kernel.KernelFeatures.ring_v3) != 0,
            features & @intFromEnum(kernel.KernelFeatures.fanout) != 0,
            features & @intFromEnum(kernel.KernelFeatures.busy_poll) != 0,
        },
    );
}

fn expectLabelled(condition: bool, comptime label: []const u8) !void {
    if (!condition) {
        std.debug.print("FAIL: {s}\n", .{label});
        return ProbeError.AssertionFailed;
    }
    return;
}

pub fn main() !void {
    if (builtin.os.tag != .linux) {
        std.debug.print("Skipping linux feature probe on {s}\n", .{@tagName(builtin.os.tag)});
        return;
    }

    std.debug.print("=== libzcap linux kernel feature probe ===\n", .{});

    const legacy_features = @intFromEnum(kernel.KernelFeatures.basic);
    const modern_features =
        legacy_features |
        @intFromEnum(kernel.KernelFeatures.ring_v3) |
        @intFromEnum(kernel.KernelFeatures.fanout) |
        @intFromEnum(kernel.KernelFeatures.busy_poll);

    const table = [_]kernel.KernelVersion{
        .{ .major = 2, .minor = 6, .patch = 36 },
        .{ .major = 2, .minor = 6, .patch = 37 },
        .{ .major = 3, .minor = 1, .patch = 0 },
        .{ .major = 3, .minor = 2, .patch = 0 },
        .{ .major = 3, .minor = 10, .patch = 0 },
        .{ .major = 3, .minor = 11, .patch = 0 },
        .{ .major = 4, .minor = 18, .patch = 0 },
        .{ .major = 5, .minor = 15, .patch = 0 },
    };

    for (table) |v| {
        const f = v.detectFeatures();
        printFeatureLine("kernel", v, f);
    }

    const host = kernel.KernelVersion.detect();
    const host_features = host.detectFeatures();

    printFeatureLine("host", host, host_features);

    try expectLabelled(host_features & @intFromEnum(kernel.KernelFeatures.basic) != 0, "basic features must be present");

    try expectLabelled(table[0].detectFeatures() & @intFromEnum(kernel.KernelFeatures.ring_v3) == 0, "2.6.36 should not have ring_v3");
    try expectLabelled(table[1].detectFeatures() & @intFromEnum(kernel.KernelFeatures.fanout) != 0, "2.6.37 should support fanout");
    try expectLabelled(table[2].detectFeatures() & @intFromEnum(kernel.KernelFeatures.ring_v3) == 0, "3.1 should not have ring_v3");
    try expectLabelled(table[3].detectFeatures() & @intFromEnum(kernel.KernelFeatures.ring_v3) != 0, "3.2 should have ring_v3");
    try expectLabelled(table[4].detectFeatures() & @intFromEnum(kernel.KernelFeatures.busy_poll) == 0, "3.10 should not have busy_poll");
    try expectLabelled(table[5].detectFeatures() & @intFromEnum(kernel.KernelFeatures.busy_poll) != 0, "3.11 should have busy_poll");
    try expectLabelled(table[6].detectFeatures() & @intFromEnum(kernel.KernelFeatures.af_xdp) != 0, "4.18 should have af_xdp");

    try expectLabelled(
        (try resolveBufferModeForProbe(legacy_features, .ring_mmap, true)) == .copy,
        "legacy host kernel should fall back to copy mode",
    );
    if (resolveBufferModeForProbe(legacy_features, .ring_mmap, false)) |_| {
        return ProbeError.AssertionFailed;
    } else |err| {
        try expectLabelled(err == libzcap.Error.RingSetupFailed, "legacy no-fallback must return RingSetupFailed");
    }
    try expectLabelled(
        (try resolveBufferModeForProbe(modern_features, .ring_mmap, true)) == .ring_mmap,
        "modern kernel should keep ring_mmap mode",
    );

    const runtime_mode = switch (try resolveBufferModeForProbe(host_features, .ring_mmap, true)) {
        .ring_mmap => "ring_mmap",
        .copy => "copy",
    };

    std.debug.print("runtime_mode_if_requested: {s}\n", .{runtime_mode});
    std.debug.print("feature_probe PASS\n", .{});
}
