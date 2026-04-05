const std = @import("std");
const testing = std.testing;
const KernelVersion = @import("libzcap").kernel.KernelVersion;

test "kernel version supports basic" {
    const v = KernelVersion{ .major = 2, .minor = 2, .patch = 0 };
    try testing.expect(v.supports(.basic));
}

test "kernel version supports ring v3 from 3.2" {
    const v1 = KernelVersion{ .major = 3, .minor = 1, .patch = 0 };
    try testing.expect(!v1.supports(.ring_v3));

    const v2 = KernelVersion{ .major = 3, .minor = 2, .patch = 0 };
    try testing.expect(v2.supports(.ring_v3));

    const v3 = KernelVersion{ .major = 3, .minor = 10, .patch = 0 };
    try testing.expect(v3.supports(.ring_v3));
}

test "kernel version supports ebpf from 3.19" {
    const v1 = KernelVersion{ .major = 3, .minor = 18, .patch = 0 };
    try testing.expect(!v1.supports(.ebpf));

    const v2 = KernelVersion{ .major = 3, .minor = 19, .patch = 0 };
    try testing.expect(v2.supports(.ebpf));
}

test "kernel version supports af_xdp from 4.18" {
    const v1 = KernelVersion{ .major = 4, .minor = 17, .patch = 0 };
    try testing.expect(!v1.supports(.af_xdp));

    const v2 = KernelVersion{ .major = 4, .minor = 18, .patch = 0 };
    try testing.expect(v2.supports(.af_xdp));

    const v3 = KernelVersion{ .major = 5, .minor = 4, .patch = 0 };
    try testing.expect(v3.supports(.af_xdp));
}

test "kernel version supportsAtLeast" {
    const v = KernelVersion{ .major = 5, .minor = 15, .patch = 0 };
    try testing.expect(v.supportsAtLeast(5, 15));
    try testing.expect(v.supportsAtLeast(5, 10));
    try testing.expect(v.supportsAtLeast(4, 0));
    try testing.expect(!v.supportsAtLeast(6, 0));
    try testing.expect(!v.supportsAtLeast(5, 20));
}

test "kernel version supports fanout from 2.6.37" {
    const v1 = .{ .major = 2, .minor = 6, .patch = 36 };
    try testing.expect(!v1.supports(.fanout));

    const v2 = .{ .major = 2, .minor = 6, .patch = 37 };
    try testing.expect(v2.supports(.fanout));
}

test "kernel version supports busy poll from 3.11" {
    const v1 = .{ .major = 3, .minor = 10, .patch = 0 };
    try testing.expect(!v1.supports(.busy_poll));

    const v2 = .{ .major = 3, .minor = 11, .patch = 0 };
    try testing.expect(v2.supports(.busy_poll));
}
