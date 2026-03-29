const std = @import("std");
const os = std.posix;

pub const KernelFeatures = enum(u32) {
    basic = 1 << 0,
    ring_v3 = 1 << 1,
    fanout = 1 << 5,
    busy_poll = 1 << 6,
    ebpf = 1 << 2,
    hw_tstamp = 1 << 3,
    af_xdp = 1 << 4,
};

pub const KernelVersion = struct {
    major: u32,
    minor: u32,
    patch: u32,

    pub fn detect() KernelVersion {
        return readUtsRelease();
    }

    fn readUtsRelease() KernelVersion {
        const fd = os.open("/proc/version", .{ .ACCMODE = .RDONLY }, 0) catch return .{ .major = 2, .minor = 2, .patch = 0 };
        defer os.close(fd);

        var buf: [256]u8 = undefined;
        const n = os.read(fd, &buf) catch return .{ .major = 2, .minor = 2, .patch = 0 };
        const content = buf[0..n];

        var major: u32 = 2;
        var minor: u32 = 2;
        var patch: u32 = 0;

        const prefix = "Linux version ";
        if (std.mem.startsWith(u8, content, prefix)) {
            const ver = content[prefix.len..];
            var remaining = ver;

            var dot_it = std.mem.indexOfScalar(u8, remaining, '.');
            if (dot_it) |idx| {
                major = parseNumber(remaining[0..idx]) catch 2;
                remaining = remaining[idx + 1 ..];

                dot_it = std.mem.indexOfScalar(u8, remaining, '.');
                if (dot_it) |idx2| {
                    minor = parseNumber(remaining[0..idx2]) catch 0;
                    remaining = remaining[idx2 + 1 ..];

                    var space_it = std.mem.indexOfScalar(u8, remaining, ' ');
                    if (space_it == null) space_it = std.mem.indexOfScalar(u8, remaining, '-');
                    const end = space_it orelse remaining.len;
                    patch = parseNumber(remaining[0..end]) catch 0;
                }
            }
        }

        return .{ .major = major, .minor = minor, .patch = patch };
    }

    fn parseNumber(s: []const u8) !u32 {
        return std.fmt.parseInt(u32, s, 10);
    }

    pub fn supports(self: KernelVersion, feature: KernelFeatures) bool {
        return switch (feature) {
            .basic => true,
            .ring_v3 => self.major > 3 or (self.major == 3 and self.minor >= 2),
            .fanout => self.major > 2 or (self.major == 2 and self.minor >= 6 and self.patch >= 37),
            .busy_poll => self.major > 3 or (self.major == 3 and self.minor >= 11),
            .ebpf => self.major > 3 or (self.major == 3 and self.minor >= 19),
            .hw_tstamp => self.major >= 4,
            .af_xdp => self.major >= 5 or (self.major == 4 and self.minor >= 18),
        };
    }

    pub fn detectFeatures(self: KernelVersion) u32 {
        var features: u32 = 0;
        inline for (std.meta.fields(KernelFeatures)) |field| {
            if (self.supports(@enumFromInt(field.value))) {
                features |= field.value;
            }
        }
        return features;
    }

    pub fn supportsAtLeast(self: KernelVersion, major: u32, minor: u32) bool {
        if (self.major > major) return true;
        if (self.major < major) return false;
        return self.minor >= minor;
    }

    pub fn supportsExact(self: KernelVersion, major: u32, minor: u32, patch: u32) bool {
        return self.major == major and self.minor == minor and self.patch == patch;
    }
};

pub fn detectFeatures() u32 {
    return KernelVersion.detect().detectFeatures();
}

test "kernel version parsing" {
    const v1: KernelVersion = .{ .major = 5, .minor = 15, .patch = 0 };
    try std.testing.expect(v1.supports(.basic));
    try std.testing.expect(v1.supports(.ring_v3));
    try std.testing.expect(v1.supports(.ebpf));
    try std.testing.expect(v1.supports(.hw_tstamp));
    try std.testing.expect(v1.supports(.af_xdp));

    const v2: KernelVersion = .{ .major = 3, .minor = 10, .patch = 0 };
    try std.testing.expect(v2.supports(.basic));
    try std.testing.expect(v2.supports(.ring_v3));
    try std.testing.expect(!v2.supports(.ebpf));
    try std.testing.expect(!v2.supports(.hw_tstamp));
    try std.testing.expect(!v2.supports(.af_xdp));

    const v3: KernelVersion = .{ .major = 2, .minor = 6, .patch = 32 };
    try std.testing.expect(v3.supports(.basic));
    try std.testing.expect(!v3.supports(.ring_v3));
}
