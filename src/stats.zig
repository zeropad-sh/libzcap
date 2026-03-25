const std = @import("std");
const os = std.posix;

pub const Stats = struct {
    packets: std.atomic.Value(u64) = .{ .raw = 0 },
    drops: std.atomic.Value(u64) = .{ .raw = 0 },
    bytes: std.atomic.Value(u64) = .{ .raw = 0 },

    pub fn reset(self: *Stats) void {
        self.packets.store(0, .release);
        self.drops.store(0, .release);
        self.bytes.store(0, .release);
    }

    pub fn addPacket(self: *Stats, len: u32) void {
        _ = self.packets.fetchAdd(1, .release);
        _ = self.bytes.fetchAdd(len, .release);
    }

    pub fn addDrop(self: *Stats, count: u64) void {
        _ = self.drops.fetchAdd(count, .release);
    }
};

pub const CaptureStats = struct {
    received: u64 = 0,
    dropped: u64 = 0,
    ifdropped: u64 = 0,
    captured: u64 = 0,
    accepted: u64 = 0,
    filtered: u64 = 0,

    pub fn reset(self: *CaptureStats) void {
        self.* = .{};
    }

    pub fn fromSocket(fd: os.fd_t) ?CaptureStats {
        var stats: os.packet_stat = undefined;
        const res = os.ioctl(fd, 0x0001, @intFromPtr(&stats));
        if (res == 0) {
            return .{
                .received = stats.ps_recv,
                .dropped = stats.ps_drop,
                .ifdropped = stats.ps_ifdrop,
            };
        }
        return null;
    }
};

test "stats basic" {
    var stats: Stats = .{};
    stats.addPacket(64);
    stats.addPacket(128);
    stats.addDrop(1);

    try std.testing.expectEqual(@as(u64, 2), stats.packets.load(.acquire));
    try std.testing.expectEqual(@as(u64, 192), stats.bytes.load(.acquire));
    try std.testing.expectEqual(@as(u64, 1), stats.drops.load(.acquire));
}
