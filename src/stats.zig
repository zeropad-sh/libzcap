const std = @import("std");
const os = std.posix;
const builtin = @import("builtin");

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
        if (comptime builtin.os.tag == .linux) {
            return readPacketStatsLinux(fd);
        }
        return null;
    }
};

const PacketStats = extern struct {
    tp_packets: u32,
    tp_drops: u32,
};

const PacketStatsV3 = extern struct {
    tp_packets: u32,
    tp_drops: u32,
    tp_freeze_q_cnt: u32,
};

fn readPacketStatsLinux(fd: os.fd_t) ?CaptureStats {
    if (readPacketStatsV3(fd)) |stats| {
        return stats;
    }
    if (readPacketStatsV1(fd)) |stats| {
        return stats;
    }
    return null;
}

fn readPacketStatsV3(fd: os.fd_t) ?CaptureStats {
    const SOL_PACKET: i32 = 263;
    const PACKET_STATISTICS = 6;
    var stats = PacketStatsV3{
        .tp_packets = 0,
        .tp_drops = 0,
        .tp_freeze_q_cnt = 0,
    };

    os.getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, std.mem.asBytes(&stats)) catch return null;

    return .{
        .received = stats.tp_packets,
        .dropped = stats.tp_drops,
        .ifdropped = stats.tp_freeze_q_cnt,
    };
}

fn readPacketStatsV1(fd: os.fd_t) ?CaptureStats {
    const SOL_PACKET: i32 = 263;
    const PACKET_STATISTICS = 6;
    var stats = PacketStats{
        .tp_packets = 0,
        .tp_drops = 0,
    };

    os.getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, std.mem.asBytes(&stats)) catch return null;
    return .{
        .received = stats.tp_packets,
        .dropped = stats.tp_drops,
        .ifdropped = 0,
    };
}

test "stats basic" {
    var stats: Stats = .{};
    stats.addPacket(64);
    stats.addPacket(128);
    stats.addDrop(1);

    try std.testing.expectEqual(@as(u64, 2), stats.packets.load(.acquire));
    try std.testing.expectEqual(@as(u64, 192), stats.bytes.load(.acquire));
    try std.testing.expectEqual(@as(u64, 1), stats.drops.load(.acquire));
}
