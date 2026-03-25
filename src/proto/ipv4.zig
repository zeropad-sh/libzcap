pub const IPv4Packet = struct {
    version_ihl: u8,
    tos: u8,
    length: u16,
    identification: u16,
    flags_fragment: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    src: u32,
    dst: u32,
    options: []const u8,
    payload: []const u8,

    pub fn parse(buf: []const u8) error{TooShort}!IPv4Packet {
        if (buf.len < 20) return error.TooShort;
        const vihl = buf[0];
        const hdr_len = (vihl & 0x0F) * 4;
        if (hdr_len < 20 or buf.len < hdr_len) return error.TooShort;

        return .{
            .version_ihl = vihl,
            .tos = buf[1],
            .length = std.mem.readInt(u16, buf[2..4], .big),
            .identification = std.mem.readInt(u16, buf[4..6], .big),
            .flags_fragment = std.mem.readInt(u16, buf[6..8], .big),
            .ttl = buf[8],
            .protocol = buf[9],
            .checksum = std.mem.readInt(u16, buf[10..12], .big),
            .src = std.mem.readInt(u32, buf[12..16], .big),
            .dst = std.mem.readInt(u32, buf[16..20], .big),
            .options = buf[20..hdr_len],
            .payload = buf[hdr_len..buf.len],
        };
    }

    pub fn version(self: IPv4Packet) u4 {
        return @truncate(self.version_ihl >> 4);
    }

    pub fn ihl(self: IPv4Packet) u4 {
        return @truncate(self.version_ihl);
    }

    pub fn headerLen(self: IPv4Packet) u8 {
        return @as(u8, self.ihl()) * 4;
    }

    pub fn totalLen(self: IPv4Packet) u16 {
        return self.length;
    }

    pub fn dataLen(self: IPv4Packet) u16 {
        return @intCast(@min(self.payload.len, self.length -| self.headerLen()));
    }

    pub const Protocol = enum(u8) {
        icmp = 1,
        igmp = 2,
        tcp = 6,
        udp = 17,
        ipv6 = 41,
        gre = 47,
        esp = 50,
        ah = 51,
        icmpv6 = 58,
        ospf = 89,
        sctp = 132,
        _,
    };

    pub fn protocolNum(self: IPv4Packet) Protocol {
        return @enumFromInt(self.protocol);
    }

    pub fn srcString(self: IPv4Packet, buf: *[15]u8) []u8 {
        const a: u8 = @truncate(self.src >> 24);
        const b: u8 = @truncate(self.src >> 16);
        const c: u8 = @truncate(self.src >> 8);
        const d: u8 = @truncate(self.src);
        return std.fmt.bufPrint(buf, "{}.{}.{}.{}", .{ a, b, c, d }) catch unreachable;
    }

    pub fn dstString(self: IPv4Packet, buf: *[15]u8) []u8 {
        const a: u8 = @truncate(self.dst >> 24);
        const b: u8 = @truncate(self.dst >> 16);
        const c: u8 = @truncate(self.dst >> 8);
        const d: u8 = @truncate(self.dst);
        return std.fmt.bufPrint(buf, "{}.{}.{}.{}", .{ a, b, c, d }) catch unreachable;
    }
};

const std = @import("std");
