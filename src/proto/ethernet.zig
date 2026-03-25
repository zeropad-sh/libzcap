pub const EthernetFrame = struct {
    dst: [6]u8,
    src: [6]u8,
    ethertype: u16,
    payload: []const u8,

    pub fn parse(buf: []const u8) error{TooShort}!EthernetFrame {
        if (buf.len < 14) return error.TooShort;
        return .{
            .dst = buf[0..6].*,
            .src = buf[6..12].*,
            .ethertype = std.mem.readInt(u16, buf[12..14], .big),
            .payload = buf[14..buf.len],
        };
    }

    pub fn parseInto(buf: []const u8, frame: *EthernetFrame) error{TooShort}!*EthernetFrame {
        if (buf.len < 14) return error.TooShort;
        @memcpy(frame.dst[0..6], buf[0..6]);
        @memcpy(frame.src[0..6], buf[6..12]);
        frame.ethertype = std.mem.readInt(u16, buf[12..14], .big);
        frame.payload = buf[14..buf.len];
        return frame;
    }

    pub const EtherType = enum(u16) {
        ipv4 = 0x0800,
        arp = 0x0806,
        rarp = 0x8035,
        ipv6 = 0x86DD,
        vlan = 0x8100,
        ethtag = 0x88A8,
        _,
    };

    pub fn etherType(self: EthernetFrame) EtherType {
        return @enumFromInt(self.ethertype);
    }
};

const std = @import("std");
