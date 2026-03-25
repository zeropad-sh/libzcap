pub const UdpDatagram = struct {
    src_port: u16,
    dst_port: u16,
    length: u16,
    checksum: u16,
    payload: []const u8,

    pub fn parse(buf: []const u8) error{TooShort}!UdpDatagram {
        if (buf.len < 8) return error.TooShort;
        const len = std.mem.readInt(u16, buf[4..6], .big);
        const safe_len = @min(len, buf.len);
        if (safe_len < 8) return error.TooShort;

        return .{
            .src_port = std.mem.readInt(u16, buf[0..2], .big),
            .dst_port = std.mem.readInt(u16, buf[2..4], .big),
            .length = len,
            .checksum = std.mem.readInt(u16, buf[6..8], .big),
            .payload = buf[8..safe_len],
        };
    }

    pub fn dataLen(self: UdpDatagram) u16 {
        return @intCast(@min(self.payload.len, self.length -| 8));
    }

    pub const WellKnown = enum(u16) {
        dns = 53,
        dhcp_server = 67,
        dhcp_client = 68,
        tftp = 69,
        ntp = 123,
        radius = 1812,
        snmp = 161,
        ldap = 389,
        _,
    };
};

const std = @import("std");
