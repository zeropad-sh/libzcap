const std = @import("std");

pub const SctpDatagram = struct {
    src_port: u16,
    dst_port: u16,
    verification_tag: u32,
    checksum: u32,
    payload: []const u8,

    pub fn parse(buf: []const u8) error{TooShort}!SctpDatagram {
        if (buf.len < 12) return error.TooShort;
        return .{
            .src_port = std.mem.readInt(u16, buf[0..2], .big),
            .dst_port = std.mem.readInt(u16, buf[2..4], .big),
            .verification_tag = std.mem.readInt(u32, buf[4..8], .big),
            // SCTP uses CRC32c which is little-endian natively over the wire
            .checksum = std.mem.readInt(u32, buf[8..12], .little),
            .payload = buf[12..buf.len],
        };
    }

    pub fn dataLen(self: SctpDatagram) u16 {
        return @intCast(self.payload.len);
    }
};
