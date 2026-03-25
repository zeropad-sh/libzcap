pub const TcpSegment = struct {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    data_offset_flags: u16,
    window: u16,
    checksum: u16,
    urgent: u16,
    payload: []const u8,

    pub fn parse(buf: []const u8) error{TooShort}!TcpSegment {
        if (buf.len < 20) return error.TooShort;
        const dofflags = std.mem.readInt(u16, buf[12..14], .big);
        const doff = ((dofflags >> 12) & 0xF) * 4;
        if (doff < 20 or buf.len < doff) return error.TooShort;

        return .{
            .src_port = std.mem.readInt(u16, buf[0..2], .big),
            .dst_port = std.mem.readInt(u16, buf[2..4], .big),
            .seq = std.mem.readInt(u32, buf[4..8], .big),
            .ack = std.mem.readInt(u32, buf[8..12], .big),
            .data_offset_flags = dofflags,
            .window = std.mem.readInt(u16, buf[14..16], .big),
            .checksum = std.mem.readInt(u16, buf[16..18], .big),
            .urgent = std.mem.readInt(u16, buf[18..20], .big),
            .payload = buf[doff..buf.len],
        };
    }

    pub fn dataOffset(self: TcpSegment) u4 {
        return @truncate(self.data_offset_flags >> 12);
    }

    pub fn headerLen(self: TcpSegment) u8 {
        return @as(u8, self.dataOffset()) * 4;
    }

    pub fn flags(self: TcpSegment) TcpFlags {
        return @enumFromInt(self.data_offset_flags & 0x3F);
    }

    pub fn flagsRaw(self: TcpSegment) u8 {
        return @truncate(self.data_offset_flags);
    }

    pub const TcpFlags = packed struct(u8) {
        fin: bool,
        syn: bool,
        rst: bool,
        psh: bool,
        ack: bool,
        urg: bool,
        ece: bool,
        cwr: bool,
    };

    pub const Flag = enum(u8) {
        fin = 0x01,
        syn = 0x02,
        rst = 0x04,
        psh = 0x08,
        ack = 0x10,
        urg = 0x20,
        ece = 0x40,
        cwr = 0x80,
    };
};

const std = @import("std");
