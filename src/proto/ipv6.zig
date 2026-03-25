pub const IPv6Packet = struct {
    version_class_flow: u32,
    payload_len: u16,
    next_header: u8,
    hop_limit: u8,
    src: [16]u8,
    dst: [16]u8,
    payload: []const u8,

    pub fn parse(buf: []const u8) error{TooShort}!IPv6Packet {
        if (buf.len < 40) return error.TooShort;
        const base = std.mem.readInt(u32, buf[0..4], .big);
        return .{
            .version_class_flow = base,
            .payload_len = std.mem.readInt(u16, buf[4..6], .big),
            .next_header = buf[6],
            .hop_limit = buf[7],
            .src = buf[8..24].*,
            .dst = buf[24..40].*,
            .payload = buf[40..buf.len],
        };
    }

    pub fn version(self: IPv6Packet) u4 {
        return @truncate(self.version_class_flow >> 28);
    }

    pub const NextHeader = enum(u8) {
        tcp = 6,
        udp = 17,
        icmpv6 = 58,
        sctp = 132,
        _,
    };

    pub fn nextHeader(self: IPv6Packet) NextHeader {
        return @enumFromInt(self.next_header);
    }

    pub fn srcString(self: IPv6Packet, buf: *[46]u8) []u8 {
        var src_arr: [16]u8 = self.src;
        return formatIpv6(&src_arr, buf);
    }

    pub fn dstString(self: IPv6Packet, buf: *[46]u8) []u8 {
        var dst_arr: [16]u8 = self.dst;
        return formatIpv6(&dst_arr, buf);
    }

    fn formatIpv6(addr: *[16]u8, buf: *[46]u8) []u8 {
        var pos: usize = 0;
        for (0..8) |i| {
            const word = (@as(u16, addr[i * 2])) << 8 | @as(u16, addr[i * 2 + 1]);
            // Format as hex (lowercase)
            const hex_chars = "0123456789abcdef";
            var nibble_buf: [4]u8 = undefined;
            nibble_buf[0] = hex_chars[(word >> 12) & 0xF];
            nibble_buf[1] = hex_chars[(word >> 8) & 0xF];
            nibble_buf[2] = hex_chars[(word >> 4) & 0xF];
            nibble_buf[3] = hex_chars[word & 0xF];

            // Copy to output
            @memcpy(buf[pos..][0..4], &nibble_buf);
            pos += 4;

            if (i < 7) {
                buf[pos] = ':';
                pos += 1;
            }
        }
        return buf[0..pos];
    }
};

const std = @import("std");
