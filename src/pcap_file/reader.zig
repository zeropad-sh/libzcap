pub const Magic = 0xa1b2c3d4;
pub const MagicSwapped = 0xd4c3b2a1;

pub const LinkType = enum(u32) {
    null = 0,
    ethernet = 1,
    raw = 101,
    loop = 108,
    linux_sll = 113,
    linux_sll2 = 276,
    _,
};

pub const GlobalHeader = extern struct {
    magic: u32,
    version_major: u16,
    version_minor: u16,
    thiszone: i32,
    sigfigs: u32,
    snaplen: u32,
    network: u32,
};

pub const PacketHeader = extern struct {
    ts_sec: u32,
    ts_usec: u32,
    incl_len: u32,
    orig_len: u32,
};

pub const Reader = struct {
    file: std.fs.File,
    header: GlobalHeader,
    endian: std.builtin.Endian,
    buf: [65536]u8 = undefined,

    pub fn open(path: []const u8) !Reader {
        const file = try std.fs.cwd().openFile(path, .{ .mode = .read_only });
        errdefer file.close();
        return try Reader.init(file);
    }

    pub fn init(file: std.fs.File) !Reader {
        var header: GlobalHeader = undefined;
        _ = try file.readAll(std.mem.asBytes(&header));

        const swapped: bool = if (header.magic == Magic)
            false
        else if (header.magic == MagicSwapped)
            true
        else
            return error.InvalidMagic;

        const endian: std.builtin.Endian = if (swapped) .little else .big;
        if (swapped) {
            header.magic = @byteSwap(header.magic);
            header.version_major = @byteSwap(header.version_major);
            header.version_minor = @byteSwap(header.version_minor);
            header.thiszone = @byteSwap(header.thiszone);
            header.sigfigs = @byteSwap(header.sigfigs);
            header.snaplen = @byteSwap(header.snaplen);
            header.network = @byteSwap(header.network);
        }

        return .{ .file = file, .header = header, .endian = endian };
    }

    pub fn next(self: *Reader) !?struct { header: PacketHeader, data: []u8 } {
        var pkt_hdr: PacketHeader = undefined;
        const n = try self.file.read(std.mem.asBytes(&pkt_hdr));
        if (n == 0) return null;

        if (self.endian == .little) {
            pkt_hdr.ts_sec = @byteSwap(pkt_hdr.ts_sec);
            pkt_hdr.ts_usec = @byteSwap(pkt_hdr.ts_usec);
            pkt_hdr.incl_len = @byteSwap(pkt_hdr.incl_len);
            pkt_hdr.orig_len = @byteSwap(pkt_hdr.orig_len);
        }

        if (pkt_hdr.incl_len > self.header.snaplen)
            return error.PacketTooBig;

        if (pkt_hdr.incl_len > self.buf.len)
            return error.PacketTooBig;

        _ = try self.file.readAll(self.buf[0..pkt_hdr.incl_len]);

        return .{ .header = pkt_hdr, .data = self.buf[0..pkt_hdr.incl_len] };
    }
};

const std = @import("std");
