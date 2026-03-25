const std = @import("std");
const libzcap = @import("../lib.zig");

pub const NativeOptions = struct {
    device: []const u8,
    snaplen: u32 = 65535,
    promisc: bool = false,
    timeout_ms: u32 = 1000,
    filter: ?[]const u8 = null,
    buffer: BufferMode = .copy,
};

pub const BufferMode = enum {
    copy,
    ring_mmap,
};

pub const Capture = struct {
    handle: libzcap.Handle,
    counters: libzcap.stats.Stats,

    pub fn init(opts: NativeOptions) !Capture {
        const handle = try libzcap.Handle.open(.{
            .device = opts.device,
            .snaplen = opts.snaplen,
            .promisc = opts.promisc,
            .timeout_ms = opts.timeout_ms,
            .filter = opts.filter,
            .buffer_mode = switch (opts.buffer) {
                .copy => .copy,
                .ring_mmap => .ring_mmap,
            },
        });

        return .{
            .handle = handle,
            .counters = .{},
        };
    }

    pub fn deinit(self: *Capture) void {
        self.handle.deinit();
    }

    pub fn next(self: *Capture) !?libzcap.PacketView {
        const pkt = self.handle.next() catch |err| {
            if (err == libzcap.Error.Timeout) {
                return null;
            }
            return err;
        };
        self.counters.addPacket(pkt.captured_len);
        return pkt;
    }

    pub fn getCounters(self: *const Capture) libzcap.stats.Stats {
        return self.counters;
    }
};

pub const File = struct {
    reader: ?libzcap.pcap_file.Reader = null,
    writer: ?libzcap.pcap_file.Writer = null,
    path: []const u8,
    mode: enum { read, write },

    pub fn open(path: []const u8) !File {
        const reader = try libzcap.pcap_file.Reader.open(path);
        return .{
            .reader = reader,
            .path = path,
            .mode = .read,
        };
    }

    pub fn create(path: []const u8, snaplen: u32, link_type: enum { ethernet, raw, linux_sll }) !File {
        const lt: libzcap.pcap_file.Writer.LinkType = switch (link_type) {
            .ethernet => .ethernet,
            .raw => .raw,
            .linux_sll => .linux_sll,
        };
        const writer = try libzcap.pcap_file.Writer.create(path, snaplen, lt);
        return .{
            .writer = writer,
            .path = path,
            .mode = .write,
        };
    }

    pub fn nextPacket(self: *File) !?libzcap.pcap_file.PacketHeader {
        if (self.reader) |*r| {
            return r.next() catch |err| {
                if (err == error.EndOfStream) return null;
                return err;
            };
        }
        return null;
    }

    pub fn writePacket(self: *File, timestamp_ns: u64, data: []const u8) !void {
        if (self.writer) |*w| {
            try w.write(timestamp_ns, data);
        }
    }

    pub fn close(self: *File) void {
        if (self.reader) |*r| {
            r.file.close();
            self.reader = null;
        }
        if (self.writer) |*w| {
            w.deinit();
            self.writer = null;
        }
    }
};

pub fn parseEthernet(data: []const u8) !libzcap.proto.EthernetFrame {
    return libzcap.proto.EthernetFrame.parse(data);
}

pub fn parseIPv4(data: []const u8) !libzcap.proto.IPv4Packet {
    return libzcap.proto.IPv4Packet.parse(data);
}

pub fn parseIPv6(data: []const u8) !libzcap.proto.IPv6Packet {
    return libzcap.proto.IPv6Packet.parse(data);
}

pub fn parseTCP(data: []const u8) !libzcap.proto.TcpSegment {
    return libzcap.proto.TcpSegment.parse(data);
}

pub fn parseUDP(data: []const u8) !libzcap.proto.UdpDatagram {
    return libzcap.proto.UdpDatagram.parse(data);
}
