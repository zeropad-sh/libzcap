const std = @import("std");
const libzcap = struct {
    pub const Handle = @import("../capture/handle.zig").Handle;
    pub const CaptureOptions = @import("../capture/handle.zig").CaptureOptions;
    pub const PacketView = @import("../capture/handle.zig").PacketView;
};

// libpcap C-ABI matching struct wraps our internal zero-cost Handle
pub const zpcap_t = opaque {};

const PcapContext = struct {
    handle: *libzcap.Handle,
    allocator: std.mem.Allocator,
};

pub const zpcap_pkthdr = extern struct {
    ts: timeval,
    caplen: u32,
    len: u32,
};

const timeval = extern struct {
    tv_sec: i32,
    tv_usec: i32,
};

pub const ZPCAP_ERRBUF_SIZE: usize = 256;

// Drop-in wrapper exporting libpcap's standard pcap_open_live
// Instead of fetching from a loaded libpcap dependency, it builds our
// ultra-fast hardware-level ring buffer zig handlers under the hood.
export fn zpcap_open_live(
    device: [*:0]const u8,
    snaplen: c_int,
    promisc: c_int,
    to_ms: c_int,
    errbuf: [*]u8,
) ?*zpcap_t {
    var alloc = std.heap.page_allocator;
    const dev_str = std.mem.span(device);

    const h = alloc.create(libzcap.Handle) catch {
        setText(errbuf, "Out of memory allocating handle");
        return null;
    };
    
    h.* = libzcap.Handle.open(.{
        .device = dev_str,
        .snaplen = @intCast(snaplen),
        .promisc = (promisc != 0),
        .timeout_ms = @intCast(to_ms),
        .buffer_mode = .ring_mmap,
    }) catch |err| {
        alloc.destroy(h);
        setText(errbuf, @errorName(err));
        return null;
    };

    const ctx = alloc.create(PcapContext) catch {
        h.deinit();
        alloc.destroy(h);
        setText(errbuf, "Out of memory allocating pcap wrapper");
        return null;
    };
    
    ctx.* = .{
        .handle = h,
        .allocator = alloc,
    };
    return @ptrCast(ctx);
}

export fn zpcap_next(p: *zpcap_t, h: [*]zpcap_pkthdr) ?[*]u8 {
    const ctx: *PcapContext = @ptrCast(@alignCast(p));
    const pkt = ctx.handle.next() catch return null;
    
    h[0].caplen = pkt.captured_len;
    h[0].len = pkt.original_len;
    h[0].ts.tv_sec = @intCast(pkt.timestamp_ns / 1_000_000_000);
    h[0].ts.tv_usec = @intCast((pkt.timestamp_ns % 1_000_000_000) / 1000);
    
    return @constCast(pkt.data.ptr);
}

export fn zpcap_close(p: *zpcap_t) void {
    const ctx: *PcapContext = @ptrCast(@alignCast(p));
    ctx.handle.deinit();
    ctx.allocator.destroy(ctx.handle);
    ctx.allocator.destroy(ctx);
}

fn setText(errbuf: [*]u8, text: []const u8) void {
    const len = @min(text.len, ZPCAP_ERRBUF_SIZE - 1);
    @memcpy(errbuf[0..len], text[0..len]);
    errbuf[len] = 0;
}

export fn zpcap_geterr(p: *zpcap_t) [*:0]const u8 {
    _ = p;
    return "libzcap internally handled";
}

export fn zpcap_datalink(p: *zpcap_t) c_int {
    _ = p;
    return 1; // DLT_EN10MB (Ethernet)
}

const zpcap_handler = *const fn(user: ?[*]u8, h: *const zpcap_pkthdr, bytes: [*]const u8) callconv(.c) void;

export fn zpcap_loop(p: *zpcap_t, cnt: c_int, callback: zpcap_handler, user: ?[*]u8) c_int {
    const ctx: *PcapContext = @ptrCast(@alignCast(p));
    var pkts: c_int = 0;
    var hdr: zpcap_pkthdr = undefined;
    
    while (cnt < 0 or pkts < cnt) {
        if (ctx.handle.next()) |pkt| {
            hdr.caplen = pkt.captured_len;
            hdr.len = pkt.original_len;
            hdr.ts.tv_sec = @intCast(pkt.timestamp_ns / 1_000_000_000);
            hdr.ts.tv_usec = @intCast((pkt.timestamp_ns % 1_000_000_000) / 1000);
            
            callback(user, &hdr, pkt.data.ptr);
            pkts += 1;
        } else |err| {
            if (err == error.Timeout or err == error.WouldBlock) continue;
            std.debug.print("[zpcap_loop] Exited on unhandled fatal error: {}\n", .{err});
            break;
        }
    }
    return 0;
}

const PcapWriter = @import("../pcap_file/writer.zig").Writer;

pub const zpcap_dumper_t = opaque {};

const DumperContext = struct {
    writer: *PcapWriter,
    allocator: std.mem.Allocator,
};

export fn zpcap_dump_open(p: *zpcap_t, fname: [*:0]const u8) ?*zpcap_dumper_t {
    _ = p; // pcap_t is bypassed in this drop-in to force .ethernet
    var alloc = std.heap.page_allocator;
    const path = std.mem.span(fname);
    
    const writer_val = PcapWriter.create(path, 65535, .ethernet) catch {
        return null;
    };
    
    const w = alloc.create(PcapWriter) catch return null;
    w.* = writer_val;
    
    const ctx = alloc.create(DumperContext) catch {
        alloc.destroy(w);
        return null;
    };
    
    ctx.* = .{
        .writer = w,
        .allocator = alloc,
    };
    return @ptrCast(ctx);
}

export fn zpcap_dump(user: ?[*]u8, h: *const zpcap_pkthdr, sp: [*]const u8) void {
    const ctx: *DumperContext = @ptrCast(@alignCast(user orelse return));
    const timestamp_ns: u64 = @as(u64, @intCast(h.ts.tv_sec)) * 1_000_000_000 + @as(u64, @intCast(h.ts.tv_usec)) * 1000;
    
    const data = sp[0..h.caplen];
    ctx.writer.write(timestamp_ns, data) catch {};
}

export fn zpcap_dump_close(p: *zpcap_dumper_t) void {
    const ctx: *DumperContext = @ptrCast(@alignCast(p));
    ctx.writer.flush() catch {};
    ctx.writer.file.close();
    ctx.allocator.destroy(ctx.writer);
    ctx.allocator.destroy(ctx);
}
