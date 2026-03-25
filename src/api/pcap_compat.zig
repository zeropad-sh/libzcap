const std = @import("std");
const cBPF = @import("../filter/cbpf.zig");
const filter_compiler = @import("../filter/compiler.zig");
const PcapReader = @import("../pcap_file/reader.zig").Reader;
const PcapWriter = @import("../pcap_file/writer.zig").Writer;

const libzcap = struct {
    pub const Handle = @import("../capture/handle.zig").Handle;
    pub const CaptureOptions = @import("../capture/handle.zig").CaptureOptions;
    pub const PacketView = @import("../capture/handle.zig").PacketView;
};

// libpcap C-ABI matching structs
pub const zpcap_t = opaque {};

const PcapSource = union(enum) {
    live: *libzcap.Handle,
    offline: *PcapReader,
};

const PcapContext = struct {
    source: PcapSource,
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
        .source = .{ .live = h },
        .allocator = alloc,
    };
    return @ptrCast(ctx);
}

export fn zpcap_open_offline(fname: [*:0]const u8, errbuf: [*]u8) ?*zpcap_t {
    var alloc = std.heap.page_allocator;
    const path = std.mem.span(fname);

    const r = alloc.create(PcapReader) catch {
        setText(errbuf, "Out of memory allocating reader");
        return null;
    };
    
    r.* = PcapReader.open(path) catch |err| {
        alloc.destroy(r);
        setText(errbuf, @errorName(err));
        return null;
    };

    const ctx = alloc.create(PcapContext) catch {
        r.file.close();
        alloc.destroy(r);
        setText(errbuf, "Out of memory allocating pcap wrapper");
        return null;
    };
    
    ctx.* = .{
        .source = .{ .offline = r },
        .allocator = alloc,
    };
    return @ptrCast(ctx);
}

export fn zpcap_next(p: *zpcap_t, h: [*]zpcap_pkthdr) ?[*]u8 {
    const ctx: *PcapContext = @ptrCast(@alignCast(p));
    
    switch (ctx.source) {
        .live => |live_h| {
            const pkt = live_h.next() catch return null;
            h[0].caplen = pkt.captured_len;
            h[0].len = pkt.original_len;
            h[0].ts.tv_sec = @intCast(pkt.timestamp_ns / 1_000_000_000);
            h[0].ts.tv_usec = @intCast((pkt.timestamp_ns % 1_000_000_000) / 1000);
            return @constCast(pkt.data.ptr);
        },
        .offline => |reader_h| {
            if (reader_h.next() catch return null) |pkt| {
                h[0].caplen = pkt.header.incl_len;
                h[0].len = pkt.header.orig_len;
                h[0].ts.tv_sec = @intCast(pkt.header.ts_sec);
                h[0].ts.tv_usec = @intCast(pkt.header.ts_usec);
                return pkt.data.ptr;
            }
            return null;
        }
    }
}

export fn zpcap_close(p: *zpcap_t) void {
    const ctx: *PcapContext = @ptrCast(@alignCast(p));
    switch (ctx.source) {
        .live => |live_h| {
            live_h.deinit();
            ctx.allocator.destroy(live_h);
        },
        .offline => |reader_h| {
            reader_h.file.close();
            ctx.allocator.destroy(reader_h);
        }
    }
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
        switch (ctx.source) {
            .live => |live_h| {
                if (live_h.next()) |pkt| {
                    hdr.caplen = pkt.captured_len;
                    hdr.len = pkt.original_len;
                    hdr.ts.tv_sec = @intCast(pkt.timestamp_ns / 1_000_000_000);
                    hdr.ts.tv_usec = @intCast((pkt.timestamp_ns % 1_000_000_000) / 1000);
                    
                    callback(user, &hdr, pkt.data.ptr);
                    pkts += 1;
                } else |err| {
                    if (err == error.Timeout or err == error.WouldBlock) continue;
                    std.debug.print("[zpcap_loop] Exited on fatal error: {}\n", .{err});
                    break;
                }
            },
            .offline => |reader_h| {
                if (reader_h.next() catch break) |pkt| {
                    hdr.caplen = pkt.header.incl_len;
                    hdr.len = pkt.header.orig_len;
                    hdr.ts.tv_sec = @intCast(pkt.header.ts_sec);
                    hdr.ts.tv_usec = @intCast(pkt.header.ts_usec);
                    
                    callback(user, &hdr, pkt.data.ptr);
                    pkts += 1;
                } else {
                    break; // EOF
                }
            }
        }
    }
    return 0;
}

pub const zpcap_bpf_program = extern struct {
    bf_len: u32,
    bf_insns: [*]cBPF.Instruction,
};

export fn zpcap_compile(p: *zpcap_t, fp: *zpcap_bpf_program, str: [*:0]const u8, optimize: c_int, netmask: u32) c_int {
    _ = p; _ = optimize; _ = netmask;
    const filter_str = std.mem.span(str);
    
    const bytecode = filter_compiler.compileRuntime(std.heap.page_allocator, filter_str) catch {
        return -1; // Compilation error
    };
    
    fp.bf_len = @intCast(bytecode.len);
    fp.bf_insns = bytecode.ptr;
    return 0;
}

export fn zpcap_setfilter(p: *zpcap_t, fp: *zpcap_bpf_program) c_int {
    const ctx: *PcapContext = @ptrCast(@alignCast(p));
    
    switch(ctx.source) {
        .live => |live_h| {
            const insns = fp.bf_insns[0..fp.bf_len];
            live_h.setFilter(insns) catch return -1;
            return 0;
        },
        .offline => {
            // Software BPF VM not currently implemented for offline tracing in libzcap.
            return -1;
        }
    }
}

export fn zpcap_freecode(fp: *zpcap_bpf_program) void {
    if (fp.bf_len > 0) {
        const slice = fp.bf_insns[0..fp.bf_len];
        std.heap.page_allocator.free(slice);
        fp.bf_len = 0;
    }
}

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
