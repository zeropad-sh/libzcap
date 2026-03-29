const std = @import("std");
const builtin = @import("builtin");

const cBPF = @import("../filter/cbpf.zig");
const filter_compiler = @import("../filter/compiler.zig");
const PcapReader = @import("../pcap_file/reader.zig").Reader;
const PcapWriter = @import("../pcap_file/writer.zig").Writer;

const libzcap = struct {
    pub const Handle = @import("../capture/handle.zig").Handle;
    pub const CaptureOptions = @import("../capture/handle.zig").CaptureOptions;
    pub const PacketView = @import("../capture/handle.zig").PacketView;
    pub const kernel = @import("../capture/kernel.zig");
};

const ZpcapError = error{
    UnsupportedPlatform,
};

pub const zpcap_t = opaque {};

pub const zpcap_pkthdr = extern struct {
    ts: timeval_z,
    caplen: u32,
    len: u32,
};

pub const zpcap_open_options = extern struct {
    version: u32,
    buffer_mode: u32,
    ring_block_size: u32,
    ring_block_count: u32,
    ring_frame_size: u32,
    ring_frame_count: u32,
    fanout_mode: u32,
    fanout_group: u16,
    busy_poll_usec: u32,
    fallback_to_copy: i32,
};

const timeval_z = extern struct {
    tv_sec: i32,
    tv_usec: i32,
};

pub const zpcap_if_t = extern struct {
    next: ?*zpcap_if_t,
    name: [*:0]u8,
    description: ?[*:0]u8,
    addresses: ?*anyopaque,
    flags: u32,
};

pub const zpcap_stat_t = extern struct {
    ps_recv: u32,
    ps_drop: u32,
    ps_ifdrop: u32,
};

const ZPCAP_ERRBUF_SIZE: usize = 256;

const PcapSource = union(enum) {
    live: *libzcap.Handle,
    offline: *PcapReader,
};

const PacketFrame = struct {
    data: []const u8,
    timestamp_ns: u64,
    captured_len: u32,
    original_len: u32,
};

const NextPacket = union(enum) {
    packet: PacketFrame,
    none: void,
    eof: void,
};

const PcapContext = struct {
    source: PcapSource,
    allocator: std.mem.Allocator,
    non_blocking: bool = false,
    break_loop: bool = false,
    next_pkt: zpcap_pkthdr = undefined,
    stats: zpcap_stat_t = .{
        .ps_recv = 0,
        .ps_drop = 0,
        .ps_ifdrop = 0,
    },
};

const InterfaceNode = struct {
    if_entry: zpcap_if_t,
    name: [:0]u8,
    description: ?[:0]u8 = null,
};

const PcapIf = extern struct {
    next: ?*PcapIf,
    name: [*:0]const u8,
    description: ?[*:0]const u8,
    addresses: ?*anyopaque,
    flags: u32,
};

const PcapFindAll = *const fn ([*]?*PcapIf, [*]u8) callconv(.c) c_int;
const PcapFreeAll = *const fn (?*PcapIf) callconv(.c) void;
const PcapLookupDev = *const fn ([*]u8) callconv(.c) ?[*:0]u8;

const PcapLib = struct {
    lib: std.DynLib,
    findall: PcapFindAll,
    free_all: PcapFreeAll,
    lookupdev: ?PcapLookupDev,

    fn close(self: *PcapLib) void {
        self.lib.close();
    }
};

var lookupdev_cache: ?[:0]u8 = null;

pub const zpcap_bpf_program = extern struct {
    bf_len: u32,
    bf_insns: [*]cBPF.Instruction,
};

const zpcap_handler = *const fn (user: ?[*]u8, h: *const zpcap_pkthdr, bytes: [*]const u8) callconv(.c) void;

const DumperContext = struct {
    writer: *PcapWriter,
    allocator: std.mem.Allocator,
};

pub const zpcap_dumper_t = opaque {};

pub fn deinit() void {
    if (lookupdev_cache) |buf| {
        std.heap.page_allocator.free(buf);
        lookupdev_cache = null;
    }
}

fn cloneCString(allocator: std.mem.Allocator, value: []const u8) ![:0]u8 {
    return allocator.dupeZ(u8, value);
}

fn setText(errbuf: ?[*]u8, text: []const u8) void {
    if (errbuf == null) return;
    const buf = errbuf.?;
    const len = @min(text.len, ZPCAP_ERRBUF_SIZE - 1);
    @memcpy(buf[0..len], text[0..len]);
    buf[len] = 0;
}

fn toHeader(out: *zpcap_pkthdr, frame: PacketFrame) void {
    out.caplen = frame.captured_len;
    out.len = frame.original_len;
    out.ts.tv_sec = @intCast(frame.timestamp_ns / 1_000_000_000);
    out.ts.tv_usec = @intCast((frame.timestamp_ns % 1_000_000_000) / 1000);
}

fn nextPacket(ctx: *PcapContext) !NextPacket {
    switch (ctx.source) {
        .live => |live_h| {
            const pkt = live_h.next() catch |err| {
                return switch (err) {
                    error.Timeout, error.WouldBlock => NextPacket.none,
                    else => return err,
                };
            };
            return NextPacket{
                .packet = .{
                    .data = pkt.data,
                    .timestamp_ns = pkt.timestamp_ns,
                    .captured_len = pkt.captured_len,
                    .original_len = pkt.original_len,
                },
            };
        },
        .offline => |reader_h| {
            if (try reader_h.next()) |pkt| {
                return NextPacket{
                    .packet = .{
                        .data = pkt.data,
                        .timestamp_ns = @as(u64, pkt.header.ts_sec) * 1_000_000_000 + @as(u64, pkt.header.ts_usec) * 1000,
                        .captured_len = pkt.header.incl_len,
                        .original_len = pkt.header.orig_len,
                    },
                };
            }
            return NextPacket.eof;
        },
    }
}

fn nextPacketBlocking(ctx: *PcapContext) !NextPacket {
    while (true) {
        const result = nextPacket(ctx) catch |err| return err;
        switch (result) {
            .none => {
                if (ctx.non_blocking) return .none;
            },
            .packet, .eof => return result,
        }
    }
}

fn captureLoopCore(
    ctx: *PcapContext,
    cnt: c_int,
    callback: zpcap_handler,
    user: ?[*]u8,
) c_int {
    var pkts: c_int = 0;
    var hdr: zpcap_pkthdr = undefined;

    while (cnt < 0 or pkts < cnt) {
        if (ctx.break_loop) {
            ctx.break_loop = false;
            break;
        }

        const result = nextPacket(ctx) catch return -1;
        switch (result) {
            .packet => |frame| {
                toHeader(&hdr, frame);
                callback(user, &hdr, frame.data.ptr);
                ctx.stats.ps_recv +%= 1;
                pkts += 1;
            },
            .none => {
                if (ctx.non_blocking) {
                    break;
                }
            },
            .eof => break,
        }
    }

    return pkts;
}

fn zpcapFeatureMask() u32 {
    return libzcap.kernel.KernelVersion.detect().detectFeatures();
}

fn resolveOpenOptions(
    snaplen: c_int,
    promisc: c_int,
    to_ms: c_int,
    options: ?*const zpcap_open_options,
) libzcap.CaptureOptions {
    var cfg = libzcap.CaptureOptions{
        .device = "",
        .snaplen = @intCast(snaplen),
        .promisc = promisc != 0,
        .timeout_ms = @intCast(to_ms),
        .buffer_mode = .ring_mmap,
        .ring = .{},
        .fanout = .{},
        .busy_poll_usec = 0,
        .fallback_to_copy = true,
    };

    if (options == null) {
        return cfg;
    }

    const req = options.?;
    if (req.version == 0) {
        return cfg;
    }

    switch (req.buffer_mode) {
        0 => cfg.buffer_mode = .copy,
        1 => cfg.buffer_mode = .ring_mmap,
        else => {},
    }

    if (req.ring_block_size != 0) cfg.ring.block_size = req.ring_block_size;
    if (req.ring_block_count != 0) cfg.ring.block_count = req.ring_block_count;
    if (req.ring_frame_size != 0) cfg.ring.frame_size = req.ring_frame_size;
    if (req.ring_frame_count != 0) cfg.ring.frame_count = req.ring_frame_count;

    cfg.fanout = switch (req.fanout_mode) {
        0 => .{ .mode = .hash, .group_id = req.fanout_group },
        1 => .{ .mode = .lb, .group_id = req.fanout_group },
        2 => .{ .mode = .cpu, .group_id = req.fanout_group },
        3 => .{ .mode = .random, .group_id = req.fanout_group },
        4 => .{ .mode = .rollover, .group_id = req.fanout_group },
        5 => .{ .mode = .cbpf, .group_id = req.fanout_group },
        6 => .{ .mode = .ebpf, .group_id = req.fanout_group },
        else => .{},
    };

    cfg.busy_poll_usec = req.busy_poll_usec;
    if (req.fallback_to_copy != 0) {
        cfg.fallback_to_copy = true;
    } else {
        cfg.fallback_to_copy = false;
    }
    return cfg;
}

fn openLiveWithOptions(
    device: [*:0]const u8,
    snaplen: c_int,
    promisc: c_int,
    to_ms: c_int,
    options: ?*const zpcap_open_options,
    errbuf: ?[*]u8,
) ?*zpcap_t {
    const alloc = std.heap.page_allocator;
    const dev_str = std.mem.span(device);
    const cfg = resolveOpenOptions(snaplen, promisc, to_ms, options);

    const h = alloc.create(libzcap.Handle) catch {
        setText(errbuf, "Out of memory allocating handle");
        return null;
    };
    errdefer alloc.destroy(h);

    h.* = libzcap.Handle.open(.{
        .device = dev_str,
        .snaplen = cfg.snaplen,
        .promisc = cfg.promisc,
        .timeout_ms = cfg.timeout_ms,
        .filter = cfg.filter,
        .ring = cfg.ring,
        .buffer_mode = cfg.buffer_mode,
        .fanout = cfg.fanout,
        .busy_poll_usec = cfg.busy_poll_usec,
        .fallback_to_copy = cfg.fallback_to_copy,
    }) catch |err| {
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

export fn zpcap_open_live(
    device: [*:0]const u8,
    snaplen: c_int,
    promisc: c_int,
    to_ms: c_int,
    errbuf: ?[*]u8,
) ?*zpcap_t {
    return openLiveWithOptions(device, snaplen, promisc, to_ms, null, errbuf);
}

export fn zpcap_open_live_ex(
    device: [*:0]const u8,
    snaplen: c_int,
    promisc: c_int,
    to_ms: c_int,
    options: ?*const zpcap_open_options,
    errbuf: ?[*]u8,
) ?*zpcap_t {
    return openLiveWithOptions(device, snaplen, promisc, to_ms, options, errbuf);
}

export fn zpcap_open_offline(fname: [*:0]const u8, errbuf: ?[*]u8) ?*zpcap_t {
    const alloc = std.heap.page_allocator;
    const path = std.mem.span(fname);

    const r = alloc.create(PcapReader) catch {
        setText(errbuf, "Out of memory allocating reader");
        return null;
    };
    errdefer alloc.destroy(r);

    r.* = PcapReader.open(path) catch |err| {
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
    if (ctx.break_loop) {
        ctx.break_loop = false;
    }

    const result = nextPacketBlocking(ctx) catch return null;
    switch (result) {
        .packet => |frame| {
            toHeader(&h[0], frame);
            ctx.stats.ps_recv +%= 1;
            return @constCast(frame.data.ptr);
        },
        .none, .eof => return null,
    }
}

export fn zpcap_next_ex(p: *zpcap_t, h: [*]*zpcap_pkthdr, data: [*][*]const u8) c_int {
    const ctx: *PcapContext = @ptrCast(@alignCast(p));

    if (ctx.break_loop) {
        ctx.break_loop = false;
    }

    const result = nextPacketBlocking(ctx) catch return -1;
    const is_offline = switch (ctx.source) {
        .live => false,
        .offline => true,
    };

    switch (result) {
        .packet => |frame| {
            toHeader(&ctx.next_pkt, frame);
            h[0] = &ctx.next_pkt;
            data[0] = frame.data.ptr;
            ctx.stats.ps_recv +%= 1;
            return 1;
        },
        .none => return 0,
        .eof => return if (is_offline) -2 else 0,
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
        },
    }
    ctx.allocator.destroy(ctx);
}

export fn zpcap_geterr(p: *zpcap_t) [*:0]const u8 {
    _ = p;
    return "libzcap internally handled";
}

export fn zpcap_datalink(p: *zpcap_t) c_int {
    _ = p;
    return 1;
}

export fn zpcap_loop(p: *zpcap_t, cnt: c_int, callback: zpcap_handler, user: ?[*]u8) c_int {
    const ctx: *PcapContext = @ptrCast(@alignCast(p));
    return captureLoopCore(ctx, cnt, callback, user);
}

export fn zpcap_dispatch(p: *zpcap_t, cnt: c_int, callback: zpcap_handler, user: ?[*]u8) c_int {
    const ctx: *PcapContext = @ptrCast(@alignCast(p));
    return captureLoopCore(ctx, cnt, callback, user);
}

export fn zpcap_breakloop(p: *zpcap_t) void {
    const ctx: *PcapContext = @ptrCast(@alignCast(p));
    ctx.break_loop = true;
}

export fn zpcap_compile(p: *zpcap_t, fp: *zpcap_bpf_program, str: [*:0]const u8, optimize: c_int, netmask: u32) c_int {
    _ = p;
    _ = optimize;
    _ = netmask;

    const filter_str = std.mem.span(str);
    const bytecode = filter_compiler.compileRuntime(std.heap.page_allocator, filter_str) catch {
        return -1;
    };

    fp.bf_len = @intCast(bytecode.len);
    fp.bf_insns = bytecode.ptr;
    return 0;
}

export fn zpcap_setfilter(p: *zpcap_t, fp: *zpcap_bpf_program) c_int {
    const ctx: *PcapContext = @ptrCast(@alignCast(p));
    switch (ctx.source) {
        .live => |live_h| {
            const insns = fp.bf_insns[0..fp.bf_len];
            live_h.setFilter(insns) catch return -1;
            return 0;
        },
        .offline => return -1,
    }
}

export fn zpcap_freecode(fp: *zpcap_bpf_program) void {
    if (fp.bf_len > 0) {
        const slice = fp.bf_insns[0..fp.bf_len];
        std.heap.page_allocator.free(slice);
        fp.bf_len = 0;
    }
}

export fn zpcap_detect_features() u32 {
    return zpcapFeatureMask();
}

export fn zpcap_kernel_version(major: ?*c_int, minor: ?*c_int, patch: ?*c_int) c_int {
    const version = libzcap.kernel.KernelVersion.detect();
    if (major != null) {
        major.?.* = @intCast(version.major);
    }
    if (minor != null) {
        minor.?.* = @intCast(version.minor);
    }
    if (patch != null) {
        patch.?.* = @intCast(version.patch);
    }
    return 0;
}

fn getIfEntriesLinux(allocator: std.mem.Allocator) !?*zpcap_if_t {
    var dir = try std.fs.cwd().openDir("/sys/class/net", .{ .iterate = true });
    defer dir.close();

    var head: ?*zpcap_if_t = null;
    var tail: ?*zpcap_if_t = null;
    errdefer if (head) |h| freeIfList(h, allocator);

    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.name.len == 0 or entry.name[0] == '.') continue;

        const if_name = try cloneCString(allocator, entry.name);
        const node = try allocator.create(InterfaceNode);
        node.name = if_name;
        node.description = null;
        node.if_entry = .{
            .next = null,
            .name = @ptrCast(node.name.ptr),
            .description = null,
            .addresses = null,
            .flags = 0,
        };

        if (tail) |t| {
            t.next = &node.if_entry;
        } else {
            head = &node.if_entry;
        }
        tail = &node.if_entry;
    }

    return head;
}

fn openPcapLibrary() !PcapLib {
    const candidates = switch (builtin.os.tag) {
        .windows => [_][]const u8{"wpcap.dll"},
        .macos => [_][]const u8{ "libpcap.dylib", "libpcap.so.1", "libpcap.so" },
        .freebsd, .openbsd, .netbsd, .dragonfly => [_][]const u8{ "libpcap.so.1", "libpcap.so" },
        else => [_][]const u8{ "libpcap.so.1", "libpcap.so" },
    };

    for (candidates) |candidate| {
        var lib = std.DynLib.open(candidate) catch continue;
        const findall = lib.lookup(PcapFindAll, "pcap_findalldevs") orelse {
            lib.close();
            continue;
        };
        const free_all = lib.lookup(PcapFreeAll, "pcap_freealldevs") orelse {
            lib.close();
            continue;
        };
        const lookupdev = lib.lookup(PcapLookupDev, "pcap_lookupdev");
        return .{
            .lib = lib,
            .findall = findall,
            .free_all = free_all,
            .lookupdev = lookupdev,
        };
    }
    return error.UnsupportedPlatform;
}

fn buildIfEntriesFromPcap(
    allocator: std.mem.Allocator,
    source: ?*PcapIf,
) !?*zpcap_if_t {
    var head: ?*zpcap_if_t = null;
    var tail: ?*zpcap_if_t = null;
    var current = source;
    errdefer if (head) |h| freeIfList(h, allocator);

    while (current) |entry| {
        const entry_name = std.mem.sliceTo(entry.name, 0);
        const if_name = cloneCString(allocator, entry_name) catch return error.OutOfMemory;
        var if_description: ?[:0]u8 = null;
        if (entry.description) |desc| {
            if_description = cloneCString(allocator, std.mem.sliceTo(desc, 0)) catch null;
        }

        const node = allocator.create(InterfaceNode) catch {
            allocator.free(if_name);
            if (if_description) |desc| allocator.free(desc);
            return error.OutOfMemory;
        };
        node.name = if_name;
        node.description = if_description;
        node.if_entry = .{
            .next = null,
            .name = @ptrCast(node.name.ptr),
            .description = if (node.description) |desc| @ptrCast(desc.ptr) else null,
            .addresses = null,
            .flags = entry.flags,
        };

        if (tail) |t| {
            t.next = &node.if_entry;
        } else {
            head = &node.if_entry;
        }
        tail = &node.if_entry;
        current = entry.next;
    }

    const result = head;
    head = null;
    return result;
}

fn getIfEntriesFromLibPcap(allocator: std.mem.Allocator) !?*zpcap_if_t {
    var api = openPcapLibrary() catch return error.UnsupportedPlatform;
    defer api.close();

    var raw: ?*PcapIf = null;
    var errbuf: [ZPCAP_ERRBUF_SIZE]u8 = undefined;
    const rc = api.findall(@ptrCast(&raw), &errbuf);
    if (rc != 0 or raw == null) {
        return error.UnsupportedPlatform;
    }

    errdefer api.free_all(raw);

    const copied = buildIfEntriesFromPcap(allocator, raw) catch |err| {
        api.free_all(raw);
        return err;
    };

    api.free_all(raw);
    return copied;
}

fn getLookupFromPcapLibrary(allocator: std.mem.Allocator, errbuf: ?[*]u8) ![:0]u8 {
    var api = openPcapLibrary() catch return error.UnsupportedPlatform;
    defer api.close();

    var pcap_err: [ZPCAP_ERRBUF_SIZE]u8 = undefined;
    if (api.lookupdev) |lookupdev_fn| {
        if (lookupdev_fn(&pcap_err)) |name| {
            const name_slice = std.mem.sliceTo(name, 0);
            if (name_slice.len > 0) {
                return cloneCString(allocator, name_slice);
            }
        }
        setText(errbuf, std.mem.sliceTo(pcap_err[0..], 0));
    }

    var raw: ?*PcapIf = null;
    if (api.findall(@ptrCast(&raw), &pcap_err) != 0 or raw == null) {
        return error.UnsupportedPlatform;
    }
    defer api.free_all(raw);

    var current = raw;
    while (current) |entry| {
        const entry_name = std.mem.sliceTo(entry.name, 0);
        if (entry_name.len > 0) {
            return cloneCString(allocator, entry_name);
        }
        current = entry.next;
    }

    return error.UnsupportedPlatform;
}

fn getIfEntries(allocator: std.mem.Allocator) !?*zpcap_if_t {
    return switch (builtin.os.tag) {
        .linux => getIfEntriesLinux(allocator) catch getIfEntriesFromLibPcap(allocator),
        .macos, .freebsd, .openbsd, .netbsd, .dragonfly => getIfEntriesFromLibPcap(allocator),
        .windows => getIfEntriesFromLibPcap(allocator),
        else => error.UnsupportedPlatform,
    };
}

fn freeIfList(first: *zpcap_if_t, alloc: std.mem.Allocator) void {
    var current: ?*zpcap_if_t = first;
    while (current) |entry| {
        const next = entry.next;
        const node: *InterfaceNode = @alignCast(@fieldParentPtr("if_entry", entry));
        alloc.free(node.name);
        if (node.description) |desc| alloc.free(desc);
        alloc.destroy(node);
        current = next;
    }
}

export fn zpcap_findalldevs(alldevs: ?[*]?*zpcap_if_t, errbuf: ?[*]u8) c_int {
    const alloc = std.heap.page_allocator;
    if (alldevs == null) {
        setText(errbuf, "alldevs is null");
        return -1;
    }
    const out = alldevs.?;

    setText(errbuf, "");
    const head = getIfEntries(alloc) catch |err| {
        setText(errbuf, @errorName(err));
        out[0] = null;
        return -1;
    };

    out[0] = head orelse null;
    if (head == null) {
        setText(errbuf, "No capture devices found");
    }
    return 0;
}

export fn zpcap_freealldevs(devs: ?*zpcap_if_t) void {
    if (devs) |head| freeIfList(head, std.heap.page_allocator);
}

export fn zpcap_lookupdev(errbuf: ?[*]u8) ?[*:0]u8 {
    const alloc = std.heap.page_allocator;
    if (lookupdev_cache) |cached| {
        return cached.ptr;
    }

    if (builtin.os.tag != .linux) {
        const from_library = getLookupFromPcapLibrary(alloc, errbuf) catch null;
        if (from_library) |copied| {
            lookupdev_cache = copied;
            return copied.ptr;
        }
    }

    const all = getIfEntries(alloc) catch |err| {
        setText(errbuf, @errorName(err));
        return null;
    };
    if (all == null) {
        setText(errbuf, "No capture device found");
        return null;
    }

    const name = std.mem.span(all.?.name);
    const copied = cloneCString(alloc, name) catch {
        setText(errbuf, "Out of memory duplicating device name");
        freeIfList(all.?, alloc);
        return null;
    };
    freeIfList(all.?, alloc);
    lookupdev_cache = copied;
    return copied.ptr;
}

export fn zpcap_sendpacket(p: *zpcap_t, buf: [*]const u8, len: c_int) c_int {
    if (len <= 0) return -1;
    const data_len: usize = @intCast(len);
    const data = buf[0..data_len];

    const ctx: *PcapContext = @ptrCast(@alignCast(p));
    return switch (ctx.source) {
        .live => |live_h| {
            live_h.send(data) catch return -1;
            return 0;
        },
        .offline => -1,
    };
}

export fn zpcap_send(p: *zpcap_t, buf: [*]const u8, len: c_int) c_int {
    return zpcap_sendpacket(p, buf, len);
}

export fn zpcap_getnonblock(p: *zpcap_t, errbuf: ?[*]u8) c_int {
    _ = errbuf;
    const ctx: *PcapContext = @ptrCast(@alignCast(p));
    return if (ctx.non_blocking) 1 else 0;
}

export fn zpcap_get_selectable_fd(p: *zpcap_t) c_int {
    const ctx: *PcapContext = @ptrCast(@alignCast(p));
    return switch (ctx.source) {
        .live => |live_h| live_h.getSelectableFd(),
        .offline => -1,
    };
}

export fn zpcap_getevent(p: *zpcap_t) ?*anyopaque {
    const ctx: *PcapContext = @ptrCast(@alignCast(p));
    return switch (ctx.source) {
        .live => |live_h| if (builtin.os.tag == .windows) live_h.getEventHandle() else null,
        .offline => null,
    };
}

export fn zpcap_setnonblock(p: *zpcap_t, nonblock: c_int, errbuf: ?[*]u8) c_int {
    const ctx: *PcapContext = @ptrCast(@alignCast(p));
    if (nonblock != 0 and nonblock != 1) {
        setText(errbuf, "Unsupported nonblocking mode value");
        return -1;
    }

    const enabled = nonblock == 1;
    switch (ctx.source) {
        .live => |live_h| {
            live_h.setNonBlocking(enabled) catch |err| {
                setText(errbuf, @errorName(err));
                return -1;
            };
            ctx.non_blocking = enabled;
        },
        .offline => ctx.non_blocking = enabled,
    }
    return 0;
}

export fn zpcap_stats(p: *zpcap_t, stats_out: *zpcap_stat_t) c_int {
    const ctx: *PcapContext = @ptrCast(@alignCast(p));
    stats_out.* = ctx.stats;
    return 0;
}

export fn zpcap_dump_open(p: *zpcap_t, fname: [*:0]const u8) ?*zpcap_dumper_t {
    _ = p;
    const alloc = std.heap.page_allocator;
    const path = std.mem.span(fname);

    const writer_val = PcapWriter.create(path, 65535, .ethernet) catch return null;
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

pub fn deinitCompat() void {
    deinit();
}
