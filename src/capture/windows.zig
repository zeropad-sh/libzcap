const std = @import("std");
const handle_types = @import("handle.zig");
const CaptureOptions = handle_types.CaptureOptions;
const PacketView = handle_types.PacketView;
const Error = handle_types.Error;
const cBPF = @import("../filter/cbpf.zig");

pub const pcap_t = opaque {};
pub const pcap_pkthdr_wpcap = extern struct {
    tv_sec: i32,
    tv_usec: i32,
    caplen: u32,
    len: u32,
};

pub const Handle = struct {
    lib: std.DynLib,
    pcap_ptr: *pcap_t,
    options: CaptureOptions,

    pcap_open_live_fn: *const fn ([*:0]const u8, c_int, c_int, c_int, [*]u8) callconv(.c) ?*pcap_t,
    pcap_next_ex_fn: *const fn (*pcap_t, [*][*]pcap_pkthdr_wpcap, [*][*]u8) callconv(.c) c_int,
    pcap_close_fn: *const fn (*pcap_t) callconv(.c) void,
    pcap_geterr_fn: *const fn (*pcap_t) callconv(.c) [*:0]const u8,
    pcap_setfilter_fn: *const fn (*pcap_t, *const anyopaque) callconv(.c) c_int,
    pcap_sendpacket_fn: *const fn (*pcap_t, [*]const u8, c_int) callconv(.c) c_int,
    pcap_setnonblock_fn: ?*const fn (*pcap_t, c_int, [*]u8) callconv(.c) c_int,

    pub fn open(options: CaptureOptions) Error!Handle {
        var lib = std.DynLib.open("wpcap.dll") catch return Error.LibraryNotFound;
        errdefer lib.close();

        const pcap_open_live_fn = lib.lookup(*const fn ([*:0]const u8, c_int, c_int, c_int, [*]u8) callconv(.c) ?*pcap_t, "pcap_open_live") orelse return Error.SymbolNotFound;
        const pcap_next_ex_fn = lib.lookup(*const fn (*pcap_t, [*][*]pcap_pkthdr_wpcap, [*][*]u8) callconv(.c) c_int, "pcap_next_ex") orelse return Error.SymbolNotFound;
        const pcap_close_fn = lib.lookup(*const fn (*pcap_t) callconv(.c) void, "pcap_close") orelse return Error.SymbolNotFound;
        const pcap_geterr_fn = lib.lookup(*const fn (*pcap_t) callconv(.c) [*:0]const u8, "pcap_geterr") orelse return Error.SymbolNotFound;
        const pcap_setfilter_fn = lib.lookup(*const fn (*pcap_t, *const anyopaque) callconv(.c) c_int, "pcap_setfilter") orelse return Error.SymbolNotFound;
        const pcap_sendpacket_fn = lib.lookup(*const fn (*pcap_t, [*]const u8, c_int) callconv(.c) c_int, "pcap_sendpacket") orelse return Error.SymbolNotFound;
        const pcap_setnonblock_fn = lib.lookup(*const fn (*pcap_t, c_int, [*]u8) callconv(.c) c_int, "pcap_setnonblock");

        var errbuf: [256]u8 = undefined;
        var dev_path: [256]u8 = undefined;
        if (options.device.len >= dev_path.len) return Error.NoSuchDevice;
        @memcpy(dev_path[0..options.device.len], options.device);
        dev_path[options.device.len] = 0;

        const pcap_ptr = pcap_open_live_fn(
            @ptrCast(dev_path[0 .. options.device.len + 1].ptr),
            @intCast(options.snaplen),
            if (options.promisc) 1 else 0,
            @intCast(options.timeout_ms),
            &errbuf,
        ) orelse return Error.PermissionDenied;

        return Handle{
            .lib = lib,
            .pcap_ptr = pcap_ptr,
            .options = options,
            .pcap_open_live_fn = pcap_open_live_fn,
            .pcap_next_ex_fn = pcap_next_ex_fn,
            .pcap_close_fn = pcap_close_fn,
            .pcap_geterr_fn = pcap_geterr_fn,
            .pcap_setfilter_fn = pcap_setfilter_fn,
            .pcap_sendpacket_fn = pcap_sendpacket_fn,
            .pcap_setnonblock_fn = pcap_setnonblock_fn,
        };
    }

    pub fn setFilter(self: *Handle, prog: []const cBPF.Instruction) Error!void {
        const bpf_program = extern struct {
            bf_len: c_uint,
            bf_insns: [*]const cBPF.Instruction,
        };
        var fprog: bpf_program = .{
            .bf_len = @intCast(prog.len),
            .bf_insns = prog.ptr,
        };
        const rc = self.pcap_setfilter_fn(self.pcap_ptr, &fprog);
        if (rc != 0) return Error.InvalidFilter;
    }

    pub fn send(self: *Handle, data: []const u8) Error!void {
        if (data.len > std.math.maxInt(c_int)) return Error.InvalidArgument;

        const rc = self.pcap_sendpacket_fn(self.pcap_ptr, data.ptr, @intCast(data.len));
        if (rc != 0) {
            return Error.DeviceNotUp;
        }
    }

    pub fn setNonBlocking(self: *Handle, enabled: bool) Error!void {
        const setnonblock = self.pcap_setnonblock_fn orelse return Error.SymbolNotFound;
        var errbuf = [_]u8{0} ** 256;
        const err_ptr: [*]u8 = errbuf[0..].ptr;
        const rc = setnonblock(self.pcap_ptr, if (enabled) 1 else 0, err_ptr);
        if (rc != 0) {
            return Error.PermissionDenied;
        }
    }

    pub fn next(self: *Handle) Error!PacketView {
        var header: *pcap_pkthdr_wpcap = undefined;
        var data: [*]u8 = undefined;

        const res = self.pcap_next_ex_fn(self.pcap_ptr, @ptrCast(&header), @ptrCast(&data));
        if (res == 1) {
            return .{
                .data = data[0..header.caplen],
                .timestamp_ns = @as(u64, @intCast(header.tv_sec)) * 1_000_000_000 + @as(u64, @intCast(header.tv_usec)) * 1000,
                .ifindex = 0,
                .protocol = 0,
                .captured_len = header.caplen,
                .original_len = header.len,
            };
        } else if (res == 0) {
            return Error.Timeout;
        } else {
            return Error.DeviceNotUp;
        }
    }

    pub fn deinit(self: *Handle) void {
        self.pcap_close_fn(self.pcap_ptr);
        self.lib.close();
    }

    pub fn getSelectableFd(self: *Handle) c_int {
        _ = self;
        return -1;
    }
};
