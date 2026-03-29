const std = @import("std");
const os = std.posix;
const ring = @import("../ring.zig");
const handle_types = @import("handle.zig");
const kernel = @import("kernel.zig");
const CaptureOptions = handle_types.CaptureOptions;
const BufferMode = handle_types.BufferMode;
const PacketView = handle_types.PacketView;
const Error = handle_types.Error;
const cBPF = struct {
    const Instruction = @import("../filter/cbpf.zig").Instruction;
    const compileRuntime = @import("../filter/compiler.zig").compileRuntime;
};

pub const Handle = struct {
    fd: os.fd_t,
    options: CaptureOptions,
    ring: ?*ring.Ring = null,
    buffer: []u8,
    filter_program: ?[]const cBPF.Instruction = null,

    pub fn open(options: CaptureOptions) Error!Handle {
        const protocol = std.mem.nativeToBig(u16, 0x0003); // ETH_P_ALL
        const fd = openRawSocket(protocol) catch |err| return err;
        errdefer os.close(fd);
        const kernel_features = kernel.KernelVersion.detect().detectFeatures();

        var h = Handle{
            .fd = fd,
            .options = options,
            .buffer = undefined,
            .ring = null,
        };

        h.options.buffer_mode = try Handle.resolveBufferMode(kernel_features, options.buffer_mode, options.fallback_to_copy);

        if (h.options.buffer_mode == .ring_mmap) {
            if (ring.Ring.init(fd, options.ring)) |r| {
                h.ring = r;
            } else |_| {
                if (!options.fallback_to_copy) return Error.RingSetupFailed;
                h.options.buffer_mode = .copy;
            }
        }

        if (h.options.buffer_mode != .ring_mmap) {
            h.buffer = try std.heap.page_allocator.alloc(u8, options.snaplen);
            const tv = std.os.linux.timeval{
                .sec = @intCast(options.timeout_ms / 1000),
                .usec = @intCast((options.timeout_ms % 1000) * 1000),
            };
            os.setsockopt(fd, os.SOL.SOCKET, os.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};
        }

        try configureModernFeatures(fd, options, kernel_features);

        const ifindex = getIfIndex(options.device) catch null;
        if (ifindex) |idx| {
            var addr: std.os.linux.sockaddr.ll = .{
                .family = os.AF.PACKET,
                .protocol = protocol,
                .ifindex = @intCast(idx),
                .hatype = 0,
                .pkttype = 0,
                .halen = 0,
                .addr = [_]u8{0} ** 8,
            };
            os.bind(fd, @ptrCast(&addr), @as(os.socklen_t, @sizeOf(@TypeOf(addr)))) catch {};
        }

        const bufsize: u32 = options.snaplen * 8;
        os.setsockopt(fd, os.SOL.SOCKET, os.SO.RCVBUF, std.mem.asBytes(&bufsize)) catch {};

        if (options.filter) |f| {
            h.filter_program = try cBPF.compileRuntime(std.heap.page_allocator, f);
            try h.setFilter(h.filter_program.?);
        }

        return h;
    }

    fn configureModernFeatures(
        fd: os.fd_t,
        options: CaptureOptions,
        kernel_features: u32,
    ) Error!void {
        if (options.fanout.mode != .none) {
            if (kernel_features & @intFromEnum(kernel.KernelFeatures.fanout) == 0) {
                return Error.InvalidArgument;
            }

            const fanout_mode = switch (options.fanout.mode) {
                .none => 0,
                .hash => @as(u32, 0),
                .lb => 1,
                .cpu => 2,
                .random => 3,
                .rollover => 4,
                .cbpf => 5,
                .ebpf => 6,
            };
            const fanout_val: u32 = @as(u32, options.fanout.group_id) << 16 | fanout_mode;
            const PACKET_FANOUT = 18;
            os.setsockopt(fd, os.SOL.PACKET, PACKET_FANOUT, std.mem.asBytes(&fanout_val)) catch {
                return Error.InvalidArgument;
            };
        }

        if (options.busy_poll_usec != 0) {
            if (kernel_features & @intFromEnum(kernel.KernelFeatures.busy_poll) == 0) {
                return Error.InvalidArgument;
            }
            const SO_BUSY_POLL = 46;
            os.setsockopt(fd, os.SOL.SOCKET, SO_BUSY_POLL, std.mem.asBytes(&options.busy_poll_usec)) catch {
                return Error.PermissionDenied;
            };
        }
    }

    fn resolveBufferMode(
        kernel_features: u32,
        requested: BufferMode,
        fallback_to_copy: bool,
    ) Error!BufferMode {
        if (requested != .ring_mmap) return .copy;

        if (kernel_features & @intFromEnum(kernel.KernelFeatures.ring_v3) == 0) {
            if (!fallback_to_copy) return Error.RingSetupFailed;
            return .copy;
        }

        return .ring_mmap;
    }

    fn openRawSocket(protocol: u16) Error!os.fd_t {
        const raw_rc = std.posix.system.socket(os.AF.PACKET, os.SOCK.RAW, @intCast(protocol));
        const rc: isize = @bitCast(raw_rc);
        if (rc >= 0) {
            return @intCast(rc);
        }

        const err = std.posix.errno(rc);
        return switch (err) {
            .SUCCESS => unreachable,
            .PERM, .ACCES => Error.PermissionDenied,
            .AFNOSUPPORT => Error.ProtocolNotSupported,
            .PROTOTYPE => Error.ProtocolNotSupported,
            .PROTONOSUPPORT => Error.ProtocolNotSupported,
            .NOBUFS, .NOMEM => Error.SocketCreationFailed,
            .NFILE, .MFILE => Error.SocketCreationFailed,
            .INVAL => Error.SocketCreationFailed,
            .ADDRINUSE, .ADDRNOTAVAIL => Error.InvalidArgument,
            else => Error.SocketCreationFailed,
        };
    }

    fn getIfIndex(name: []const u8) Error!u32 {
        var path_buf: [64]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "/sys/class/net/{s}/ifindex", .{name}) catch return Error.NoSuchDevice;

        const file = std.fs.cwd().openFile(path, .{}) catch return Error.NoSuchDevice;
        defer file.close();

        var idx_buf: [16]u8 = undefined;
        const len = try file.readAll(&idx_buf);
        return std.fmt.parseInt(u32, std.mem.trim(u8, idx_buf[0..len], " \n\r\t"), 10) catch return Error.NoSuchDevice;
    }

    pub fn setFilter(self: *Handle, prog: []const cBPF.Instruction) Error!void {
        const sock_fprog = extern struct {
            len: u16,
            filter: [*]const cBPF.Instruction,
        };
        var fprog: sock_fprog = .{
            .len = @intCast(prog.len),
            .filter = prog.ptr,
        };
        const SO_ATTACH_FILTER = 26;
        std.posix.setsockopt(self.fd, std.posix.SOL.SOCKET, SO_ATTACH_FILTER, std.mem.asBytes(&fprog)) catch return Error.InvalidFilter;
    }

    pub fn send(self: *Handle, data: []const u8) Error!void {
        var sent: usize = 0;
        while (sent < data.len) {
            const n = try os.write(self.fd, data[sent..]);
            if (n == 0) {
                return Error.SocketNotConnected;
            }
            sent += n;
        }
    }

    pub fn setNonBlocking(self: *Handle, enabled: bool) Error!void {
        const current = os.fcntl(self.fd, os.F.GETFL, 0) catch return Error.PermissionDenied;
        const nonblock: usize = comptime 1 << @intCast(@bitOffsetOf(os.O, "NONBLOCK"));
        const next_flags = if (enabled) current | nonblock else current & ~nonblock;
        if (next_flags != current) {
            _ = os.fcntl(self.fd, os.F.SETFL, next_flags) catch return Error.PermissionDenied;
        }
    }

    pub fn next(self: *Handle) Error!PacketView {
        if (self.ring) |r| {
            if (r.next()) |pkt| {
                return .{
                    .data = pkt.data,
                    .timestamp_ns = pkt.timestamp_ns,
                    .ifindex = 0,
                    .protocol = 0,
                    .captured_len = pkt.captured_len,
                    .original_len = pkt.original_len,
                };
            }
            std.posix.nanosleep(0, 10_000_000);
            return Error.Timeout;
        }
        return self.readFromSocket();
    }

    fn readFromSocket(self: *Handle) Error!PacketView {
        const n = os.read(self.fd, self.buffer) catch |err| {
            if (err == error.WouldBlock or err == error.ResourceUnavailable) {
                return Error.Timeout;
            }
            return err;
        };
        return .{
            .data = self.buffer[0..n],
            .timestamp_ns = @intCast(std.time.nanoTimestamp()),
            .ifindex = 0,
            .protocol = 0,
            .captured_len = @intCast(n),
            .original_len = @intCast(n),
        };
    }

    pub fn deinit(self: *Handle) void {
        os.close(self.fd);
        if (self.options.buffer_mode != .ring_mmap) {
            std.heap.page_allocator.free(self.buffer);
        }
        if (self.filter_program) |f| {
            std.heap.page_allocator.free(f);
        }
        if (self.ring) |r| {
            r.deinit();
        }
    }

    pub fn getSelectableFd(self: *Handle) c_int {
        return self.fd;
    }
};

test "linux resolveBufferMode falls back to copy when ring mmap unsupported" {
    const features_legacy: u32 = @intFromEnum(kernel.KernelFeatures.basic);
    const features_modern: u32 = features_legacy | @intFromEnum(kernel.KernelFeatures.ring_v3);

    try std.testing.expectEqual(BufferMode.copy, try Handle.resolveBufferMode(features_legacy, .ring_mmap, true));
    try std.testing.expectError(Error.RingSetupFailed, Handle.resolveBufferMode(features_legacy, .ring_mmap, false));
    try std.testing.expectEqual(BufferMode.ring_mmap, try Handle.resolveBufferMode(features_modern, .ring_mmap, true));
    try std.testing.expectEqual(BufferMode.ring_mmap, try Handle.resolveBufferMode(features_modern, .ring_mmap, false));
    try std.testing.expectEqual(BufferMode.copy, try Handle.resolveBufferMode(features_legacy, .copy, false));
}
