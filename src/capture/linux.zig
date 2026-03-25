const std = @import("std");
const os = std.posix;
const ring = @import("../ring.zig");
const handle_types = @import("handle.zig");
const CaptureOptions = handle_types.CaptureOptions;
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
        const fd = os.socket(os.AF.PACKET, os.SOCK.RAW, protocol) catch |err| return err;
        errdefer os.close(fd);

        var h = Handle{
            .fd = fd,
            .options = options,
            .buffer = undefined,
            .ring = null,
        };

        if (options.buffer_mode == .ring_mmap) {
            h.ring = ring.Ring.init(fd, .{ .timeout_ms = options.timeout_ms }) catch return Error.RingSetupFailed;
        } else {
            h.buffer = try std.heap.page_allocator.alloc(u8, options.snaplen);
            const tv = std.os.linux.timeval{
                .sec = @intCast(options.timeout_ms / 1000),
                .usec = @intCast((options.timeout_ms % 1000) * 1000),
            };
            os.setsockopt(fd, os.SOL.SOCKET, os.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};
        }

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
        }

        return h;
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
};
