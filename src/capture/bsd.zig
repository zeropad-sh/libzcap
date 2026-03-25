const std = @import("std");
const os = std.posix;
const handle_types = @import("handle.zig");
const CaptureOptions = handle_types.CaptureOptions;
const PacketView = handle_types.PacketView;
const Error = handle_types.Error;

pub const Handle = struct {
    fd: os.fd_t,
    options: CaptureOptions,
    buffer: []align(4096) u8,
    buf_pos: usize = 0,
    buf_len: usize = 0,

    pub fn open(options: CaptureOptions) Error!Handle {
        var buf: [64]u8 = undefined;
        var fd: ?os.fd_t = null;

        for (0..99) |i| {
            const path = std.fmt.bufPrintZ(&buf, "/dev/bpf{d}", .{i}) catch return Error.NoSuchDevice;
            if (os.openZ(path, .{ .ACCMODE = .RDWR }, 0)) |opened_fd| {
                fd = opened_fd;
                break;
            } else |err| {
                if (err == error.DeviceBusy) continue;
                if (err == error.FileNotFound) break;
            }
        }
        
        const valid_fd = fd orelse return Error.PermissionDenied;
        errdefer os.close(valid_fd);

        const bpf_buf_len: u32 = 2 * 1024 * 1024; // 2MB fallback buffer
        const buffer = try std.heap.page_allocator.alignedAlloc(u8, 4096, bpf_buf_len);

        return Handle{
            .fd = valid_fd,
            .options = options,
            .buffer = buffer,
        };
    }

    pub fn next(self: *Handle) Error!PacketView {
        if (self.buf_pos >= self.buf_len) {
            const n = os.read(self.fd, self.buffer) catch |err| {
                if (err == error.WouldBlock) return Error.Timeout;
                return err;
            };
            if (n == 0) return Error.Timeout;
            self.buf_len = n;
            self.buf_pos = 0;
        }

        if (self.buf_len - self.buf_pos < 18) return Error.Timeout;

        const hdr_mem = self.buffer[self.buf_pos..];
        const caplen = std.mem.readInt(u32, hdr_mem[8..12], .native);
        const datalen = std.mem.readInt(u32, hdr_mem[12..16], .native);
        const hdrlen = std.mem.readInt(u16, hdr_mem[16..18], .native);

        const data_start = self.buf_pos + hdrlen;
        const data_end = data_start + caplen;
        
        if (data_end > self.buf_len) {
            self.buf_len = 0;
            return Error.Timeout;
        }

        const data = self.buffer[data_start..data_end];
        
        const total_consumed = hdrlen + caplen;
        const padded_consumed = (total_consumed + 3) & ~@as(u32, 3);
        self.buf_pos += padded_consumed;

        return .{
            .data = data,
            .timestamp_ns = 0,
            .ifindex = 0,
            .protocol = 0,
            .captured_len = caplen,
            .original_len = datalen,
        };
    }

    pub fn deinit(self: *Handle) void {
        os.close(self.fd);
        std.heap.page_allocator.free(self.buffer);
    }
};
