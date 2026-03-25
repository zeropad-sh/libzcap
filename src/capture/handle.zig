const std = @import("std");
const builtin = @import("builtin");
const proto = struct {
    const EthernetFrame = @import("../proto/ethernet.zig").EthernetFrame;
};

pub const Error = error{
    NoSuchDevice,
    PermissionDenied,
    InvalidFilter,
    BufferTooSmall,
    DeviceNotUp,
    SocketCreationFailed,
    MmapFailed,
    OutOfMemory,
    ProtocolNotSupported,
    InvalidSnaplen,
    RingSetupFailed,
    Timeout,
    FilterTooComplex,
    LibraryNotFound,
    SymbolNotFound,
} || std.posix.OpenError || std.posix.SocketError || std.posix.ReadError || std.posix.WriteError;

pub const CaptureOptions = struct {
    device: []const u8,
    snaplen: u32 = 65535,
    promisc: bool = false,
    timeout_ms: u32 = 1000,
    filter: ?[]const u8 = null,
    buffer_mode: BufferMode = .copy,
};

pub const BufferMode = enum {
    copy,
    ring_mmap,
};

pub const PacketView = struct {
    data: []const u8,
    timestamp_ns: u64,
    ifindex: u32,
    protocol: u16,
    captured_len: u32,
    original_len: u32,

    pub fn ethernetFrame(self: PacketView) Error!proto.EthernetFrame {
        return proto.EthernetFrame.parse(self.data);
    }
};

pub const Handle = switch (builtin.os.tag) {
    .linux => @import("linux.zig").Handle,
    .macos => @import("macos.zig").Handle,
    .freebsd, .openbsd, .netbsd, .dragonfly => @import("bsd.zig").Handle,
    .windows => @import("windows.zig").Handle,
    else => @compileError("Unsupported capture OS: " ++ @tagName(builtin.os.tag)),
};
