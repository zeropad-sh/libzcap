pub const Handle = @import("capture/handle.zig").Handle;
pub const CaptureOptions = @import("capture/handle.zig").CaptureOptions;
pub const FanoutMode = @import("capture/handle.zig").FanoutMode;
pub const FanoutConfig = @import("capture/handle.zig").FanoutConfig;
pub const PacketView = @import("capture/handle.zig").PacketView;
pub const BufferMode = @import("capture/handle.zig").BufferMode;
pub const Error = @import("capture/handle.zig").Error;

pub const cBPF = struct {
    pub const Instruction = @import("filter/cbpf.zig").Instruction;
    pub const Program = @import("filter/cbpf.zig").Program;
    pub const compile = @import("filter/compiler.zig").compile;
    pub const compileRuntime = @import("filter/compiler.zig").compileRuntime;
};

pub const kernel = @import("capture/kernel.zig");
pub const stats = @import("stats.zig");
pub const ring = @import("ring.zig");

pub const proto = .{
    .EthernetFrame = @import("proto/ethernet.zig").EthernetFrame,
    .IPv4Packet = @import("proto/ipv4.zig").IPv4Packet,
    .IPv6Packet = @import("proto/ipv6.zig").IPv6Packet,
    .TcpSegment = @import("proto/tcp.zig").TcpSegment,
    .UdpDatagram = @import("proto/udp.zig").UdpDatagram,
    .SctpDatagram = @import("proto/sctp.zig").SctpDatagram,
};

pub const pcap_file = .{
    .Reader = @import("pcap_file/reader.zig").Reader,
    .Writer = @import("pcap_file/writer.zig").Writer,
    .PacketHeader = @import("pcap_file/reader.zig").PacketHeader,
    .GlobalHeader = @import("pcap_file/reader.zig").GlobalHeader,
};

pub const pcap_compat = @import("api/pcap_compat.zig");
pub const native = @import("api/native.zig");

// Force compilation of C-ABI exports for dynamic library linking
comptime {
    _ = @import("api/pcap_compat.zig");
}
