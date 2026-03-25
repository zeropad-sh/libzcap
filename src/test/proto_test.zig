const std = @import("std");
const testing = std.testing;
const EthernetFrame = @import("../proto/ethernet.zig").EthernetFrame;
const IPv4Packet = @import("../proto/ipv4.zig").IPv4Packet;
const IPv6Packet = @import("../proto/ipv6.zig").IPv6Packet;
const TcpSegment = @import("../proto/tcp.zig").TcpSegment;
const UdpDatagram = @import("../proto/udp.zig").UdpDatagram;

test "ethernet frame parse" {
    const packet = [_]u8{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // dst
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // src
        0x08, 0x00, // ethertype IPv4
        0x45, 0x00, 0x00, 0x3c, // IPv4 header
    };

    const frame = try EthernetFrame.parse(&packet);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 }, &frame.dst);
    try testing.expectEqualSlices(u8, &.{ 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb }, &frame.src);
    try testing.expectEqual(@as(u16, 0x0800), frame.ethertype);
    try testing.expectEqual(@as(usize, 20), frame.payload.len);
}

test "ethernet frame too short" {
    const packet = [_]u8{ 0x00, 0x11, 0x22 };
    const result = EthernetFrame.parse(&packet);
    try testing.expectError(error.TooShort, result);
}

test "ipv4 packet parse" {
    const packet = [_]u8{
        0x45, 0x00, // version/IHL, TOS
        0x00, 0x28, // total length 40
        0x1c, 0x46, // ID
        0x40, 0x00, // flags + fragment
        0x40, // TTL
        0x06, // protocol TCP
        0x00, 0x00, // checksum
        0xc0, 0xa8, 0x01, 0x64, // src 192.168.1.100
        0xc0, 0xa8, 0x01, 0x01, // dst 192.168.1.1
        0x04, 0x2e, // TCP src port
        0x00, 0x50, // TCP dst port
    };

    const ip = try IPv4Packet.parse(&packet);
    try testing.expectEqual(@as(u4, 4), ip.version());
    try testing.expectEqual(@as(u8, 20), ip.headerLen());
    try testing.expectEqual(@as(u16, 40), ip.totalLen());
    try testing.expectEqual(IPv4Packet.Protocol.tcp, ip.protocolNum());
}

test "ipv4 packet too short" {
    const packet = [_]u8{ 0x45, 0x00, 0x00, 0x28 };
    const result = IPv4Packet.parse(&packet);
    try testing.expectError(error.TooShort, result);
}

test "tcp segment parse" {
    const packet = [_]u8{
        0x04, 0x2e, // src port 1102
        0x01, 0xbb, // dst port 443
        0x00, 0x00, 0x00, 0x01, // seq
        0x00, 0x00, 0x00, 0x01, // ack
        0x50, 0x02, // data offset + flags (SYN)
        0x72, 0x10, // window
        0x00, 0x00, // checksum
        0x00, 0x00, // urgent
    };

    const tcp = try TcpSegment.parse(&packet);
    try testing.expectEqual(@as(u16, 1102), tcp.src_port);
    try testing.expectEqual(@as(u16, 443), tcp.dst_port);
    try testing.expectEqual(@as(u8, 20), tcp.headerLen());
    try testing.expect(tcp.flags().syn);
}

test "tcp segment with options" {
    var packet: [32]u8 = undefined;
    packet[0..2].* = .{ 0x04, 0x2e }; // src port
    packet[2..4].* = .{ 0x01, 0xbb }; // dst port
    packet[4..8].* = .{ 0x00, 0x00, 0x00, 0x01 }; // seq
    packet[8..12].* = .{ 0x00, 0x00, 0x00, 0x01 }; // ack
    packet[12..14].* = .{ 0x60, 0x02 }; // offset 24 + SYN flag
    packet[14..16].* = .{ 0x72, 0x10 }; // window
    packet[16..18].* = .{ 0x00, 0x00 }; // checksum
    packet[18..20].* = .{ 0x00, 0x00 }; // urgent
    // 4 bytes of options

    const tcp = try TcpSegment.parse(&packet);
    try testing.expectEqual(@as(u8, 24), tcp.headerLen());
    try testing.expectEqual(@as(usize, 8), tcp.payload.len);
}

test "udp datagram parse" {
    const packet = [_]u8{
        0x04, 0x2e, // src port 1102
        0x00, 0x35, // dst port 53 (DNS)
        0x00, 0x10, // length 16
        0x00, 0x00, // checksum
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // payload
    };

    const udp = try UdpDatagram.parse(&packet);
    try testing.expectEqual(@as(u16, 1102), udp.src_port);
    try testing.expectEqual(@as(u16, 53), udp.dst_port);
    try testing.expectEqual(@as(u16, 16), udp.length);
    try testing.expectEqual(@as(u16, 8), udp.dataLen());
}

test "udp datagram too short" {
    const packet = [_]u8{ 0x04, 0x2e, 0x00, 0x35 };
    const result = UdpDatagram.parse(&packet);
    try testing.expectError(error.TooShort, result);
}

test "ethernet frame IPv6 ethertype" {
    const packet = [_]u8{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0x86, 0xDD, // IPv6 ethertype
    };

    const frame = try EthernetFrame.parse(&packet);
    try testing.expectEqual(EthernetFrame.EtherType.ipv6, frame.etherType());
}
