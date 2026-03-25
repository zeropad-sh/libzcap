const std = @import("std");
const libzcap = @import("libzcap");
const pcap_file = libzcap.pcap_file;
const proto = libzcap.proto;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);

    if (args.len < 2) {
        try std.fs.File.stderr().writeAll("Usage:\n");
        try std.fs.File.stderr().writeAll("  zigdump <pcap-file>                                    - Read and display pcap file\n");
        try std.fs.File.stderr().writeAll("  zigdump --capture <iface> [output.pcap] [count]        - Capture packets\n");
        try std.fs.File.stderr().writeAll("  zigdump --capture <iface> [output.pcap] --timeout N    - Capture with timeout (seconds)\n");
        return;
    }

    if (std.mem.eql(u8, args[1], "--capture") or std.mem.eql(u8, args[1], "-c")) {
        if (args.len < 3) {
            try std.fs.File.stderr().writeAll("Usage: zigdump --capture <interface> [output.pcap] [count] [--timeout N]\n");
            return;
        }
        const iface = args[2];
        const output_path = if (args.len > 3) args[3] else "/tmp/capture.pcap";
        const count: usize = if (args.len > 4) std.fmt.parseInt(usize, args[4], 10) catch 10 else 10;

        var timeout_secs: ?f64 = null;
        for (args[4..], 0..) |arg, i| {
            if (std.mem.eql(u8, arg, "--timeout") or std.mem.eql(u8, arg, "-t")) {
                if (4 + i + 1 < args.len) {
                    timeout_secs = std.fmt.parseFloat(f64, args[4 + i + 1]) catch null;
                }
            }
        }

        try captureToFile(iface, output_path, count, timeout_secs, alloc);
    } else {
        try dumpFile(args[1]);
    }
}

fn captureToFile(iface: []const u8, output_path: []const u8, max_packets: usize, timeout_secs: ?f64, alloc: std.mem.Allocator) !void {
    const stderr = std.fs.File.stderr();

    try stderr.writeAll("=== libzcap Packet Capture ===\n");
    try stderr.writeAll("Interface: ");
    try stderr.writeAll(iface);
    try stderr.writeAll("\n");
    try stderr.writeAll("Output: ");
    try stderr.writeAll(output_path);
    try stderr.writeAll("\n");
    try stderr.writeAll("Max packets: ");
    try printNum(stderr, max_packets);
    if (timeout_secs) |t| {
        try stderr.writeAll("\nTimeout: ");
        try printNum(stderr, @as(u32, @intFromFloat(t)));
        try stderr.writeAll(" seconds");
    }
    try stderr.writeAll("\n\n");

    // Open capture handle
    try stderr.writeAll("Opening capture handle...\n");
    var handle = libzcap.Handle.open(.{
        .device = iface,
        .snaplen = 65535,
        .promisc = false,
        .timeout_ms = 100,
        .buffer_mode = .ring_mmap,
    }) catch |err| {
        try stderr.writeAll("Error opening capture: ");
        try stderr.writeAll(@errorName(err));
        try stderr.writeAll("\n");
        return;
    };
    defer handle.deinit();
    try stderr.writeAll("Capture handle opened.\n\n");

    // Open pcap writer
    try stderr.writeAll("Opening pcap writer...\n");
    var writer = try pcap_file.Writer.create(output_path, 65535, .ethernet);
    try stderr.writeAll("Pcap writer opened.\n\n");

    // Generate test traffic
    try stderr.writeAll("Generating test traffic...\n");
    const ping_args = if (@import("builtin").os.tag == .windows)
        &[_][]const u8{ "ping", "-n", "100", "127.0.0.1" }
    else
        &[_][]const u8{ "ping", "-c", "100", "127.0.0.1" };
    var ping = std.process.Child.init(ping_args, alloc);
    try ping.spawn();
    defer {
        _ = ping.kill() catch {};
        _ = ping.wait() catch {};
    }
    try stderr.writeAll("Traffic generator started.\n\n");

    try stderr.writeAll("Capturing packets...\n");
    try stderr.writeAll("-" ** 60);
    try stderr.writeAll("\n");

    var captured: usize = 0;
    var errors: usize = 0;
    const start_ns = std.time.nanoTimestamp();

    while (captured < max_packets) {
        // Check timeout
        if (timeout_secs) |t| {
            const elapsed = @as(f64, @floatFromInt(std.time.nanoTimestamp() - start_ns)) / 1_000_000_000.0;
            if (elapsed >= t) {
                try stderr.writeAll("\nTimeout reached.\n");
                break;
            }
        }

        const pkt = handle.next() catch |err| {
            if (err == libzcap.Error.Timeout) {
                if (timeout_secs != null) {
                    try stderr.writeAll("\nTimeout reached (no more packets).\n");
                    break;
                }
                continue;
            }
            errors += 1;
            if (errors > 10) {
                try stderr.writeAll("\nToo many errors, stopping.\n");
                break;
            }
            continue;
        };

        captured += 1;

        // Write to pcap
        writer.write(pkt.timestamp_ns, pkt.data) catch |err| {
            try stderr.writeAll("Write error: ");
            try stderr.writeAll(@errorName(err));
            try stderr.writeAll("\n");
            break;
        };

        // Show progress
        try printNum(stderr, captured);
        try stderr.writeAll(": ");
        try printNum(stderr, pkt.captured_len);
        try stderr.writeAll(" bytes");

        // Try to show protocol info
        if (pkt.data.len >= 14) {
            const ether_type = std.mem.readInt(u16, pkt.data[12..14], .big);
            try stderr.writeAll(" ethertype=0x");
            try printHex(stderr, ether_type);
        }
        try stderr.writeAll("\n");
    }

    try stderr.writeAll("\n");
    try stderr.writeAll("=" ** 60);
    try stderr.writeAll("\n");
    try stderr.writeAll("Capture complete!\n");
    try printNum(stderr, captured);
    try stderr.writeAll(" packets written to ");
    try stderr.writeAll(output_path);
    try stderr.writeAll("\n");

    if (errors > 0) {
        try stderr.writeAll("Encountered ");
        try printNum(stderr, errors);
        try stderr.writeAll(" errors during capture.\n");
    }
}

fn dumpFile(path: []const u8) !void {
    var reader = try pcap_file.Reader.open(path);
    defer reader.file.close();

    const stderr = std.fs.File.stderr();
    try printHeader(stderr, path, reader.header);
    try stderr.writeAll("\n");

    var count: u32 = 0;
    var tcp_count: u32 = 0;
    var udp_count: u32 = 0;
    var sctp_count: u32 = 0;
    var icmp_count: u32 = 0;
    var icmpv6_count: u32 = 0;
    var arp_count: u32 = 0;
    var other_count: u32 = 0;

    while (true) {
        const pkt_opt = reader.next() catch |err| {
            try stderr.writeAll("\nRead error: ");
            try stderr.writeAll(@errorName(err));
            try stderr.writeAll("\n");
            break;
        };
        const pkt = pkt_opt orelse break;
        count += 1;

        const parsed = parsePacketDetails(reader.header.network, pkt.data);
        switch (parsed.protocol) {
            .tcp => tcp_count += 1,
            .udp => udp_count += 1,
            .sctp => sctp_count += 1,
            .icmp => icmp_count += 1,
            .icmpv6 => icmpv6_count += 1,
            .arp => arp_count += 1,
            else => other_count += 1,
        }

        if (count <= 20) {
            try printPacketLine(stderr, count, &parsed, pkt.header.ts_sec, pkt.header.ts_usec, pkt.data.len);
        }
    }

    try printSummary(stderr, count, tcp_count, udp_count, sctp_count, icmp_count, icmpv6_count, arp_count, other_count);
}

fn printHeader(stderr: anytype, path: []const u8, header: pcap_file.GlobalHeader) !void {
    try stderr.writeAll("File: ");
    try stderr.writeAll(path);
    try stderr.writeAll("\n");
    try stderr.writeAll("Link type: ");
    try printDlt(stderr, header.network);
    try stderr.writeAll(" (");
    try printDltName(stderr, header.network);
    try stderr.writeAll(")");
    try stderr.writeAll("  |  Snaplen: ");
    try printNum(stderr, header.snaplen);
    try stderr.writeAll(" bytes\n");
    try stderr.writeAll("-" ** 95);
    try stderr.writeAll("\n");
    try stderr.writeAll("  NUM  TIME STAMP            | PROTO  | SRC ADDR:PORT          | DST ADDR:PORT          | LEN    | CHKSUM   | INFO\n");
    try stderr.writeAll("-" ** 95);
    try stderr.writeAll("\n");
}

fn printPacketLine(stderr: anytype, num: u32, parsed: *const PacketDetails, ts_sec: u32, ts_usec: u32, total_len: usize) !void {
    try printPaddedNum(stderr, num, 5);
    try stderr.writeAll(" ");

    const ts_str = formatTimestamp(ts_sec, ts_usec);
    try stderr.writeAll(&ts_str);
    try stderr.writeAll(" | ");

    try printProtocol(stderr, parsed);
    try stderr.writeAll("  | ");

    try printAddresses(stderr, parsed);
    try stderr.writeAll(" | ");

    try printPaddedNum(stderr, @as(u32, @intCast(total_len)), 5);
    try stderr.writeAll("  | ");

    try printChecksum(stderr, parsed);
    try stderr.writeAll("   | ");

    try printExtraInfo(stderr, parsed);
    try stderr.writeAll("\n");
}

fn formatTimestamp(ts_sec: u32, ts_usec: u32) [28]u8 {
    var buf: [28]u8 = .{' '} ** 28;
    const secs: u64 = ts_sec;
    const hours = secs / 3600;
    const mins = (secs % 3600) / 60;
    const secs_rem = secs % 60;
    const ms = ts_usec / 1000;
    const us = ts_usec % 1000;
    _ = std.fmt.bufPrint(&buf, "{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}:{d:0>3}", .{ hours, mins, secs_rem, ms, us }) catch {};
    return buf;
}

const PacketDetails = struct {
    ether_type: u16 = 0,
    ip_version: u8 = 0,
    src_ip: [46]u8 = undefined,
    dst_ip: [46]u8 = undefined,
    src_ip_len: usize = 0,
    dst_ip_len: usize = 0,
    protocol: Protocol = .unknown,
    src_port: u16 = 0,
    dst_port: u16 = 0,
    checksum: u16 = 0,
    payload_len: u16 = 0,
    tcp_flags: u8 = 0,
    vlan: u16 = 0,
};

const Protocol = enum { tcp, udp, sctp, icmp, icmpv6, arp, ipv4, ipv6, vlan, other, unknown };

fn parsePacketDetails(dlt: u32, data: []const u8) PacketDetails {
    var result: PacketDetails = .{};

    switch (dlt) {
        1 => {
            if (data.len < 14) return result;
            result.ether_type = std.mem.readInt(u16, data[12..14], .big);
            return parseL3(&result, data[14..]);
        },
        101 => {
            if (data.len < 1) return result;
            const version = (data[0] >> 4) & 0xF;
            if (version == 4 and data.len >= 20) {
                result.ip_version = 4;
                return parseIpv4(&result, data);
            }
            if (version == 6 and data.len >= 40) {
                result.ip_version = 6;
                return parseIpv6(&result, data);
            }
            return result;
        },
        113 => {
            if (data.len < 16) return result;
            result.ether_type = std.mem.readInt(u16, data[14..16], .big);
            return parseL3(&result, data[16..]);
        },
        276 => {
            if (data.len < 20) return result;
            result.ether_type = std.mem.readInt(u16, data[18..20], .big);
            return parseL3(&result, data[20..]);
        },
        else => return result,
    }
}

fn parseL3(result: *PacketDetails, payload: []const u8) PacketDetails {
    switch (result.ether_type) {
        0x8100, 0x88A8 => {
            if (payload.len < 4) return result.*;
            result.vlan = std.mem.readInt(u16, payload[0..2], .big);
            result.ether_type = std.mem.readInt(u16, payload[2..4], .big);
            result.protocol = .vlan;
            return parseL3(result, payload[4..]);
        },
        0x0800 => {
            result.ip_version = 4;
            return parseIpv4(result, payload);
        },
        0x86DD => {
            result.ip_version = 6;
            return parseIpv6(result, payload);
        },
        0x0806 => {
            result.protocol = .arp;
            return result.*;
        },
        else => {
            result.protocol = .other;
            return result.*;
        },
    }
}

fn parseIpv4(result: *PacketDetails, data: []const u8) PacketDetails {
    if (data.len < 20) return result.*;

    const ip = proto.IPv4Packet.parse(data) catch return result.*;
    var src_buf: [15]u8 = undefined;
    var dst_buf: [15]u8 = undefined;
    const src_len = ip.srcString(&src_buf).len;
    const dst_len = ip.dstString(&dst_buf).len;
    for (src_buf[0..src_len], 0..) |byte, i| result.src_ip[i] = byte;
    for (dst_buf[0..dst_len], 0..) |byte, i| result.dst_ip[i] = byte;
    result.src_ip_len = src_len;
    result.dst_ip_len = dst_len;
    result.checksum = ip.checksum;
    result.payload_len = @intCast(ip.dataLen());

    switch (ip.protocol) {
        6 => return parseTcp(result, ip.payload),
        17 => return parseUdp(result, ip.payload),
        132 => {
            result.protocol = .sctp;
            return result.*;
        },
        1 => {
            result.protocol = .icmp;
            return result.*;
        },
        else => {
            result.protocol = .ipv4;
            return result.*;
        },
    }
}

fn parseIpv6(result: *PacketDetails, data: []const u8) PacketDetails {
    if (data.len < 40) return result.*;

    const ip = proto.IPv6Packet.parse(data) catch return result.*;
    var src_buf: [46]u8 = undefined;
    var dst_buf: [46]u8 = undefined;
    const src_len = ip.srcString(&src_buf).len;
    const dst_len = ip.dstString(&dst_buf).len;
    for (src_buf[0..src_len], 0..) |byte, i| result.src_ip[i] = byte;
    for (dst_buf[0..dst_len], 0..) |byte, i| result.dst_ip[i] = byte;
    result.src_ip_len = src_len;
    result.dst_ip_len = dst_len;
    result.payload_len = ip.payload_len;

    var payload_data = ip.payload;
    var next_hdr: u8 = ip.next_header;

    while (true) {
        if (next_hdr == 17) {
            return parseUdp(result, payload_data);
        } else if (next_hdr == 6) {
            return parseTcp(result, payload_data);
        } else if (next_hdr == 132) {
            result.protocol = .sctp;
            return result.*;
        } else if (next_hdr == 58) {
            result.protocol = .icmpv6;
            return result.*;
        } else if (next_hdr == 0 or next_hdr == 43 or next_hdr == 44 or next_hdr == 50 or next_hdr == 51 or next_hdr == 60) {
            if (payload_data.len < 8) return result.*;
            next_hdr = payload_data[0];
            const ext_len = payload_data[1];
            const len_bytes = (@as(usize, ext_len) + 1) * 8;
            if (len_bytes > payload_data.len) return result.*;
            payload_data = payload_data[len_bytes..];
        } else {
            result.protocol = .ipv6;
            return result.*;
        }
    }
}

fn parseTcp(result: *PacketDetails, data: []const u8) PacketDetails {
    if (data.len < 20) return result.*;

    const tcp = proto.TcpSegment.parse(data) catch return result.*;
    result.protocol = .tcp;
    result.src_port = tcp.src_port;
    result.dst_port = tcp.dst_port;
    result.checksum = tcp.checksum;
    result.tcp_flags = tcp.flagsRaw();
    result.payload_len = @intCast(tcp.payload.len);
    return result.*;
}

fn parseUdp(result: *PacketDetails, data: []const u8) PacketDetails {
    if (data.len < 8) return result.*;

    const udp = proto.UdpDatagram.parse(data) catch return result.*;
    result.protocol = .udp;
    result.src_port = udp.src_port;
    result.dst_port = udp.dst_port;
    result.checksum = udp.checksum;
    result.payload_len = udp.dataLen();
    return result.*;
}

fn printProtocol(stderr: anytype, p: *const PacketDetails) !void {
    const name: []const u8 = switch (p.protocol) {
        .tcp => "TCP",
        .udp => "UDP",
        .sctp => "SCTP",
        .icmp => "ICMP",
        .icmpv6 => "ICMPv6",
        .arp => "ARP",
        .ipv4 => "IPv4",
        .ipv6 => "IPv6",
        .vlan => "VLAN",
        .other => "ETH",
        .unknown => "UNK",
    };
    try stderr.writeAll(name);
}

fn printAddresses(stderr: anytype, p: *const PacketDetails) !void {
    switch (p.protocol) {
        .tcp, .udp => {
            if (p.src_ip_len > 0) {
                try stderr.writeAll(p.src_ip[0..p.src_ip_len]);
            }
            try stderr.writeAll(":");
            try printNum(stderr, p.src_port);
            try stderr.writeAll(" -> ");
            if (p.dst_ip_len > 0) {
                try stderr.writeAll(p.dst_ip[0..p.dst_ip_len]);
            }
            try stderr.writeAll(":");
            try printNum(stderr, p.dst_port);
        },
        .icmp, .icmpv6 => {
            if (p.src_ip_len > 0) {
                try stderr.writeAll(p.src_ip[0..p.src_ip_len]);
            }
            try stderr.writeAll(" -> ");
            if (p.dst_ip_len > 0) {
                try stderr.writeAll(p.dst_ip[0..p.dst_ip_len]);
            }
        },
        else => {
            if (p.src_ip_len > 0) {
                try stderr.writeAll(p.src_ip[0..p.src_ip_len]);
            }
            try stderr.writeAll(" -> ");
            if (p.dst_ip_len > 0) {
                try stderr.writeAll(p.dst_ip[0..p.dst_ip_len]);
            }
        },
    }
}

fn printChecksum(stderr: anytype, p: *const PacketDetails) !void {
    if (p.protocol == .tcp or p.protocol == .udp or p.protocol == .icmp or p.protocol == .icmpv6 or p.protocol == .ipv4 or p.protocol == .ipv6) {
        try printHex(stderr, p.checksum);
    } else {
        try stderr.writeAll("    ");
    }
}

fn printHex(stderr: anytype, val: u16) !void {
    var buf: [8]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, "0x{X:0>4}", .{val}) catch "0x0000";
    try stderr.writeAll(s);
}

fn printExtraInfo(stderr: anytype, p: *const PacketDetails) !void {
    if (p.protocol == .tcp) {
        var flags_buf: [12]u8 = undefined;
        var idx: usize = 0;
        const f = p.tcp_flags;
        if (f & 0x02 != 0) {
            flags_buf[idx] = 'S';
            idx += 1;
        }
        if (f & 0x01 != 0) {
            flags_buf[idx] = 'F';
            idx += 1;
        }
        if (f & 0x04 != 0) {
            flags_buf[idx] = 'R';
            idx += 1;
        }
        if (f & 0x10 != 0) {
            flags_buf[idx] = 'A';
            idx += 1;
        }
        if (f & 0x08 != 0) {
            flags_buf[idx] = 'P';
            idx += 1;
        }
        if (f & 0x20 != 0) {
            flags_buf[idx] = 'U';
            idx += 1;
        }

        if (idx > 0) {
            try stderr.writeAll(flags_buf[0..idx]);
        } else {
            try stderr.writeAll("none");
        }
        try stderr.writeAll(" seq=");
        try printNum(stderr, p.payload_len);
    } else if (p.protocol == .udp or p.protocol == .icmp) {
        try stderr.writeAll("payload=");
        try printNum(stderr, p.payload_len);
    } else if (p.vlan != 0) {
        try stderr.writeAll("vlan=");
        try printNum(stderr, p.vlan);
    } else if (p.payload_len > 0) {
        try printNum(stderr, p.payload_len);
        try stderr.writeAll(" bytes");
    } else {
        try stderr.writeAll("-");
    }
}

fn printSummary(stderr: anytype, count: u32, tcp: u32, udp: u32, sctp: u32, icmp: u32, icmpv6: u32, arp: u32, other: u32) !void {
    try stderr.writeAll("\n");
    try stderr.writeAll("=" ** 95);
    try stderr.writeAll("\n");
    try stderr.writeAll("SUMMARY: ");
    try printNum(stderr, count);
    try stderr.writeAll(" packets\n");
    try stderr.writeAll("  TCP: ");
    try printNum(stderr, tcp);
    try stderr.writeAll("  |  UDP: ");
    try printNum(stderr, udp);
    try stderr.writeAll("  |  SCTP: ");
    try printNum(stderr, sctp);
    try stderr.writeAll("  |  ICMP: ");
    try printNum(stderr, icmp);
    try stderr.writeAll("  |  ICMPv6: ");
    try printNum(stderr, icmpv6);
    try stderr.writeAll("  |  ARP: ");
    try printNum(stderr, arp);
    try stderr.writeAll("  |  Other: ");
    try printNum(stderr, other);
    try stderr.writeAll("\n");
}

fn printDlt(stderr: anytype, dlt: u32) !void {
    var buf: [16]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, "{}", .{dlt}) catch "err";
    try stderr.writeAll(s);
}

fn printDltName(stderr: anytype, dlt: u32) !void {
    const name: []const u8 = switch (dlt) {
        0 => "NULL",
        1 => "EN10MB",
        101 => "RAW",
        108 => "LOOP",
        113 => "LINUX_SLL",
        276 => "LINUX_SLL2",
        228 => "IPV4",
        229 => "IPV6",
        105 => "IEEE802_11",
        127 => "IEEE802_11_RADIO",
        248 => "SCTP",
        else => "UNKNOWN",
    };
    try stderr.writeAll(name);
}

fn printNum(stderr: anytype, num: anytype) !void {
    var buf: [32]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, "{}", .{num}) catch "err";
    try stderr.writeAll(s);
}

fn printPaddedNum(stderr: anytype, num: anytype, width: usize) !void {
    var buf: [32]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, "{}", .{num}) catch "err";
    const padding = if (s.len < width) width - s.len else 0;
    var i: usize = 0;
    while (i < padding) : (i += 1) try stderr.writeAll(" ");
    try stderr.writeAll(s);
}
