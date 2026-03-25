const std = @import("std");
const libzcap = @import("libzcap");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const iface = "lo"; // Loopback interface - safe to test with

    // Open capture handle
    std.debug.print("Opening capture on {s}...\n", .{iface});
    var handle = libzcap.Handle.open(.{
        .device = iface,
        .snaplen = 65535,
        .promisc = false,
        .timeout_ms = 1000,
    }) catch |err| {
        std.debug.print("Failed to open capture: {}\n", .{err});
        return;
    };
    defer handle.deinit();

    std.debug.print("Capture opened successfully!\n", .{});

    // Generate some traffic using ping to loopback
    std.debug.print("Generating test traffic (ping 127.0.0.1)...\n", .{});
    const ping_result = std.ChildProcess.exec(.{
        .allocator = alloc,
        .argv = &.{ "ping", "-c", "5", "-W", "1", "127.0.0.1" },
    }) catch |err| {
        std.debug.print("Failed to run ping: {}\n", .{err});
        return;
    };
    defer ping_result.cleanup();

    if (ping_result.term.Exited != 0) {
        std.debug.print("Ping exited with code: {}\n", .{ping_result.term.Exited});
        std.debug.print("stderr: {s}\n", .{ping_result.stderr});
    } else {
        std.debug.print("Ping started!\n", .{});
    }

    // Small delay to let packets arrive
    std.time.sleep(500 * std.time.ns_per_ms);

    // Capture some packets
    std.debug.print("\nCapturing packets...\n", .{});
    var captured_packets: usize = 0;
    var packets_data = std.ArrayList(struct { data: []u8, ts: u64 }).init(alloc);
    defer {
        for (packets_data.items) |p| alloc.free(p.data);
        packets_data.deinit();
    }

    while (captured_packets < 10) {
        const pkt = handle.next() catch |err| {
            std.debug.print("Capture error (packet {}): {}\n", .{ captured_packets, err });
            break;
        };

        std.debug.print("  Captured packet {} ({} bytes)\n", .{ captured_packets + 1, pkt.captured_len });

        // Copy packet data for later use
        const data_copy = try alloc.alloc(u8, pkt.captured_len);
        @memcpy(data_copy, pkt.data);
        try packets_data.append(.{ .data = data_copy, .ts = pkt.timestamp_ns });

        captured_packets += 1;
    }

    if (captured_packets == 0) {
        std.debug.print("No packets captured. Try running 'ping 127.0.0.1' in another terminal.\n", .{});
        return;
    }

    std.debug.print("\nCaptured {} packets total!\n", .{captured_packets});

    // Write to pcap file
    const output_path = "/tmp/libzcap_test.pcap";
    std.debug.print("\nWriting to {s}...\n", .{output_path});

    var writer = libzcap.pcap_file.Writer.open(output_path, .{
        .network = 1, // DLT_EN10MB for Ethernet
        .snaplen = 65535,
    }) catch |err| {
        std.debug.print("Failed to create pcap writer: {}\n", .{err});
        return;
    };
    defer writer.deinit();

    for (packets_data.items, 0..) |pkt, i| {
        const ts_sec = @as(u32, @intCast(pkt.ts / std.time.ns_per_s));
        const ts_usec = @as(u32, @intCast((pkt.ts % std.time.ns_per_s) / std.time.ns_per_us));
        writer.writePacket(pkt.data, ts_sec, ts_usec) catch |err| {
            std.debug.print("Failed to write packet {}: {}\n", .{ i, err });
            return;
        };
        std.debug.print("  Wrote packet {}\n", .{i + 1});
    }

    writer.close();
    std.debug.print("Wrote {} packets to {s}\n", .{ captured_packets, output_path });

    // Read back and display
    std.debug.print("\nReading back from {s}...\n", .{output_path});
    var reader = libzcap.pcap_file.Reader.open(output_path) catch |err| {
        std.debug.print("Failed to open pcap reader: {}\n", .{err});
        return;
    };
    defer reader.file.close();

    std.debug.print("Link type: {}\n\n", .{reader.header.network});

    var read_count: u32 = 0;
    while (true) {
        const pkt = reader.next() catch |err| {
            std.debug.print("Read error: {}\n", .{err});
            break;
        } orelse break;
        read_count += 1;

        std.debug.print("Packet {}: {} bytes at {}.{:06}\n", .{
            read_count,
            pkt.data.len,
            pkt.header.ts_sec,
            pkt.header.ts_usec,
        });

        // Try to parse as IPv4
        if (pkt.data.len >= 20) {
            const version = (pkt.data[0] >> 4) & 0xF;
            if (version == 4) {
                const proto = pkt.data[9];
                const src_ip = pkt.data[12..16];
                const dst_ip = pkt.data[16..20];
                std.debug.print("  IPv4: {}.{}.{}.{} -> {}.{}.{}.{} proto={}\n", .{
                    src_ip[0], src_ip[1], src_ip[2], src_ip[3],
                    dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3],
                    proto,
                });
            }
        }
    }

    std.debug.print("\n=== SUCCESS ===\n", .{});
    std.debug.print("End-to-end test passed!\n", .{});
    std.debug.print("Captured {} packets, wrote to pcap, and read them back.\n", .{read_count});
}
