const std = @import("std");
const os = std.posix;
const linux = std.os.linux;

pub const Error = error{
    RingSetupFailed,
    MmapFailed,
    InvalidBlockSize,
    OutOfMemory,
};

pub const RingOptions = struct {
    block_size: u32 = 1 << 22, // 4MB
    block_count: u32 = 64,
    frame_size: u32 = 2048,
    frame_count: u32 = 0, // computed from blocks
    timeout_ms: u32 = 1000,
};

pub const Ring = struct {
    fd: os.fd_t,
    mmap_slice: []align(4096) u8,
    mmap_len: usize,
    options: RingOptions,
    block_idx: u32 = 0,
    packet_idx: u32 = 0,
    current_pkt_offset: u32 = 0,
    version: u32 = 2,

    pub fn init(fd: os.fd_t, opts: RingOptions) Error!*Ring {
        var options = opts;
        if (options.frame_count == 0) {
            options.frame_count = (options.block_size * options.block_count) / options.frame_size;
        }

        // Ensure power of 2 alignment for block_size
        if (options.block_size < 4096 or (options.block_size & (options.block_size - 1)) != 0) {
            return Error.InvalidBlockSize;
        }

        // Set packet version for TPACKET_V3
        var version: u32 = 2;
        os.setsockopt(fd, os.SOL.PACKET, 10, std.mem.asBytes(&version)) catch return Error.RingSetupFailed; // PACKET_VERSION

        // Set up ring buffer
        var req = linux.tpacket_req3{
            .block_size = options.block_size,
            .block_nr = options.block_count,
            .frame_size = options.frame_size,
            .frame_nr = options.frame_count,
            .retire_blk_tov = options.timeout_ms,
            .sizeof_priv = 0,
            .feature_req_word = 0,
        };
        os.setsockopt(fd, os.SOL.PACKET, 5, std.mem.asBytes(&req)) catch return Error.RingSetupFailed; // PACKET_RX_RING

        // Map the ring buffer
        const total_size = options.block_size * options.block_count;
        const mmap_slice = os.mmap(null, total_size, os.PROT.READ | os.PROT.WRITE, .{ .TYPE = .SHARED }, fd, 0) catch return Error.MmapFailed;

        const ring = try std.heap.page_allocator.create(Ring);
        ring.* = .{
            .fd = fd,
            .mmap_slice = mmap_slice,
            .mmap_len = total_size,
            .options = options,
            .block_idx = 0,
            .packet_idx = 0,
            .current_pkt_offset = 0,
            .version = 3,
        };

        return ring;
    }

    pub fn deinit(ring: *Ring) void {
        os.munmap(ring.mmap_slice);
        std.heap.page_allocator.destroy(ring);
    }

    pub fn next(ring: *Ring) ?PacketView {
        const block = ring.getBlock(ring.block_idx);
        const status = @atomicLoad(u32, &block.bh1.block_status, .acquire);

        if (status & 1 == 0) { // TP_STATUS_USER not set
            return null;
        }

        const num_pkts = block.bh1.num_pkts;
        if (num_pkts == 0) {
            @atomicStore(u32, &block.bh1.block_status, 0, .release);
            ring.block_idx = (ring.block_idx + 1) % ring.options.block_count;
            ring.packet_idx = 0;
            return ring.next();
        }

        if (ring.packet_idx == 0) {
            ring.current_pkt_offset = block.bh1.offset_to_first_pkt;
        }

        // Get packet at current position
        const block_start = @as(usize, ring.block_idx) * ring.options.block_size;
        const pkt_offset_abs = block_start + ring.current_pkt_offset;
        const pkt: *linux.tpacket3_hdr = @ptrCast(@alignCast(ring.mmap_slice.ptr + pkt_offset_abs));

        const mac_offset = pkt_offset_abs + pkt.mac;
        const data = ring.mmap_slice[mac_offset .. mac_offset + pkt.snaplen];
        const timestamp_ns = @as(u64, pkt.sec) * 1_000_000_000 + @as(u64, pkt.nsec);

        ring.packet_idx += 1;
        if (ring.packet_idx < num_pkts) {
            ring.current_pkt_offset += pkt.next_offset;
        } else {
            @atomicStore(u32, &block.bh1.block_status, 0, .release);
            ring.block_idx = (ring.block_idx + 1) % ring.options.block_count;
            ring.packet_idx = 0;
        }

        return .{
            .data = data,
            .timestamp_ns = timestamp_ns,
            .captured_len = pkt.snaplen,
            .original_len = pkt.len,
        };
    }

    fn getBlock(ring: *Ring, idx: u32) *tpacket_block_desc {
        const offset = @as(usize, idx) * ring.options.block_size;
        return @ptrCast(@alignCast(ring.mmap_slice.ptr + offset));
    }

    const tpacket_block_desc = extern struct {
        version: u32,
        offset_to_priv: u32,
        bh1: extern struct {
            block_status: u32,
            num_pkts: u32,
            offset_to_first_pkt: u32,
            blk_len: u32,
            seq_num: u64,
            ts_first_pkt: extern struct {
                ts_sec: u32,
                ts_nsec: u32,
            },
            ts_last_pkt: extern struct {
                ts_sec: u32,
                ts_nsec: u32,
            },
        },
    };
};

pub const PacketView = struct {
    data: []const u8,
    timestamp_ns: u64,
    captured_len: u32,
    original_len: u32,
};
