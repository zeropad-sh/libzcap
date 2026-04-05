const std = @import("std");
const os = std.posix;
const linux = std.os.linux;
const math = std.math;

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
        if (options.block_size == 0 or options.block_count == 0) {
            return Error.InvalidBlockSize;
        }

        if (options.frame_size == 0) {
            return Error.InvalidBlockSize;
        }

        if (!math.isPowerOfTwo(options.block_size) or options.block_size < 4096) {
            return Error.InvalidBlockSize;
        }
        if (!math.isPowerOfTwo(options.frame_size) or options.frame_size > options.block_size) {
            return Error.InvalidBlockSize;
        }

        if (options.block_size % options.frame_size != 0) {
            return Error.InvalidBlockSize;
        }

        const capacity_frames_u64 = @as(u64, options.block_size) * options.block_count;
        if (capacity_frames_u64 > std.math.maxInt(u32)) {
            return Error.InvalidBlockSize;
        }

        if (options.frame_count == 0) {
            options.frame_count = @intCast(capacity_frames_u64 / options.frame_size);
            if (options.frame_count == 0) {
                return Error.InvalidBlockSize;
            }
        } else if (options.frame_count < 16) {
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
        const total_size_u64 = @as(u64, options.block_size) * options.block_count;
        if (total_size_u64 > std.math.maxInt(usize)) {
            return Error.InvalidBlockSize;
        }

        const total_size: usize = @intCast(total_size_u64);
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
        var scanned: u32 = 0;
        while (scanned < ring.options.block_count) {
            const block = ring.getBlock(ring.block_idx);
            const status = @atomicLoad(u32, &block.bh1.block_status, .acquire);

            if (status & 1 == 0) { // TP_STATUS_USER not set
                return null;
            }

            const num_pkts = block.bh1.num_pkts;
            const block_len: usize = ring.options.block_size;
            if (num_pkts == 0 or ring.packet_idx > num_pkts) {
                ring.releaseCurrentBlock();
                scanned += 1;
                continue;
            }

            if (ring.packet_idx == 0) {
                ring.current_pkt_offset = block.bh1.offset_to_first_pkt;
            } else if (ring.current_pkt_offset == 0) {
                ring.releaseCurrentBlock();
                scanned += 1;
                continue;
            }

            const block_start = @as(usize, ring.block_idx) * block_len;
            const frame_start = ring.current_pkt_offset;
            const frame_abs_start = block_start + frame_start;
            const header_span = frame_start + @sizeOf(linux.tpacket3_hdr);
            if (header_span > block_len) {
                ring.releaseCurrentBlock();
                scanned += 1;
                continue;
            }

            const pkt: *linux.tpacket3_hdr = @ptrCast(@alignCast(ring.mmap_slice.ptr + frame_abs_start));
            var frame_end: usize = @as(usize, frame_start) + @as(usize, pkt.next_offset);
            if (frame_end == 0) {
                if (ring.packet_idx + 1 < num_pkts) {
                    ring.releaseCurrentBlock();
                    scanned += 1;
                    continue;
                }
                frame_end = block_len;
            }

            if (frame_end > block_len or frame_end <= frame_start) {
                ring.releaseCurrentBlock();
                scanned += 1;
                continue;
            }

            const mac_offset = frame_start + pkt.mac;
            if (pkt.len < pkt.snaplen or mac_offset > frame_end) {
                ring.releaseCurrentBlock();
                scanned += 1;
                continue;
            }

            const snap_end = mac_offset + pkt.snaplen;
            if (snap_end > frame_end or snap_end > block_len) {
                ring.releaseCurrentBlock();
                scanned += 1;
                continue;
            }

            const data = ring.mmap_slice[(block_start + mac_offset)..(block_start + snap_end)];
            const timestamp_ns = @as(u64, pkt.sec) * 1_000_000_000 + @as(u64, pkt.nsec);

            ring.packet_idx += 1;
            if (ring.packet_idx < num_pkts) {
                ring.current_pkt_offset += pkt.next_offset;
            } else {
                ring.releaseCurrentBlock();
            }

            return .{
                .data = data,
                .timestamp_ns = timestamp_ns,
                .captured_len = pkt.snaplen,
                .original_len = pkt.len,
            };
        }

        return null;
    }

    fn releaseCurrentBlock(ring: *Ring) void {
        const block = ring.getBlock(ring.block_idx);
        @atomicStore(u32, &block.bh1.block_status, 0, .release);
        ring.block_idx = (ring.block_idx + 1) % ring.options.block_count;
        ring.packet_idx = 0;
        ring.current_pkt_offset = 0;
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
