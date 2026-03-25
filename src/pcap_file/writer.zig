const std = @import("std");
const reader = @import("reader.zig");

pub const Writer = struct {
    file: std.fs.File,
    header: reader.GlobalHeader,
    packets_written: u32 = 0,

    pub fn create(path: []const u8, snaplen: u32, linktype: reader.LinkType) !Writer {
        const file = try std.fs.cwd().createFile(path, .{});
        errdefer file.close();

        const header: reader.GlobalHeader = .{
            .magic = reader.Magic,
            .version_major = 2,
            .version_minor = 4,
            .thiszone = 0,
            .sigfigs = 0,
            .snaplen = snaplen,
            .network = @intFromEnum(linktype),
        };

        try file.writeAll(std.mem.asBytes(&header));

        return .{ .file = file, .header = header };
    }

    pub fn write(self: *Writer, timestamp_ns: u64, data: []const u8) !void {
        const hdr: reader.PacketHeader = .{
            .ts_sec = @intCast(timestamp_ns / std.time.ns_per_s),
            .ts_usec = @intCast((timestamp_ns % std.time.ns_per_s) / std.time.ns_per_us),
            .incl_len = @intCast(@min(data.len, self.header.snaplen)),
            .orig_len = @intCast(data.len),
        };
        try self.file.writeAll(std.mem.asBytes(&hdr));
        try self.file.writeAll(data[0..hdr.incl_len]);
        self.packets_written += 1;
    }

    pub fn flush(self: *Writer) !void {
        try self.file.sync();
    }
};
