const lib = @import("libzcap");

comptime {
    _ = lib;
}

pub const _kernel_tests = @import("kernel_test.zig");
pub const _proto_tests = @import("proto_test.zig");
pub const _cbpf_tests = @import("cbpf_test.zig");
pub const _filter_tests = @import("filter_test.zig");
