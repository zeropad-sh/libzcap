const std = @import("std");
const testing = std.testing;
const libzcap = @import("libzcap");

const compiler = libzcap.cBPF;
const Instruction = libzcap.cBPF.Instruction;

const RET_ALL: u32 = 0xffff_ffff;
const RET_NONE: u32 = 0x0000_0000;

test "compile any filter emits unconditional return-all" {
    const program = compiler.compile("");
    try testing.expectEqual(@as(usize, 1), program.len);
    try testing.expectEqual(RET_ALL, program[0].k);
    try testing.expectEqual(@as(u16, 0x0006), program[0].code);
}

test "compile ip filter" {
    const program = compiler.compile("ip");
    try testing.expectEqual(@as(usize, 4), program.len);
    try testing.expectEqual(@as(u16, 0x0028), program[0].code); // ldh [12]
    try testing.expectEqual(@as(u16, 0x0015), program[1].code); // jeq ETH_P_IP
    try testing.expectEqual(@as(u8, 0), program[1].jt);
    try testing.expectEqual(@as(u8, 1), program[1].jf);
    try testing.expectEqual(@as(u16, 0x0006), program[2].code);
    try testing.expectEqual(RET_ALL, program[2].k);
    try testing.expectEqual(@as(u16, 0x0006), program[3].code);
    try testing.expectEqual(RET_NONE, program[3].k);
}

test "compile tcp port filter has proto and port checks" {
    const program = compiler.compile("tcp port 80");
    try testing.expectEqual(@as(usize, 10), program.len);
    try testing.expectEqual(@as(u16, 0x0028), program[0].code); // ldh [12]
    try testing.expectEqual(@as(u16, 0x0015), program[1].code); // jeq ETH_P_IP
    try testing.expectEqual(@as(u16, 0x0030), program[2].code); // ldb [23]
    try testing.expectEqual(@as(u16, 0x0015), program[3].code); // jeq proto
    try testing.expectEqual(@as(u8, 5), program[3].jf);
    try testing.expectEqual(@as(u16, 0x0028), program[4].code); // ldh [34]
    try testing.expectEqual(@as(u16, 0x0015), program[5].code); // jeq src port
    try testing.expectEqual(@as(u8, 2), program[5].jt);
    try testing.expectEqual(@as(u8, 1), program[5].jf);
    try testing.expectEqual(@as(u16, 0x0028), program[6].code); // ldh [36]
    try testing.expectEqual(@as(u16, 0x0015), program[7].code); // jeq dst port
    try testing.expectEqual(@as(u8, 0), program[7].jt);
    try testing.expectEqual(@as(u8, 1), program[7].jf);
    try testing.expectEqual(@as(u16, 0x0006), program[8].code); // ret all
    try testing.expectEqual(RET_ALL, program[8].k);
    try testing.expectEqual(@as(u16, 0x0006), program[9].code); // ret none
    try testing.expectEqual(RET_NONE, program[9].k);
}

test "compile tcp filter only" {
    const program = compiler.compile("tcp");
    try testing.expectEqual(@as(usize, 6), program.len);
    try testing.expectEqual(@as(u16, 0x0028), program[0].code); // ldh [12]
    try testing.expectEqual(@as(u16, 0x0015), program[1].code); // jeq ETH_P_IP
    try testing.expectEqual(@as(u8, 0), program[1].jt);
    try testing.expectEqual(@as(u8, 3), program[1].jf);
    try testing.expectEqual(@as(u16, 0x0030), program[2].code); // ldb [23]
    try testing.expectEqual(@as(u16, 0x0015), program[3].code); // jeq proto
    try testing.expectEqual(@as(u8, 0), program[3].jt);
    try testing.expectEqual(@as(u8, 1), program[3].jf);
    try testing.expectEqual(@as(u16, 0x0006), program[4].code); // ret all
    try testing.expectEqual(RET_ALL, program[4].k);
    try testing.expectEqual(@as(u16, 0x0006), program[5].code); // ret none
    try testing.expectEqual(RET_NONE, program[5].k);
}

test "compile udp filter only" {
    const program = compiler.compile("udp");
    try testing.expectEqual(@as(usize, 6), program.len);
    try testing.expectEqual(@as(u16, 0x0028), program[0].code); // ldh [12]
    try testing.expectEqual(@as(u16, 0x0015), program[1].code); // jeq ETH_P_IP
    try testing.expectEqual(@as(u8, 0), program[1].jt);
    try testing.expectEqual(@as(u8, 3), program[1].jf);
    try testing.expectEqual(@as(u16, 0x0030), program[2].code); // ldb [23]
    try testing.expectEqual(@as(u16, 0x0015), program[3].code); // jeq proto
    try testing.expectEqual(@as(u8, 0), program[3].jt);
    try testing.expectEqual(@as(u8, 1), program[3].jf);
    try testing.expectEqual(@as(u16, 0x0006), program[4].code); // ret all
    try testing.expectEqual(RET_ALL, program[4].k);
    try testing.expectEqual(@as(u16, 0x0006), program[5].code); // ret none
    try testing.expectEqual(RET_NONE, program[5].k);
}

test "runtime compiler rejects unsupported expression" {
    const alloc = std.testing.allocator;
    try testing.expectError(error.FilterTooComplex, compiler.compileRuntime(alloc, "ip port 80"));
}

test "runtime compiler rejects mixed protocol terms" {
    const alloc = std.testing.allocator;
    try testing.expectError(error.FilterTooComplex, compiler.compileRuntime(alloc, "tcp udp"));
}
