const std = @import("std");
const testing = std.testing;
const cBPF = @import("../filter/cbpf.zig");
const Instruction = cBPF.Instruction;

test "cBPF instruction ld" {
    const inst = Instruction.ld(.w, .abs, 12);
    try testing.expectEqual(@as(u8, 0x00), inst.code);
    try testing.expectEqual(@as(u32, 12), inst.k);
}

test "cBPF instruction ldx" {
    const inst = Instruction.ldx(.w, .mem, 0);
    try testing.expectEqual(@as(u8, 0x01 | 0x01), inst.code);
}

test "cBPF instruction ret" {
    const inst = Instruction.ret(65535);
    try testing.expectEqual(@as(u32, 65535), inst.k);
}

test "cBPF instruction alu" {
    const inst = Instruction.alu(.{ .@"or" = 0x08 }, 0xFF);
    try testing.expectEqual(@as(u8, 0x08), inst.code);
    try testing.expectEqual(@as(u32, 0xFF), inst.k);
}

test "cBPF instruction jmp" {
    const inst = Instruction.jmp(.{ .jeq = 0x10 }, 10, 0, 0);
    try testing.expectEqual(@as(u8, 0x10), inst.code);
    try testing.expectEqual(@as(u8, 10), inst.jt);
}
