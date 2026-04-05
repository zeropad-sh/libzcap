const std = @import("std");
const testing = std.testing;
const cBPF = @import("libzcap").cBPF;
const Instruction = cBPF.Instruction;

test "cBPF instruction ld" {
    const inst = Instruction.ld(.w, .abs, 12);
    try testing.expectEqual(@as(u16, 0x0020), inst.code);
    try testing.expectEqual(@as(u32, 12), inst.k);
}

test "cBPF instruction ldx" {
    const inst = Instruction.ldx(.w, .mem, 0);
    try testing.expectEqual(@as(u16, 0x0061), inst.code);
}

test "cBPF instruction ret" {
    const inst = Instruction.ret(65535);
    try testing.expectEqual(@as(u16, 0x0006), inst.code);
    try testing.expectEqual(@as(u32, 65535), inst.k);
}

test "cBPF instruction alu" {
    const inst = Instruction.alu(.@"or", 0xFF);
    try testing.expectEqual(@as(u16, 0x0040 | 0x0004), inst.code);
    try testing.expectEqual(@as(u32, 0xFF), inst.k);
}

test "cBPF instruction jmp" {
    const inst = Instruction.jmp(.jeq, 10, 0, 0);
    try testing.expectEqual(@as(u16, 0x0015), inst.code);
    try testing.expectEqual(@as(u8, 10), inst.jt);
}
