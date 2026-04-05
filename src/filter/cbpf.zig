pub const InstructionClass = enum(u16) {
    ld = 0x0000,
    ldx = 0x0001,
    alu = 0x0004,
    jmp = 0x0005,
    ret = 0x0006,
    misc = 0x0007,
};

pub const InstructionSize = enum(u16) {
    w = 0x0000,
    h = 0x0008,
    b = 0x0010,
    dw = 0x0018,
};

pub const InstructionMode = enum(u16) {
    imp = 0x0000,
    mem = 0x0060,
    abs = 0x0020,
    ind = 0x0040,
    len = 0x0080,
    msh = 0x00a0,
};

pub const AluOp = enum(u16) {
    add = 0x0000,
    sub = 0x0010,
    mul = 0x0020,
    div = 0x0030,
    @"or" = 0x0040,
    @"and" = 0x0050,
    lsh = 0x0060,
    rsh = 0x0070,
    neg = 0x0080,
    mod = 0x0090,
    xor = 0x00a0,
    jmp_reserved = 0x00b0,
};

pub const JumpOp = enum(u16) {
    jeq = 0x0010,
    jgt = 0x0020,
    jge = 0x0030,
    jset = 0x0040,
};

pub const Instruction = extern struct {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,

    pub fn ld(size: InstructionSize, mode: InstructionMode, offset: u32) Instruction {
        return .{
            .code = @intFromEnum(InstructionClass.ld) | @intFromEnum(size) | @intFromEnum(mode),
            .jt = 0,
            .jf = 0,
            .k = offset,
        };
    }

    pub fn ldx(size: InstructionSize, mode: InstructionMode, offset: u32) Instruction {
        return .{
            .code = @intFromEnum(InstructionClass.ldx) | @intFromEnum(size) | @intFromEnum(mode),
            .jt = 0,
            .jf = 0,
            .k = offset,
        };
    }

    pub fn alu(op: AluOp, k: u32) Instruction {
        return .{
            .code = @intFromEnum(InstructionClass.alu) | @intFromEnum(op),
            .jt = 0,
            .jf = 0,
            .k = k,
        };
    }

    pub fn jmp(op: JumpOp, jt: u8, jf: u8, k: u32) Instruction {
        return .{
            .code = @intFromEnum(InstructionClass.jmp) | @intFromEnum(op),
            .jt = jt,
            .jf = jf,
            .k = k,
        };
    }

    pub fn ret(k: u32) Instruction {
        return .{
            .code = @intFromEnum(InstructionClass.ret),
            .jt = 0,
            .jf = 0,
            .k = k,
        };
    }
};

pub const Program = struct {
    instructions: []Instruction,
    len: usize,

    pub fn toBytes(self: Program) []const u8 {
        @setRuntimeSafety(false);
        const size = self.len * @sizeOf(Instruction);
        return @as([*]const u8, @ptrFromInt(@intFromPtr(self.instructions.ptr)))[0..size];
    }
};
