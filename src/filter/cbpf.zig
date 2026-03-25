pub const Opcode = enum(u8) {
    ld = 0x00,
    ldx = 0x01,
    st = 0x02,
    stx = 0x03,
    add = 0x04,
    sub = 0x05,
    mul = 0x06,
    div = 0x07,
    @"or" = 0x08,
    @"and" = 0x09,
    lsh = 0x0a,
    rsh = 0x0b,
    neg = 0x0c,
    mod = 0x0d,
    xor = 0x0e,
    jeq,
    jgt,
    jge,
    jset,
};

pub const Size = enum(u8) {
    w = 0x00,
    h = 0x08,
    b = 0x10,
    dw = 0x18,
};

pub const Mode = enum(u8) {
    imp = 0x00,
    mem = 0x01,
    abs = 0x02,
    ind = 0x03,
    len = 0x40,
    msh = 0x60,
};

pub const Instruction = struct {
    code: u8,
    jt: u8,
    jf: u8,
    k: u32,

    pub fn ld(size: Size, mode: Mode, offset: u32) Instruction {
        return .{
            .code = @intFromEnum(Opcode.ld) | @intFromEnum(size) | @intFromEnum(mode),
            .jt = 0,
            .jf = 0,
            .k = offset,
        };
    }

    pub fn ldx(size: Size, mode: Mode, offset: u32) Instruction {
        return .{
            .code = @intFromEnum(Opcode.ldx) | @intFromEnum(size) | @intFromEnum(mode),
            .jt = 0,
            .jf = 0,
            .k = offset,
        };
    }

    pub fn alu(op: Opcode, k: u32) Instruction {
        return .{
            .code = @intFromEnum(op),
            .jt = 0,
            .jf = 0,
            .k = k,
        };
    }

    pub fn jmp(op: Opcode, jt: u8, jf: u8, k: u32) Instruction {
        return .{
            .code = @intFromEnum(op),
            .jt = jt,
            .jf = jf,
            .k = k,
        };
    }

    pub fn ret(k: u32) Instruction {
        return .{
            .code = @intFromEnum(Opcode.ld) | @intFromEnum(Size.w) | @intFromEnum(Mode.imp),
            .jt = 0,
            .jf = 0,
            .k = k,
        };
    }

    pub fn emit(self: Instruction, writer: anytype) !void {
        try writer.writeInt(u16, 0, .little);
        try writer.writeInt(u16, self.code, .little);
        try writer.writeInt(u32, self.k, .little);
        try writer.writeInt(u8, self.jt, .little);
        try writer.writeInt(u8, self.jf, .little);
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
