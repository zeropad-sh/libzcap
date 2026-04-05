const std = @import("std");
const Instruction = @import("cbpf.zig").Instruction;

const ETH_P_IP: u16 = 0x0800;
const ETH_P_ARP: u16 = 0x0806;
const IP_PROTO_TCP: u8 = 6;
const IP_PROTO_UDP: u8 = 17;
const IP_PROTO_ICMP: u8 = 1;
const RET_ALL: u32 = 0xffff_ffff;
const RET_NONE: u32 = 0x0000_0000;

const ParseError = error{
    FilterTooComplex,
};

const Proto = enum {
    any,
    ip,
    arp,
    tcp,
    udp,
    icmp,
};

const ParsedFilter = struct {
    proto: Proto,
    port: ?u16,
};

fn isWhitespace(c: u8) bool {
    return c == ' ' or c == '\t' or c == '\n' or c == '\r';
}

fn skipWhitespace(text: []const u8, idx: *usize) void {
    while (idx.* < text.len and isWhitespace(text[idx.*])) {
        idx.* += 1;
    }
}

fn startsWord(text: []const u8, idx: usize, word: []const u8) bool {
    if (idx >= text.len) return false;
    if (!std.mem.startsWith(u8, text[idx..], word)) return false;
    const end = idx + word.len;
    if (end == text.len) return true;
    return isWhitespace(text[end]);
}

fn parseU16(text: []const u8, idx: *usize) ?u16 {
    if (idx.* >= text.len or text[idx.*] < '0' or text[idx.*] > '9') return null;
    var end = idx.*;
    while (end < text.len and text[end] >= '0' and text[end] <= '9') {
        end += 1;
    }
    const value = std.fmt.parseInt(u16, text[idx.*..end], 10) catch return null;
    idx.* = end;
    return value;
}

fn parseExprText(comptime expr: []const u8) ParsedFilter {
    var idx: usize = 0;
    var proto: Proto = .any;
    var port: ?u16 = null;

    while (idx < expr.len) {
        skipWhitespace(expr, &idx);
        if (idx >= expr.len) break;

        if (startsWord(expr, idx, "tcp")) {
            idx += 3;
            if (proto != .any) @compileError("filter compiler does not support mixed protocol terms");
            proto = .tcp;
            continue;
        }

        if (startsWord(expr, idx, "udp")) {
            idx += 3;
            if (proto != .any) @compileError("filter compiler does not support mixed protocol terms");
            proto = .udp;
            continue;
        }

        if (startsWord(expr, idx, "icmp")) {
            idx += 4;
            if (proto != .any) @compileError("filter compiler does not support mixed protocol terms");
            proto = .icmp;
            continue;
        }

        if (startsWord(expr, idx, "arp")) {
            idx += 3;
            if (proto != .any) @compileError("filter compiler does not support mixed protocol terms");
            proto = .arp;
            continue;
        }

        if (startsWord(expr, idx, "ip")) {
            idx += 2;
            if (proto != .any) @compileError("filter compiler does not support mixed protocol terms");
            proto = .ip;
            continue;
        }

        if (startsWord(expr, idx, "port")) {
            idx += 4;
            skipWhitespace(expr, &idx);
            const parsed = parseU16(expr, &idx) orelse {
                @compileError("unsupported filter syntax: invalid port");
            };
            if (port != null) {
                @compileError("filter compiler does not support multiple ports");
            }
            port = parsed;
            continue;
        }

        @compileError("unsupported filter token");
    }

    return .{ .proto = proto, .port = port };
}

fn parseExprRuntime(expr: []const u8) !ParsedFilter {
    var idx: usize = 0;
    var proto: Proto = .any;
    var port: ?u16 = null;

    while (idx < expr.len) {
        skipWhitespace(expr, &idx);
        if (idx >= expr.len) break;

        if (startsWord(expr, idx, "tcp")) {
            idx += 3;
            if (proto != .any) return ParseError.FilterTooComplex;
            proto = .tcp;
            continue;
        }

        if (startsWord(expr, idx, "udp")) {
            idx += 3;
            if (proto != .any) return ParseError.FilterTooComplex;
            proto = .udp;
            continue;
        }

        if (startsWord(expr, idx, "icmp")) {
            idx += 4;
            if (proto != .any) return ParseError.FilterTooComplex;
            proto = .icmp;
            continue;
        }

        if (startsWord(expr, idx, "arp")) {
            idx += 3;
            if (proto != .any) return ParseError.FilterTooComplex;
            proto = .arp;
            continue;
        }

        if (startsWord(expr, idx, "ip")) {
            idx += 2;
            if (proto != .any) return ParseError.FilterTooComplex;
            proto = .ip;
            continue;
        }

        if (startsWord(expr, idx, "port")) {
            idx += 4;
            skipWhitespace(expr, &idx);
            const parsed = parseU16(expr, &idx) orelse return ParseError.FilterTooComplex;
            if (port != null) return ParseError.FilterTooComplex;
            port = parsed;
            continue;
        }

        return ParseError.FilterTooComplex;
    }

    return .{ .proto = proto, .port = port };
}

fn addInstr(list: []Instruction, idx: *usize, inst: Instruction) !void {
    if (idx.* >= list.len) return ParseError.FilterTooComplex;
    list[idx.*] = inst;
    idx.* += 1;
}

fn emitProgramFromFilter(list: []Instruction, parsed: ParsedFilter) !usize {
    var idx: usize = 0;

    switch (parsed.proto) {
        .any => {
            if (parsed.port != null) {
                return ParseError.FilterTooComplex;
            }
            try addInstr(list, &idx, Instruction.ret(RET_ALL));
            return idx;
        },
        .ip => {
            try addInstr(list, &idx, Instruction.ld(.h, .abs, 12));
            try addInstr(list, &idx, Instruction.jmp(.jeq, 0, 1, ETH_P_IP));
            try addInstr(list, &idx, Instruction.ret(RET_ALL));
            try addInstr(list, &idx, Instruction.ret(RET_NONE));
            return idx;
        },
        .arp => {
            try addInstr(list, &idx, Instruction.ld(.h, .abs, 12));
            try addInstr(list, &idx, Instruction.jmp(.jeq, 0, 1, ETH_P_ARP));
            try addInstr(list, &idx, Instruction.ret(RET_ALL));
            try addInstr(list, &idx, Instruction.ret(RET_NONE));
            return idx;
        },
        .tcp, .udp, .icmp => {},
    }

    const proto_byte: u8 = switch (parsed.proto) {
        .tcp => IP_PROTO_TCP,
        .udp => IP_PROTO_UDP,
        .icmp => IP_PROTO_ICMP,
        else => unreachable,
    };

    if (parsed.port != null and (parsed.proto == .ip or parsed.proto == .arp)) {
        return ParseError.FilterTooComplex;
    }

    const has_port_filter = parsed.port != null;
    try addInstr(list, &idx, Instruction.ld(.h, .abs, 12));
    try addInstr(list, &idx, Instruction.jmp(.jeq, 0, if (has_port_filter) 7 else 3, ETH_P_IP));
    try addInstr(list, &idx, Instruction.ld(.b, .abs, 23));
    try addInstr(list, &idx, Instruction.jmp(.jeq, 0, if (has_port_filter) 5 else 1, proto_byte));
    if (parsed.port) |raw_port| {
        try addInstr(list, &idx, Instruction.ld(.h, .abs, 34));
        try addInstr(list, &idx, Instruction.jmp(.jeq, 2, 1, raw_port));
        try addInstr(list, &idx, Instruction.ld(.h, .abs, 36));
        try addInstr(list, &idx, Instruction.jmp(.jeq, 0, 1, raw_port));
        try addInstr(list, &idx, Instruction.ret(RET_ALL));
        try addInstr(list, &idx, Instruction.ret(RET_NONE));
        return idx;
    }

    try addInstr(list, &idx, Instruction.ret(RET_ALL));
    try addInstr(list, &idx, Instruction.ret(RET_NONE));
    return idx;
}

fn emitProgramFromFilterComptime(parsed: ParsedFilter) []const Instruction {
    @setEvalBranchQuota(10000);
    var prog: [64]Instruction = undefined;
    const len = emitProgramFromFilter(&prog, parsed) catch {
        @compileError("filter compiler does not support complex expression");
    };
    return prog[0..len];
}

pub fn compile(comptime expr: []const u8) []const Instruction {
    return emitProgramFromFilterComptime(parseExprText(expr));
}

pub fn compileRuntime(alloc: std.mem.Allocator, expr: []const u8) ![]Instruction {
    const parsed = parseExprRuntime(expr) catch |err| return err;

    var prog = try alloc.alloc(Instruction, 64);
    errdefer alloc.free(prog);
    const len = try emitProgramFromFilter(prog, parsed);
    return prog[0..len];
}
