const Instruction = @import("cbpf.zig").Instruction;
const std = @import("std");

pub fn compile(comptime expr: []const u8) []const Instruction {
    return comptime compileImpl(expr);
}

fn compileImpl(comptime expr: []const u8) []const Instruction {
    @setEvalBranchQuota(10000);
    var prog: [64]Instruction = undefined;
    var len: usize = 0;

    const tokens = tokenize(expr);
    inline for (tokens) |tok| {
        if (len >= prog.len) @compileError("filter too complex");
        switch (tok) {
            .tcp => prog[len] = Instruction.ld(.w, .abs, 9),
            .udp => prog[len] = Instruction.ld(.w, .abs, 9),
            else => {},
        }
        len += 1;
    }

    prog[len] = Instruction.ret(@intCast(prog.len));
    len += 1;

    return prog[0..len];
}

pub fn compileRuntime(alloc: std.mem.Allocator, expr: []const u8) ![]Instruction {
    var prog = try alloc.alloc(Instruction, 64);
    errdefer alloc.free(prog);
    var len: usize = 0;

    const tokens = tokenizeRuntime(expr);
    for (tokens) |tok| {
        if (len >= prog.len) return error.FilterTooComplex;
        switch (tok) {
            .tcp => prog[len] = Instruction.ld(.w, .abs, 9),
            .udp => prog[len] = Instruction.ld(.w, .abs, 9),
            else => continue,
        }
        len += 1;
    }

    prog[len] = Instruction.ret(@intCast(len));
    len += 1;

    return prog[0..len];
}

const Token = union(enum) {
    tcp,
    udp,
    icmp,
    arp,
    port: u16,
};

fn tokenize(comptime expr: []const u8) []const Token {
    @setEvalBranchQuota(10000);
    var tokens: [32]Token = undefined;
    var count: usize = 0;

    comptime {
        var remaining = expr;
        while (remaining.len > 0) {
            while (remaining.len > 0 and remaining[0] == ' ') remaining = remaining[1..];
            if (remaining.len == 0) break;

            if (std.mem.startsWith(u8, remaining, "tcp")) {
                tokens[count] = .tcp;
                remaining = remaining[3..];
            } else if (std.mem.startsWith(u8, remaining, "udp")) {
                tokens[count] = .udp;
                remaining = remaining[3..];
            } else if (std.mem.startsWith(u8, remaining, "icmp")) {
                tokens[count] = .icmp;
                remaining = remaining[4..];
            } else if (std.mem.startsWith(u8, remaining, "arp")) {
                tokens[count] = .arp;
                remaining = remaining[3..];
            } else {
                break;
            }
            count += 1;
        }
    }

    return tokens[0..count];
}

fn tokenizeRuntime(expr: []const u8) []Token {
    var tokens: [32]Token = undefined;
    var count: usize = 0;

    var remaining = expr;
    while (remaining.len > 0) {
        while (remaining.len > 0 and remaining[0] == ' ') remaining = remaining[1..];
        if (remaining.len == 0) break;

        if (std.mem.startsWith(u8, remaining, "tcp")) {
            tokens[count] = .tcp;
            remaining = remaining[3..];
        } else if (std.mem.startsWith(u8, remaining, "udp")) {
            tokens[count] = .udp;
            remaining = remaining[3..];
        } else if (std.mem.startsWith(u8, remaining, "icmp")) {
            tokens[count] = .icmp;
            remaining = remaining[4..];
        } else if (std.mem.startsWith(u8, remaining, "arp")) {
            tokens[count] = .arp;
            remaining = remaining[3..];
        } else {
            break;
        }
        count += 1;
    }

    return tokens[0..count];
}
