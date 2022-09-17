const std = @import("std");
const File = @import("File.zig");
const signature = @import("signature.zig");
const mem = std.mem;

const usage =
    \\USAGE:
    \\    {s} [SUBCOMMAND] file [FLAGS]
    \\
    \\FLAGS:
    \\    -h, --help            Prints help information
    \\    -o [path]             Output path of the signed binary
    \\    -v                    Verbose output
    \\    -k                    The key file to sign or verify the binary with
    \\SUBCOMMANDS:
    \\    sign                  Signs a Wasm binary using a private key
    \\    verify                Verifies the signature of a Wasm binary from a public key
;

pub fn log(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.EnumLiteral),
    comptime format: []const u8,
    args: anytype,
) void {
    _ = scope; // we overwrite given scope
    if (!verbose_output) return;
    std.log.defaultLog(level, .wasmsign, format, args);
}

var verbose_output: bool = false;

const SubCommand = enum {
    sign,
    verify,
};

pub fn main() !void {
    var gpa_allocator = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (@import("builtin").mode == .Debug) {
        _ = gpa_allocator.deinit();
    };
    const gpa = gpa_allocator.allocator();
    const args = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, args);

    var positionals = try std.ArrayList([]const u8).initCapacity(gpa, args.len);
    defer positionals.deinit();

    var sub_command: ?SubCommand = null;
    var output_path: ?[]const u8 = null;
    var key_path: ?[]const u8 = null;

    var arg_i: usize = 1;
    while (arg_i < args.len) : (arg_i += 1) {
        const arg = args[arg_i];
        if (mem.eql(u8, arg, "sign")) {
            sub_command = .sign;
            continue;
        } else if (mem.eql(u8, arg, "verify")) {
            sub_command = .verify;
            continue;
        } else if (mem.eql(u8, arg, "-o")) {
            arg_i += 1;
            output_path = getNextArg(args, arg_i, "Missing path after flag '-0'.");
            continue;
        } else if (mem.eql(u8, arg, "-k")) {
            arg_i += 1;
            key_path = getNextArg(args, arg_i, "Missing key path after flag '-k'.");
            continue;
        } else if (mem.eql(u8, arg, "-v")) {
            verbose_output = true;
            continue;
        } else if (mem.eql(u8, arg, "-h") or mem.eql(u8, arg, "--help")) {
            printUsageAndExit(args[0]);
        }

        positionals.appendAssumeCapacity(mem.sliceTo(arg, 0));
    }

    const command = sub_command orelse {
        printErrorAndExit("Missing subcommand");
    };

    if (positionals.items.len == 0) {
        printErrorAndExit("Missing input file");
    }

    switch (command) {
        .sign => {
            const output = output_path orelse {
                printErrorAndExit("Missing output path.");
            };
            _ = output; // TODO
        },
        .verify => {
            var wasm_binary = try File.open(gpa, positionals.items[0]);
            defer wasm_binary.deinit(gpa);

            signature.verify("", &wasm_binary.module) catch |err| switch (err) {
                // TODO: Nice error note per error
                else => |e| return e,
            };
        },
    }
}

pub fn printUsageAndExit(self_exe_path: [:0]const u8) noreturn {
    const std_out = std.io.getStdOut();
    std_out.writer().print(usage, .{self_exe_path}) catch {};
    std_out.writeAll("\n") catch {};
    std.os.exit(0);
}

pub fn printErrorAndExit(message: []const u8) noreturn {
    const std_err = std.io.getStdErr();
    std_err.writeAll(message) catch {};
    std_err.writeAll("\n") catch {};
    std.os.exit(1);
}

pub fn getNextArg(args: [][:0]u8, index: usize, message: []const u8) []const u8 {
    if (index >= args.len) {
        printErrorAndExit(message);
    }
    return mem.sliceTo(args[index], 0);
}
