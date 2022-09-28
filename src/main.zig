const std = @import("std");
const File = @import("File.zig");
const signature = @import("signature.zig");
const keys = @import("key.zig");
const mem = std.mem;

const usage =
    \\USAGE:
    \\    {s} [SUBCOMMAND] file [FLAGS]
    \\
    \\FLAGS:
    \\    -h, --help            Prints help information
    \\    -o [path]             Output path of the signed binary
    \\    -v                    Verbose output
    \\    -s [path]             The key file to sign the binary module with, or to write the secret key component to
    \\    -p [path]             The public key to verify a signature for, or to write the public key component to
    \\SUBCOMMANDS:
    \\    sign                  Signs a Wasm binary using a private key
    \\    verify                Verifies the signature of a Wasm binary from a public key
    \\    keygen                Generates a new secret and public key pair
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
    keygen,
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
    var secret_path: ?[]const u8 = null;
    var public_path: ?[]const u8 = null;

    var arg_i: usize = 1;
    while (arg_i < args.len) : (arg_i += 1) {
        const arg = args[arg_i];
        if (mem.eql(u8, arg, "sign")) {
            sub_command = .sign;
            continue;
        } else if (mem.eql(u8, arg, "verify")) {
            sub_command = .verify;
            continue;
        } else if (mem.eql(u8, arg, "keygen")) {
            sub_command = .keygen;
            continue;
        } else if (mem.eql(u8, arg, "-o")) {
            arg_i += 1;
            output_path = getNextArg(args, arg_i, "Missing path after flag '-0'.");
            continue;
        } else if (mem.eql(u8, arg, "-s")) {
            arg_i += 1;
            secret_path = getNextArg(args, arg_i, "Missing secret key path after flag '-s'.");
            continue;
        } else if (mem.eql(u8, arg, "-p")) {
            arg_i += 1;
            public_path = getNextArg(args, arg_i, "Missing public key path after flag '-p'.");
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

    if (positionals.items.len == 0 and command != .keygen) {
        printErrorAndExit("Missing input file");
    }

    switch (command) {
        .sign => {
            const result_path = output_path orelse printErrorAndExit("Missing output path.");

            const path = secret_path orelse printErrorAndExit("Missing secret key argument.");
            const key_file = std.fs.cwd().openFile(path, .{}) catch |err| switch (err) {
                error.FileNotFound => printErrorAndExit("Public key could not be found at given path."),
                else => printErrorAndExit("Could not open public key file."),
            };
            defer key_file.close();
            var key_buf: [65]u8 = undefined; // type + public + secret key max length
            const len = try key_file.readAll(&key_buf);
            const key_pair = keys.KeyPair.deserialize(key_buf[0..len]) catch {
                printErrorAndExit("secret key could not be deserialised.");
            };
            var signature_data = std.ArrayList(u8).init(gpa);
            defer signature_data.deinit();

            var wasm_binary = try File.open(gpa, positionals.items[0]);
            defer wasm_binary.deinit(gpa);

            signature.sign(gpa, key_pair.signer(), &wasm_binary.module, signature_data.writer()) catch {
                printErrorAndExit("Could not sign the Wasm module.");
            };

            const result_binary = try std.fs.cwd().createFile(result_path, .{});
            defer result_binary.close();

            const magic: []const u8 = (&std.wasm.magic ++ &std.wasm.version);
            var io_vec = [_]std.os.iovec_const{
                .{ .iov_base = magic.ptr, .iov_len = magic.len },
                .{ .iov_base = signature_data.items.ptr, .iov_len = signature_data.items.len },
                .{ .iov_base = wasm_binary.module.raw_data, .iov_len = wasm_binary.module.size },
            };
            try result_binary.writevAll(&io_vec);
        },
        .verify => {
            const path = public_path orelse printErrorAndExit("Missing public key argument.");
            const key_file = std.fs.cwd().openFile(path, .{}) catch |err| switch (err) {
                error.FileNotFound => printErrorAndExit("Public key could not be found at given path."),
                else => printErrorAndExit("Could not open public key file."),
            };
            defer key_file.close();
            var key_buf: [65]u8 = undefined; // type + public + secret key max length
            const len = try key_file.readAll(&key_buf);
            const public_key = try keys.PublicKey.deserialize(key_buf[0..len]);

            var wasm_binary = try File.open(gpa, positionals.items[0]);
            defer wasm_binary.deinit(gpa);

            signature.verify(public_key.verifier(), &wasm_binary.module) catch {
                printErrorAndExit("Could not verify signature.");
            };
        },
        .keygen => {
            const secret = secret_path orelse printErrorAndExit("Missing secret key path.");
            const public = public_path orelse printErrorAndExit("Missing public key path.");
            keys.generateKeyPair(secret, public) catch {
                printErrorAndExit("Failed generating a new key-pair, please try again...");
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
