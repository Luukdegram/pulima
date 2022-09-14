//! Represents a Wasm binary file
const File = @This();

const std = @import("std");
const Module = @import("Module.zig");

module: Module,
handle: std.fs.File,
path: []const u8,
content: []const u8,

pub fn deinit(file: *File, gpa: std.mem.Allocator) void {
    file.module.deinit(gpa);
    gpa.free(file.content);
    file.handle.close();
    file.* = undefined;
}

/// From a given path, opens the file and parses the Wasm module
pub fn open(gpa: std.mem.Allocator, path: []const u8) !File {
    const file = try std.fs.cwd().openFile(path, .{});
    errdefer file.close();

    const content = file.readToEndAlloc(gpa, std.math.maxInt(u32)); // wasm32 binaries couldn't be larger than this
    errdefer gpa.free(content);
    const module = try Module.parse(gpa, content);

    return File{
        .module = module,
        .content = content,
        .path = path,
        .handle = file,
    };
}
