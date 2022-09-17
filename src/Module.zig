//! Represents a Wasm module and its sections
//! as defined by the official Wasm specification:
//! https://webassembly.github.io/spec/core/syntax/modules.html
const Module = @This();
const std = @import("std");
const leb = std.leb;
const mem = std.mem;

/// Pointer to the raw data of the Wasm module
raw_data: [*]const u8,
/// Module size in bytes, excludes magic bytes
/// and the binary version.
size: u32,
types: SectionHeader,
functions: SectionHeader,
tables: SectionHeader,
imports: SectionHeader,
memories: SectionHeader,
globals: SectionHeader,
exports: SectionHeader,
start: u32,
elements: SectionHeader,
code: SectionHeader,
data: SectionHeader,
custom_sections: []const CustomSectionHeader,

/// Possible errors when parsing the Wasm module
pub const ParseError = error{
    InvalidMagicBytes,
    InvalidModuleVersion,
    UnknownSectionNumber,
    OutOfMemory,
    EndOfStream,
    /// leb128 encoded integer doesn't fit into given size
    Overflow,
};

/// Represents the meta data of an entire section.
/// Using the meta data, its contents can be found and parsed
/// to gain access to its data representation.
pub const SectionHeader = struct {
    /// Size of the section in bytes
    size: u32 = 0,
    /// The amount of entries within the section
    entries: u32 = 0,
    /// Offset in the binary from where the section starts,
    /// excluding the 'entries' field.
    offset: u32 = 0,
    /// The order in which the section is found in the Module.
    index: u32 = 0,

    /// Returns the raw bytes of the entire section
    pub fn raw(header: SectionHeader, module: *const Module) []const u8 {
        return module.data[header.offset..][0..header.size];
    }
};

pub const CustomSectionHeader = struct {
    /// The name of the custom section
    name: []const u8,
    /// Pointer to the data of a custom section
    raw_data: [*]const u8,
    /// The size of the custom section in bytes, excluding the name field.
    size: u32,
    /// The order in which the custom section is found in the Wasm module.
    index: u32,

    /// Returns the data of the custom section as a slice
    pub fn data(header: CustomSectionHeader) []const u8 {
        return header.raw_data[0..header.size];
    }
};

/// Frees all resources of the `Module`.
/// Accessing the `Module` after calling deinit is illegal behavior.
pub fn deinit(self: *Module, gpa: std.mem.Allocator) void {
    gpa.free(self.custom_sections);
    self.* = undefined;
}

/// Finds a custom section from a given name.
/// When the custom section does not exist, returns null.
pub fn getNamed(module: *const Module, name: []const u8) ?CustomSectionHeader {
    for (module.custom_sections) |section| {
        if (mem.eql(u8, section.name, name)) {
            return section;
        }
    }
    return null;
}

/// Represents an empty unparsed Module.
const empty: Module = .{
    .raw_data = undefined,
    .size = 0,
    .types = .{},
    .functions = .{},
    .imports = .{},
    .tables = .{},
    .memories = .{},
    .globals = .{},
    .exports = .{},
    .start = 0,
    .elements = .{},
    .code = .{},
    .data = .{},
    .custom_sections = &[_]CustomSectionHeader{},
};

/// Accepts a Wasm binary's raw bytes and parses it on validity.
/// Stores meta data about the module rather than parsing it as individual
/// objects. This makes parsing quick, and if specific data is retrieved,
/// it can be parsed by using this metadata such as offsets.
pub fn parse(gpa: std.mem.Allocator, data: []const u8) ParseError!Module {
    if (!mem.eql(u8, data[0..4], &std.wasm.magic)) {
        return error.InvalidMagicBytes;
    }
    if (!mem.eql(u8, data[4..8], &std.wasm.version)) {
        return error.InvalidModuleVersion;
    }

    var module = empty;
    module.size = @intCast(u32, data.len - 8);

    var custom_sections = std.ArrayList(CustomSectionHeader).init(gpa);
    defer custom_sections.deinit();

    var fbs = std.io.fixedBufferStream(data);
    fbs.pos = 8; // we already verified the first 8 bytes
    const reader = fbs.reader();

    var current_section_index: u32 = 0;
    while (reader.readByte()) |byte| : (current_section_index += 1) {
        const section = std.meta.intToEnum(std.wasm.Section, byte) catch {
            return error.UnknownSectionNumber;
        };
        const section_size = try leb.readULEB128(u32, reader);
        const current_read_position = fbs.pos;
        switch (section) {
            .custom => {
                const name_length = try leb.readULEB128(u32, reader);
                const name = data[fbs.pos..][0..name_length];
                fbs.pos += name_length;

                try custom_sections.append(.{
                    .name = name,
                    .raw_data = data[fbs.pos..].ptr,
                    .size = @intCast(u32, section_size - (fbs.pos - current_read_position)),
                    .index = current_section_index,
                });
                fbs.pos = current_read_position + section_size;
            },
            .start => {
                module.start = try leb.readULEB128(u32, reader);
            },
            .type,
            .function,
            .global,
            .import,
            .table,
            .@"export",
            .memory,
            .element,
            .code,
            .data,
            => {
                const entries = try leb.readULEB128(u32, reader);
                const header: SectionHeader = .{
                    .index = current_section_index,
                    .offset = @intCast(u32, fbs.pos),
                    .entries = entries,
                    .size = @intCast(u32, section_size - (fbs.pos - current_read_position)),
                };

                switch (section) {
                    .type => module.types = header,
                    .function => module.functions = header,
                    .global => module.globals = header,
                    .import => module.imports = header,
                    .table => module.tables = header,
                    .@"export" => module.exports = header,
                    .memory => module.memories = header,
                    .element => module.elements = header,
                    .code => module.code = header,
                    .data => module.data = header,
                    else => unreachable,
                }
                fbs.pos = current_read_position + section_size;
            },
            else => fbs.pos += section_size, // skip section
        }
    } else |err| switch (err) {
        error.EndOfStream => {}, // finished reading file, stop reading.
        else => unreachable,
    }
    module.custom_sections = custom_sections.toOwnedSlice();
    return module;
}
