//! Implements the signing and verification
//! of the signature section of Wasm binaries.
//! The implementation follows the design proposal as
//! specified by the tool-convention found at:
//! https://github.com/WebAssembly/tool-conventions/blob/main/Signatures.md
const std = @import("std");
const Module = @import("Module.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;
const Ed25519 = std.crypto.sign.Ed25519;
const leb = std.leb;

/// Signs the given `Module` by constructing a signature section.
/// The new constructed signature section will be written using
/// the given writer, leaving the given `module` in-tact.
pub fn sign(gpa: std.mem.Allocator, signer: anytype, module: *const Module, writer: anytype) !void {
    std.debug.assert(module.getNamed("signature") == null); // module is already signed
    std.log.debug("no signature found, signing module...", .{});
    var hash = Sha256.init(.{});
    var hash_out: [Sha256.digest_length]u8 = undefined;
    hash.update(module.raw_data[0..module.size]);
    hash.final(&hash_out);
    std.log.debug("finished hashing module", .{});

    const header: SignatureHeader = .{
        .version = spec_version,
        .hash = .sha256,
        .content_type = default_context_type,
        .signed_hash_count = 1,
    };

    var section_bytes = std.ArrayList(u8).init(gpa);
    defer section_bytes.deinit();

    var signature_buf: [SignedHashes.max_signatures * 64]u8 = undefined;
    const message = Message.init(spec_version, header.hash, default_context_type, &hash_out);
    const signature_length = try signer.sign(message.data(), &signature_buf);
    std.log.debug("successfully signed the module", .{});
    std.log.debug("serialising signature section...", .{});

    const signature: Signature = .{
        .key_id_len = 0,
        .key_id = &[_]u8{},
        .signature = signature_buf[0..signature_length].ptr,
        .len = @intCast(u32, signature_length),
    };

    const signed_hashes: SignedHashes = .{
        .hashes_count = 1,
        .hashes = &hash_out,
        .hash_len = header.hash.len(),
        .signature_count = 1,
        .signatures = undefined,
        .signature_bytes_len = 0,
    };

    try header.serialize(section_bytes.writer());
    std.log.debug("   serialised the header. Spec version: {d}, using hash: {s}, with content type: 0x{x}", .{
        header.version,
        @tagName(header.hash),
        header.content_type,
    });

    const current_offset = @intCast(u32, section_bytes.items.len);
    try signed_hashes.serialize(section_bytes.writer());
    std.log.debug("   serialised the signed hashes section", .{});
    try signature.serialize(section_bytes.writer());
    std.log.debug("   serialised the signatures", .{});
    const new_offset = @intCast(u32, section_bytes.items.len);
    var buf: [5]u8 = undefined;
    var size_state: LebState = .{ .count = 0 };
    size_state.write(u32, &buf, new_offset - current_offset);
    try section_bytes.insertSlice(current_offset, buf[0..size_state.count]);

    try writer.writeByte(@enumToInt(std.wasm.Section.custom));
    const section_name = "signature";
    const name_len_leb = LebState.lebSize(@intCast(u32, section_name.len));
    const total_len = @intCast(u32, section_name.len + name_len_leb + section_bytes.items.len);
    try leb.writeULEB128(writer, total_len);
    try leb.writeULEB128(writer, @intCast(u32, section_name.len));
    try writer.writeAll(section_name);
    try writer.writeAll(section_bytes.items);
    std.log.debug("finished constructing the \"signature\" section", .{});
}

/// Verifies the `Module`'s signature using the given `verifier`.
/// Ensures the Module contains a signature, of which its specification
/// version must match, and then verifies it.
/// Returns nothing on success, but fails with an error if the signature
/// does not match in any way.
pub fn verify(verifier: anytype, module: *const Module) !void {
    const signature_header = module.getNamed("signature") orelse {
        std.log.err("signature section missing", .{});
        return error.MissingSignature;
    };

    var leb_state: LebState = .{ .count = 0 };
    const signature_bytes = signature_header.data();
    const header = try SignatureHeader.deserialize(signature_bytes, &leb_state);
    if (header.version != 0x1) {
        std.log.err("expected signature version 1", .{});
        return error.UnsupportedVersion;
    }

    if (header.hash != .sha256) {
        std.log.err("expected sha256 as has function", .{});
        return error.UnsupportedHashFunction;
    }

    if (header.signed_hash_count > 1) {
        std.log.err("wasmsign currently only supports verifying the single module signature", .{});
        return error.UnsupportedSignedHashesCount;
    }

    std.log.debug("signature contains {d} signed hashes", .{header.signed_hash_count});
    std.log.debug("verifying hashes...", .{});

    var signature_index: u32 = 0;
    var bytes_ptr: usize = leb_state.count; // we already retrieved the signature header
    while (signature_index < header.signed_hash_count) : (signature_index += 1) {
        const raw_signature_bytes = signature_bytes[bytes_ptr..];
        var previous_state_count = leb_state.count;
        const signed_hashes = try SignedHashes.deserialize(raw_signature_bytes, header.hash.len(), &leb_state);
        std.log.debug("   hash count: {d}", .{signed_hashes.hashes_count});
        std.log.debug("   signatures: {d}", .{signed_hashes.signature_count});
        bytes_ptr += signed_hashes.size() + (leb_state.count - previous_state_count);
        const msg = Message.init(header.version, header.hash, header.content_type, signed_hashes.hash());

        var signature_it = signed_hashes.signatureIterator(&leb_state);
        var verified_hash_count: u32 = 0;
        while (try signature_it.next()) |signature| {
            if (!std.mem.eql(u8, signature.key(), verifier.identifier())) continue; // TODO
            std.log.debug("      verifying signature: {}", .{signature});
            verifier.verify(msg.data(), signature.asSlice()) catch continue;
            verified_hash_count += 1;
            std.log.debug("      signature verified successfully", .{});
        }

        if (verified_hash_count == 0) {
            std.log.err("No signature could be verified", .{});
            return error.NoValidSignatures;
        }

        // we have verified at least one hash was signed correctly for the given key
        // now we hash the data ourselves and ensure it matches a verified hash.
        var hasher = Sha256.init(.{});
        const module_start = signature_header.offset + signature_header.size - 8; // minus 8 for magic bytes + version
        hasher.update(module.raw_data[module_start..module.size]);
        var final_hash: [Sha256.digest_length]u8 = undefined;
        hasher.final(&final_hash);
        std.log.debug("      verifying at least one of the hashes matches", .{});

        var hash_matches = false;
        var hash_it = signed_hashes.hashIterator();
        while (hash_it.next()) |hash| {
            if (std.mem.eql(u8, hash, &final_hash)) {
                hash_matches = true;
            }
        }
        if (!hash_matches) {
            std.log.err("No matching hash was found", .{});
            return error.NoValidSignatures;
        }
        std.log.debug("      found matching hash", .{});
    }
    std.log.debug("module signature verified successfully", .{});
}

/// The maximum size the message can be that must be verified for its signature.
/// This size can be used to construct a buffer, large enough to construct the message,
/// without requiring any heap allocations.
const max_message_len = Hash.max_hash_length * SignedHashes.max_hashes + min_message_len;
/// The minimum size a message must be
const min_message_len = wasmsig.len + 3;
/// String part of message used to verify the signature
const wasmsig = "wasmsig";
/// Current supported spec version
pub const spec_version = 0x01;
/// Default context type, which allows to specify the context on what the signature
/// is being used for.
pub const default_context_type = 0x01;

/// Supported hashes by wasmsign
const Hash = enum(u8) {
    sha256 = 0x01,

    fn len(hash: Hash) u32 {
        switch (hash) {
            .sha256 => return Sha256.digest_length,
        }
    }

    const max_hash_length = 32;
};

/// Message that will be signed or used to verify a signature
/// This is essentially a little helper struct to easily construct
/// a message without having to manually setup up the initial array.
const Message = struct {
    buffer: [max_message_len]u8,
    len: usize,

    /// Constructs a new `Message` which fills the internal buffer in according
    /// to the tooling-convention, which can then be signed to generate a signature.
    fn init(version: u8, hash: Hash, content_type: u8, hashes: []const u8) Message {
        var message: Message = .{ .buffer = undefined, .len = 0 };
        std.mem.copy(u8, &message.buffer, wasmsig);
        message.buffer[wasmsig.len..][0..3].* = .{ version, @enumToInt(hash), content_type };
        std.mem.copy(u8, message.buffer[min_message_len..], hashes);
        message.len = min_message_len + hashes.len;
        return message;
    }

    /// Returns the message as a slice, using only the data that was filled.
    fn data(message: *const Message) []const u8 {
        return message.buffer[0..message.len];
    }
};

const SignatureHeader = struct {
    version: u8,
    hash: Hash,
    content_type: u8,
    signed_hash_count: u32,

    /// From the given slice of bytes, decodes it into a `SignatureHeader`.
    /// The leb-encoded fields will modify the internal state of the given `LebState`.
    fn deserialize(bytes: []const u8, state: *LebState) !SignatureHeader {
        return .{
            .version = try state.read(u7, bytes),
            .content_type = try state.read(u7, bytes[state.count..]),
            .hash = try std.meta.intToEnum(Hash, try state.read(u7, bytes[state.count..])),
            .signed_hash_count = try state.read(u32, bytes[state.count..]),
        };
    }

    /// Serializes the header of the signature section into its leb128-encoded form.
    fn serialize(header: SignatureHeader, writer: anytype) !void {
        try writer.writeByte(header.version);
        try writer.writeByte(@enumToInt(header.hash));
        try writer.writeByte(header.content_type);
        try leb.writeULEB128(writer, header.signed_hash_count);
    }
};

const SignedHashes = struct {
    hashes_count: u32,
    hashes: [*]const u8,
    hash_len: u32,
    signature_count: u32,
    signatures: [*]const u8,
    signature_bytes_len: u32,

    const max_hashes = 64;
    const max_signatures = 256;

    const SignatureIterator = struct {
        index: u32,
        max_count: u32,
        byte_index: usize,
        bytes_len: u32,
        bytes: [*]const u8,
        state: *LebState,

        /// Deserializes the next Signature. Returns null when end of iterator has been reached.
        fn next(it: *SignatureIterator) !?Signature {
            if (it.index == it.max_count) return null;
            var last_state = it.state.count;
            const signature = try Signature.deserialize(it.bytes[it.byte_index..it.bytes_len], it.state);
            it.byte_index += signature.size() + (it.state.count - last_state);
            it.index += 1;
            return signature;
        }
    };

    const HashIterator = struct {
        index: u32,
        max_count: u32,
        hash_len: u32,
        bytes: [*]const u8,

        /// Deserializes and returns the next hash. Returns null when end of iterator has been reached.
        fn next(it: *HashIterator) ?[]const u8 {
            if (it.index == it.max_count) return null;
            const start = it.index * it.hash_len;
            const hash_bytes = it.bytes[start .. start + it.hash_len];
            it.index += 1;
            return hash_bytes;
        }
    };

    /// Deserializes the raw bytes into a `SignedHashes`.
    fn deserialize(bytes: []const u8, hash_len: u32, state: *LebState) !SignedHashes {
        var prev_count = state.count;
        _ = try state.read(u32, bytes); // The length is not needed, this can simply be inferred...
        var offset = state.count - prev_count;
        const count = try state.read(u32, bytes[offset..]);
        offset = state.count - prev_count;
        prev_count = state.count;
        const hashes = bytes[offset..].ptr;
        const hashes_len = count * hash_len;
        offset += hashes_len;
        const sig_count = try state.read(u32, bytes[offset..]);
        if (sig_count > 1) return error.Unsupported;
        offset += state.count - prev_count;
        prev_count = state.count;
        const signature_length = try state.read(u32, bytes[offset..]);
        offset += state.count - prev_count;
        const signatures = bytes[offset..].ptr;

        return .{
            .hashes_count = count,
            .hashes = hashes,
            .hash_len = hash_len,
            .signature_count = sig_count,
            .signatures = signatures,
            .signature_bytes_len = signature_length,
        };
    }

    /// Deserialises a `SignedHashes` structure into its serialised-encoding.
    fn serialize(signed_hashes: *const SignedHashes, writer: anytype) !void {
        try leb.writeULEB128(writer, signed_hashes.hashes_count);
        try writer.writeAll(signed_hashes.hash());
        try leb.writeULEB128(writer, signed_hashes.signature_count);
        // signatures are serialised independently of this function
    }

    /// Returns all hashes concatenated as a single slice
    fn hash(signed_hashes: *const SignedHashes) []const u8 {
        return signed_hashes.hashes[0 .. signed_hashes.hash_len * signed_hashes.hashes_count];
    }

    /// Builds and returns an iterator for iterating all signatures
    fn signatureIterator(signed_hashes: *const SignedHashes, state: *LebState) SignatureIterator {
        return .{
            .index = 0,
            .max_count = signed_hashes.signature_count,
            .byte_index = 0,
            .bytes_len = signed_hashes.signature_bytes_len,
            .bytes = signed_hashes.signatures,
            .state = state,
        };
    }

    /// Builds and returns an iterator for iterating all signed hashes
    fn hashIterator(signed_hashes: *const SignedHashes) HashIterator {
        return .{
            .index = 0,
            .max_count = signed_hashes.hashes_count,
            .hash_len = signed_hashes.hash_len,
            .bytes = signed_hashes.hashes,
        };
    }

    /// Returns the size of `SignedHashes` in bytes, excluding the 'count' fields
    fn size(signed_hashes: *const SignedHashes) u32 {
        const hash_size = signed_hashes.hash_len * signed_hashes.hashes_count;
        return hash_size + signed_hashes.signature_bytes_len;
    }
};

const Signature = struct {
    /// The length of the key identifier
    key_id_len: u32,
    /// The key identifier
    key_id: [*]const u8,
    /// The length of the signature in bytes
    len: u32,
    /// Pointer to the signature in raw bytes
    signature: [*]const u8,

    /// From a slice of raw bytes, deserializes them into a `Signature`
    fn deserialize(bytes: []const u8, state: *LebState) !Signature {
        var previous_count = state.count;
        const key_id_len = try state.read(u32, bytes);
        var offset = state.count - previous_count;
        previous_count = state.count;
        const key_id = bytes[offset..].ptr;
        offset += key_id_len;
        const len = try state.read(u32, bytes[offset..]);
        offset += state.count - previous_count;
        const signature = bytes[offset..].ptr;

        return .{
            .key_id_len = key_id_len,
            .key_id = key_id,
            .len = len,
            .signature = signature,
        };
    }

    /// Serialises the `Signature` into its serialized encoding
    fn serialize(signature: Signature, writer: anytype) !void {
        try leb.writeULEB128(writer, signature.lebSize());
        try leb.writeULEB128(writer, signature.key_id_len);
        try writer.writeAll(signature.key());
        try leb.writeULEB128(writer, signature.len);
        try writer.writeAll(signature.asSlice());
    }

    /// Returns total size of the signature + key in bytes.
    fn size(signature: *const Signature) u32 {
        return signature.key_id_len + signature.len;
    }

    /// Returns the total size of the signature + key in bytes
    /// using the leb128 encoding, including the length of the key and signature.
    fn lebSize(signature: *const Signature) u32 {
        const lens = LebState.lebSize(signature.key_id_len) + LebState.lebSize(signature.len);
        return lens + signature.size();
    }

    /// Returns the signature as a slice instead of a multi-pointer
    fn asSlice(signature: *const Signature) []const u8 {
        return signature.signature[0..signature.len];
    }

    /// Returns the key as a slice
    fn key(signature: *const Signature) []const u8 {
        return signature.key_id[0..signature.key_id_len];
    }

    /// Returns true for when the `Signature` contains a key
    fn hasKey(signature: *const Signature) bool {
        return signature.key_id_len > 0;
    }

    pub fn format(signature: Signature, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = options;
        _ = fmt;
        var key_to_print: []const u8 = "(no key)";
        if (signature.key_id_len > 0) {
            key_to_print = signature.key();
        }
        try writer.writeAll(key_to_print);
    }
};

/// Reads leb128-encoded integers and preserves
/// state of the currently read length of all bytes read.
const LebState = struct {
    /// The current read bytes
    count: u32,

    /// Reads a leb128-encoded integer from a slice of byte.
    /// Returns `error.Overflow` when either the slice is too small,
    /// or the read integer does not fit into the result type.
    pub fn read(state: *LebState, comptime T: type, data: []const u8) error{Overflow}!T {
        const U = if (@typeInfo(T).Int.bits < 8) u8 else T;
        const ShiftT = std.math.Log2Int(U);

        const max_group = (@typeInfo(U).Int.bits + 6) / 7;

        var value = @as(U, 0);
        var group = @as(ShiftT, 0);

        while (group < max_group) : (group += 1) {
            if (group == data.len) return error.Overflow;
            const byte = data[group];
            var temp = @as(U, byte & 0x7f);

            if (@shlWithOverflow(U, temp, group * 7, &temp)) return error.Overflow;

            value |= temp;
            if (byte & 0x80 == 0) break;
        } else {
            return error.Overflow;
        }

        // only applies in the case that we extended to u8
        if (U != T) {
            if (value > std.math.maxInt(T)) return error.Overflow;
        }

        state.count += group + 1;
        return @truncate(T, value);
    }

    /// Writes a leb128-encoded integer to the given array.
    /// Array must be equal to the maximum byte-length for the given type `T`.
    /// Increments the `state`'s `count` with the length that was required to encode the integer
    /// to 128leb and was written to the given buffer `buf`.
    pub fn write(state: *LebState, comptime T: type, buf: *[(@typeInfo(T).Int.bits + 6) / 7]u8, uint_value: T) void {
        const U = if (@typeInfo(T).Int.bits < 8) u8 else T;
        var value = @intCast(U, uint_value);

        var group: u32 = 0;
        while (true) : (group += 1) {
            const byte = @truncate(u8, value & 0x7f);
            value >>= 7;
            if (value == 0) {
                buf[group] = byte;
                break;
            } else {
                buf[group] = byte | 0x80;
            }
        }
        state.count += group + 1;
    }

    /// From a given value, returns the amount of bytes it costs
    /// to store it in its 128-leb form.
    fn lebSize(uint_value: anytype) u32 {
        const T = @TypeOf(uint_value);
        const U = if (@typeInfo(T).Int.bits < 8) u8 else T;
        var value = @intCast(U, uint_value);

        var size: u32 = 0;
        while (value != 0) : (size += 1) {
            value >>= 7;
        }
        return size;
    }
};

/// Constructs a generic verifier which allows to verify a message
/// and signature of any length, where the `context` decides what it must
/// comply to, in order to verify a signature. This allows you to verify
/// arbitrary signatures without having the knowledge on a comptime-known length
/// or specific key.
pub fn Verifier(
    comptime Context: type,
    comptime VerifyError: type,
    comptime verifyFn: fn (
        context: Context,
        message: []const u8,
        signature: []const u8,
    ) VerifyError!void,
    comptime identifierFn: fn (context: Context) []const u8,
) type {
    return struct {
        const SignatureVerifier = @This();
        context: Context,

        /// Verifies a message with the given signature.
        /// Returns an error on failure, with no result on a successfull verification
        pub fn verify(verifier: SignatureVerifier, message: []const u8, signature: []const u8) VerifyError!void {
            return verifyFn(verifier.context, message, signature);
        }

        /// For the given verifier, returns its identifier.
        pub fn identifier(verifier: SignatureVerifier) []const u8 {
            return identifierFn(verifier.context);
        }
    };
}

/// Constructs a generic signer which allows to sign a message
/// and constructs a signature of any length. This allows you to
/// sign a given message using any key-pair with any signature length.
pub fn Signer(
    comptime Context: type,
    comptime SignError: type,
    comptime signFn: fn (
        context: Context,
        message: []const u8,
        buffer: []u8,
    ) SignError!usize,
    comptime identifierFn: fn (context: Context) []const u8,
) type {
    return struct {
        const SignatureSigner = @This();
        context: Context,

        /// Signs the message and generates a signature of which will be written into
        /// the given `buffer`. The length that was written is returned as value,
        /// or an error when a message could not be signed.
        /// This does *not* use a nounce.
        pub fn sign(signer: SignatureSigner, message: []const u8, buffer: []u8) SignError!usize {
            return signFn(signer.context, message, buffer);
        }

        /// For a given signer, returns its identifier
        pub fn identifier(signer: SignatureSigner) []const u8 {
            return identifierFn(signer.context);
        }
    };
}
