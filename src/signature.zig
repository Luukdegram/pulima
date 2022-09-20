//! Implements the signing and verification
//! of the signature section of Wasm binaries.
//! The implementation follows the design proposal as
//! specified by the tool-convention found at:
//! https://github.com/WebAssembly/tool-conventions/blob/main/Signatures.md
const std = @import("std");
const Module = @import("Module.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;
const Ed25519 = std.crypto.sign.Ed25519;

pub fn sign(key: []const u8, module: *const Module) !void {
    _ = key; // TODO
    _ = module; // TODO
}

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

    std.log.debug("signature contains {d} signed hashes", .{header.signed_hash_count});
    std.log.debug("verifying hashes...", .{});

    var signature_index: u32 = 0;
    var bytes_ptr: usize = 2 + leb_state.count; // we already retrieved the signature header
    while (signature_index < header.signed_hash_count) : (signature_index += 1) {
        const raw_signature_bytes = signature_bytes[bytes_ptr..];
        var previous_state_count = leb_state.count;
        const signed_hashes = try SignedHashes.deserialize(raw_signature_bytes, header.hash.len(), &leb_state);
        std.log.debug("   hash count: {d}", .{signed_hashes.hashes_count});
        std.log.debug("   signatures: {d}", .{signed_hashes.signature_count});
        bytes_ptr += signed_hashes.size() + (leb_state.count - previous_state_count);

        var signature_it = signed_hashes.signatureIterator(&leb_state);
        var verified_hash_count: u32 = 0;
        while (try signature_it.next()) |signature| {
            std.log.debug("      signature key: {s}", .{signature.key()});
            std.log.debug("      signature: {s}", .{signature.asSlice()});
            // verifier.verify(signed_hashes.hash(), signature.asSlice()) catch continue; // invalid signature for hash
            try verifier.verify(signed_hashes.hash(), signature.asSlice());
            verified_hash_count += 1;
        }

        if (verified_hash_count == 0) {
            return error.NoValidSignatures;
        }

        // we have verified at least one hash was signed correctly for the given key
        // now we hash the data ourselves and ensure it matches a verified hash.
        var hasher = Sha256.init(.{});
        const module_start = signature_header.offset + signature_header.size;
        hasher.update(module.raw_data[module_start .. module.size - module_start]);
        var final_hash: [Sha256.digest_length]u8 = undefined;
        hasher.final(&final_hash);

        var hash_matches = false;
        var hash_it = signed_hashes.hashIterator();
        while (hash_it.next()) |hash| {
            if (std.mem.eql(u8, hash, &final_hash)) {
                hash_matches = true;
            }
        }
        if (!hash_matches) {
            return error.NoValidSignatures;
        }
    }
}

const Hash = enum(u8) {
    sha256 = 0x01,
    _,

    fn len(hash: Hash) u32 {
        switch (hash) {
            .sha256 => return Sha256.digest_length,
            else => return 0,
        }
    }
};

const SignatureHeader = struct {
    version: u8,
    hash: Hash,
    signed_hash_count: u32,

    fn deserialize(bytes: []const u8, state: *LebState) !SignatureHeader {
        return .{
            .version = bytes[0],
            .hash = @intToEnum(Hash, bytes[1]),
            .signed_hash_count = try state.read(u32, bytes[2..]),
        };
    }
};

const SignedHashes = struct {
    hashes_count: u32,
    hashes: [*]const u8,
    hash_len: u32,
    signature_count: u32,
    signatures: [*]const u8,
    signature_bytes_len: u32,

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
        const count = try state.read(u32, bytes);
        var offset = state.count - prev_count;
        const hashes = bytes[offset..].ptr;
        const hashes_len = count * hash_len;
        offset += hashes_len + 1;
        const sig_count = try state.read(u32, bytes[offset..]);
        offset += state.count - prev_count + 1;
        const signatures = bytes[offset..].ptr;

        return .{
            .hashes_count = count,
            .hashes = hashes,
            .hash_len = hash_len,
            .signature_count = sig_count,
            .signatures = signatures,
            .signature_bytes_len = @intCast(u32, bytes.len - offset),
        };
    }

    /// Returns all hashes concatenated as a single slice
    fn hash(signed_hashes: *const SignedHashes) []const u8 {
        return signed_hashes.hashes[0 .. signed_hashes.hash_len * signed_hashes.hashes_count];
    }

    /// Builds and returns an iterator for iterating all signatures
    fn signatureIterator(signed_hashes: SignedHashes, state: *LebState) SignatureIterator {
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
        const previous_count = state.count;
        const key_id_len = try state.read(u32, bytes);
        var offset = state.count - previous_count;
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

    /// Returns total size of the signature + key in bytes.
    fn size(signature: *const Signature) u32 {
        return signature.key_id_len + signature.len;
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
};

pub fn Verifier(
    comptime Context: type,
    comptime VerifyError: type,
    comptime verifyFn: fn (
        context: Context,
        message: []const u8,
        signature: []const u8,
    ) VerifyError!void,
) type {
    return struct {
        const SignatureVerifier = @This();
        context: Context,

        pub fn verify(verifier: SignatureVerifier, message: []const u8, signature: []const u8) VerifyError!void {
            return verifyFn(verifier.context, message, signature);
        }
    };
}
