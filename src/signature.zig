//! Implements the signing and verification
//! of the signature section of Wasm binaries.
//! The implementation follows the design proposal as
//! specified by the tool-convention found at:
//! https://github.com/WebAssembly/tool-conventions/blob/main/Signatures.md
const std = @import("std");
const Module = @import("Module.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;

pub fn sign(key: []const u8, module: *const Module) !void {
    _ = key; // TODO
    _ = module; // TODO
}

pub fn verify(key: []const u8, module: *const Module) !bool {
    _ = key; // TODO

    const signature_header = module.getNamed("signature") orelse {
        return error.MissingSignature;
    };

    const signature_bytes = signature_header.raw();
    const header = SignatureHeader.deserialize(signature_bytes[0..6]);
    if (header.version != 0x1) {
        return error.UnsupportedVersion;
    }

    if (header.hash != .sha256) {
        return error.UnsupportedHashFunction;
    }

    var signature_index: u32 = 0;
    var bytes_ptr: usize = 6; // we already retrieved the signature header
    while (signature_index < header.signed_hash_count) : (signature_index += 1) {
        const raw_signature_bytes = signature_bytes[bytes_ptr..];
        const signed_hashes = SignedHashes.deserialize(raw_signature_bytes, header.hash.len());
        bytes_ptr += signed_hashes.size();
    }
}

const Hash = enum(u8) {
    sha256 = 0x1,
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

    fn deserialize(bytes: *const [6]u8) SignatureHeader {
        return .{
            .version = bytes[0],
            .hash = @intToEnum(Hash, bytes[1]),
            .signed_hash_count = std.mem.readIntLittle(u32, bytes[2..6]),
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

        /// Deserializes the next Signature. Returns null when end of iterator has been reached.
        fn next(it: *SignatureIterator) ?Signature {
            if (it.index == it.max_count) return null;
            const signature = Signature.deserialize(it.bytes[it.byte_index..it.bytes_len]);
            it.byte_index += signature.size();
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
            const hash = it.bytes[it.index * it.hash_len ..][0..it.hash_len];
            it.index += 1;
            return hash;
        }
    };

    /// Deserializes the raw bytes into a `SignedHashes`.
    fn deserialize(bytes: []const u8, hash_len: u32) SignedHashes {
        const count = std.mem.readIntLittle(u32, bytes[0..4]);
        const hashes = bytes[4..].ptr;
        const hashes_len = count * hash_len;
        const sig_count = std.mem.readIntLittle(u32, bytes[4 + hashes_len ..][0..4]);
        const signatures = bytes[8 + hashes_len ..].ptr;

        return .{
            .hashes_count = count,
            .hashes = hashes,
            .hash_len = hash_len,
            .signature_count = sig_count,
            .signatures = signatures,
            .signature_bytes_len = @intCast(u32, bytes.len - 8 - hashes_len),
        };
    }

    /// Builds and returns an iterator for iterating all signatures
    fn signatureIterator(signed_hashes: SignedHashes) SignatureIterator {
        return .{
            .index = 0,
            .max_count = signed_hashes.signature_count,
            .byte_index = 0,
            .bytes_len = signed_hashes.signature_bytes_len,
            .bytes = signed_hashes.signatures,
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

    /// Returns the size of `SignedHashes` in bytes
    fn size(signed_hashes: *const SignedHashes) u32 {
        const hash_size = @intCast(u32, 4 + (signed_hashes.hash_len * signed_hashes.hashes_count));
        const sig_size = 4 + signed_hashes.signature_bytes_len;
        return hash_size + sig_size;
    }
};

const Signature = struct {
    /// The length of the key identifier
    key_id_len: u32,
    /// The key identifier
    key_id: [*]const u8,
    /// The length of the signature in bytes (excluding the length fields)
    len: u32,
    /// Pointer to the signature in raw bytes
    signature: [*]const u8,

    /// From a slice of raw bytes, deserializes them into a `Signature`
    fn deserialize(bytes: []const u8) Signature {
        const key_id_len = std.mem.readIntLittle(u32, bytes[0..4]);
        const key_id = bytes[4..].ptr;
        const len = std.mem.readIntLittle(u32, bytes[4 + key_id_len ..][0..4]);
        const signature = bytes[8 + key_id_len ..].ptr;
        return .{
            .key_id_line = key_id_len,
            .key_id = key_id,
            .len = len,
            .signature = signature,
        };
    }

    /// Returns the total signature size in bytes (including the length fields).
    fn size(signature: *const Signature) u32 {
        return 8 + signature.key_id_len + signature.len;
    }

    /// Returns the signature as a slice instead of a multi-pointer
    fn asSlice(signature: *const Signature) []const u8 {
        return signature.signature[0..signature.len];
    }

    /// Returns the key as a slice
    fn key(signature: *const Signature) []const u8 {
        return signature.key_id[0..signature.key_id_len];
    }
};
