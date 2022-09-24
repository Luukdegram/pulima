///! Structures for public and secret key implementations
///! which are used to sign and verify signatures.
const std = @import("std");
const SignatureVerifier = @import("signature.zig").Verifier;
const SignatureSigner = @import("signature.zig").Signer;
const Ed25519 = std.crypto.sign.Ed25519;
const errors = std.crypto.errors;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

/// Public key using the Edwards 25519 elliptic curve for verifying
/// signatures in a Wasm module.
pub const PublicKey = struct {
    /// Represents the ID of a specific key which is used to
    /// differentiate between the different public keys as multiple keys
    /// are allowed to sign different parts of the module.
    key_id: []const u8,
    /// The key representation in bytes
    key: [Ed25519.public_length]u8,

    /// When verifying the signature of a given message,
    /// the following errors may occur, resulting in an
    /// invalid signature.
    const VerifyError = error{
        InvalidSignature,
    } ||
        errors.SignatureVerificationError ||
        errors.WeakPublicKeyError ||
        errors.EncodingError ||
        errors.NonCanonicalError ||
        errors.IdentityElementError;

    /// Verifies the signature for a given message using the Edwards25519 elliptic curve.
    /// Only when no error was returned, is the signature to be considered valid for the given message.
    pub fn verify(key: PublicKey, message: []const u8, signature: []const u8) VerifyError!void {
        if (signature.len != Ed25519.signature_length) return error.InvalidSignature;
        return Ed25519.verify(signature[0..Ed25519.signature_length].*, message, key.key);
    }

    /// From a given slice of bytes constructs a `PublicKey`.
    /// Returns `error.InvalidKey` when the data does not follow the tooling convention.
    pub fn deserialize(bytes: []const u8) error{InvalidKey}!PublicKey {
        if (bytes.len < 33) return error.InvalidKey;
        if (bytes[0] != 0x01) return error.InvalidKey;

        return PublicKey{
            .key_id = &.{},
            .key = bytes[1..33].*,
        };
    }

    pub const Verifier = SignatureVerifier(PublicKey, VerifyError, verify, identifier);

    /// Returns a verifier instance which can be used to verify signatures
    /// using this public key and the Edwards 25519 elliptic curve for verifying.
    pub fn verifier(key: PublicKey) Verifier {
        return .{ .context = key };
    }

    /// Returns the public key's identifier. It is safe to access `key_id` directly as this
    /// function is used to comply to the `Verifier` interface.
    pub fn identifier(key: PublicKey) []const u8 {
        return key.key_id;
    }
};

/// A keypair using the Edwards 25519 elliptic curve.
/// Used to sign messages to construct a signature.
pub const KeyPair = struct {
    /// Represents the ID of a specific key which is used to
    /// differentiate between the different public keys as multiple keys
    /// are allowed to sign different parts of the module.
    key_id: []const u8,
    /// Private key of the KeyPair, which also holds
    /// the public key.
    private_key: [Ed25519.secret_length]u8,

    pub const SignError = error{
        BufferTooSmall,
    } ||
        errors.IdentityElementError ||
        errors.WeakPublicKeyError ||
        errors.KeyMismatchError;

    /// From a given slice of bytes constructs a `KeyPair`.
    /// Returns `error.InvalidKey` when the data does not follow the tooling convention.
    pub fn deserialize(bytes: []const u8) error{InvalidKeyPair}!KeyPair {
        if (bytes.len < 65) return error.InvalidKey;
        if (bytes[0] != 0x81) return error.InvalidKey;

        return KeyPair{
            .private_key = bytes[1..65].*,
        };
    }

    /// Signer type which allows a generic signing implementation.
    pub const Signer = SignatureSigner(KeyPair, SignError, sign, identifier);

    /// Returns a generic `Signer` which allows to sign arbitrary messages
    /// and writes the signature into a buffer.
    pub fn signer(key_pair: KeyPair) Signer {
        return .{ .context = key_pair };
    }

    /// Signs the given message using this `KeyPair`. Writes the signature into `buffer`,
    /// and returns the amount of bytes written.
    pub fn sign(key_pair: KeyPair, message: []const u8, buffer: []u8) SignError!usize {
        if (buffer.len < Ed25519.signature_length) return error.BufferTooSmall;
        const pair = Ed25519.KeyPair.fromSecretKey(key_pair.private_key);
        const signature = Ed25519.sign(message, pair, null);
        std.mem.copy(u8, buffer, &signature);
        return Ed25519.signature_length;
    }

    /// Returns the key pair's identifier. It is safe to access `key_id` directly as this
    /// function is used to comply to the `Signer` interface.
    pub fn identifier(key_pair: KeyPair) []const u8 {
        return key_pair.identifier();
    }

    /// Returns the `KeyPair` as a `PublicKey` which can then be used
    /// to verify a signature that was produced by this KeyPair.
    pub fn publicKey(key_pair: KeyPair) PublicKey {
        return .{
            .public_key = key_pair.private_key[Ed25519.seed_length..].*,
            .key_id = key_pair.key_id,
        };
    }
};
