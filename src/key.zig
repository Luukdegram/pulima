///! Structures for public and secret key implementations
///! which are used to sign and verify signatures.
const std = @import("std");
const SignatureVerifier = @import("signature.zig").Verifier;
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
        SignatureTooShort,
    } ||
        errors.SignatureVerificationError ||
        errors.WeakPublicKeyError ||
        errors.EncodingError ||
        errors.NonCanonicalError ||
        errors.IdentityElementError;

    /// Verifies the signature for a given message using the Edwards25519 elliptic curve.
    /// Only when no error was returned, is the signature to be considered valid for the given message.
    pub fn verify(key: PublicKey, message: []const u8, signature: []const u8) VerifyError!void {
        if (signature.len < Ed25519.signature_length) return error.SignatureTooShort;
        return Ed25519.verify(signature[0..Ed25519.signature_length].*, message, key.key);
    }

    /// From a given slice of bytes constructs a `PublicKey`
    /// Returns `error.InvalidKey` when the slice is too short or contains
    /// an invalid identifier.
    pub fn fromBytes(bytes: []const u8) error{InvalidKey}!PublicKey {
        if (bytes.len < 33) return error.InvalidKey;
        if (bytes[0] != 0x01) return error.InvalidKey;

        return PublicKey{
            .key_id = &.{},
            .key = bytes[1..33].*,
        };
    }

    const Verifier = SignatureVerifier(PublicKey, VerifyError, PublicKey.verify);

    pub fn verifier(key: PublicKey) Verifier {
        return .{ .context = key };
    }
};
