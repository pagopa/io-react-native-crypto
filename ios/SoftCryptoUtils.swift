import CryptoKit
import Foundation
import Security

/**
 * Soft-crypto utilities for ephemeral (non-hardware-backed) key operations.
 *
 * All functions accept and return raw Data; Base64 encoding/decoding and
 * packing into React Native bridge types is handled by the calling module.
 */
enum SoftCryptoUtils {

  // ─── Error type ────────────────────────────────────────────────────────────

  enum SoftCryptoError: LocalizedError {
    case saltGenerationFailed
    case unsupportedAlgorithm(String)
    case unsupportedCurve(String)
    case invalidKey(String)

    var errorDescription: String? {
      switch self {
      case .saltGenerationFailed:
        return "Failed to generate cryptographically random bytes"
      case .unsupportedAlgorithm(let alg):
        return "Unsupported hash algorithm: \(alg)"
      case .unsupportedCurve(let crv):
        return "Unsupported elliptic curve: \(crv)"
      case .invalidKey(let msg):
        return "Invalid key data: \(msg)"
      }
    }
  }

  // ─── Key-pair result ───────────────────────────────────────────────────────

  struct EphemeralKeyPair {
    let namedCurve: String
    let publicX: Data
    let publicY: Data
    let privateD: Data
  }

  // ─── Public API ────────────────────────────────────────────────────────────

  /// Returns a hex string of exactly [length] characters derived from
  /// [length] cryptographically random bytes.
  static func generateSalt(_ length: Int) throws -> String {
    guard length > 0 else { return "" }
    var bytes = [UInt8](repeating: 0, count: length)
    let status = SecRandomCopyBytes(kSecRandomDefault, length, &bytes)
    guard status == errSecSuccess else {
      throw SoftCryptoError.saltGenerationFailed
    }
    let hex = bytes.map { String(format: "%02x", $0) }.joined()
    return String(hex.prefix(length))
  }

  /// Hashes [input] with [algorithm] ("sha-256", "sha-384", or "sha-512").
  /// Returns the raw hash bytes.
  static func hash(_ input: Data, algorithm: String) throws -> Data {
    switch normalizeHashAlg(algorithm) {
    case "sha256": return Data(SHA256.hash(data: input))
    case "sha384": return Data(SHA384.hash(data: input))
    case "sha512": return Data(SHA512.hash(data: input))
    default: throw SoftCryptoError.unsupportedAlgorithm(algorithm)
    }
  }

  /// Generates an ephemeral ECDSA key pair for [namedCurve]
  /// ("P-256", "P-384", or "P-521").
  /// Returns raw unsigned coordinate bytes for x, y and d.
  static func generateEphemeralKeyPair(namedCurve: String) throws -> EphemeralKeyPair {
    switch namedCurve {
    case "P-256":
      let key = P256.Signing.PrivateKey()
      let x963 = key.publicKey.x963Representation  // 04 || X(32) || Y(32)
      return EphemeralKeyPair(
        namedCurve: namedCurve,
        publicX: x963[1..<33],
        publicY: x963[33..<65],
        privateD: key.rawRepresentation
      )
    case "P-384":
      let key = P384.Signing.PrivateKey()
      let x963 = key.publicKey.x963Representation  // 04 || X(48) || Y(48)
      return EphemeralKeyPair(
        namedCurve: namedCurve,
        publicX: x963[1..<49],
        publicY: x963[49..<97],
        privateD: key.rawRepresentation
      )
    case "P-521":
      let key = P521.Signing.PrivateKey()
      let x963 = key.publicKey.x963Representation  // 04 || X(66) || Y(66)
      return EphemeralKeyPair(
        namedCurve: namedCurve,
        publicX: x963[1..<67],
        publicY: x963[67..<133],
        privateD: key.rawRepresentation
      )
    default:
      throw SoftCryptoError.unsupportedCurve(namedCurve)
    }
  }

  /// Signs [data] (raw bytes) with the private key scalar [privateD].
  /// Returns the signature in IEEE P1363 format (raw R‖S).
  static func sign(
    _ data: Data,
    privateD: Data,
    namedCurve: String,
    hashAlgorithm: String
  ) throws -> Data {
    let hash = normalizeHashAlg(hashAlgorithm)
    switch namedCurve {
    case "P-256":
      let key = try P256.Signing.PrivateKey(rawRepresentation: privateD)
      return try signP256(key, data: data, hash: hash).rawRepresentation
    case "P-384":
      let key = try P384.Signing.PrivateKey(rawRepresentation: privateD)
      return try signP384(key, data: data, hash: hash).rawRepresentation
    case "P-521":
      let key = try P521.Signing.PrivateKey(rawRepresentation: privateD)
      return try signP521(key, data: data, hash: hash).rawRepresentation
    default:
      throw SoftCryptoError.unsupportedCurve(namedCurve)
    }
  }

  /// Verifies an IEEE P1363 [signature] (raw R‖S) against [data]
  /// using the public key coordinates [publicX] and [publicY].
  /// Returns true when the signature is valid.
  static func verify(
    _ data: Data,
    signature: Data,
    publicX: Data,
    publicY: Data,
    namedCurve: String,
    hashAlgorithm: String
  ) throws -> Bool {
    // Reconstruct uncompressed point: 04 || X || Y
    var x963 = Data([0x04])
    x963.append(publicX)
    x963.append(publicY)

    let hash = normalizeHashAlg(hashAlgorithm)
    switch namedCurve {
    case "P-256":
      let key = try P256.Signing.PublicKey(x963Representation: x963)
      let sig = try P256.Signing.ECDSASignature(rawRepresentation: signature)
      return try verifyP256(key, signature: sig, data: data, hash: hash)
    case "P-384":
      let key = try P384.Signing.PublicKey(x963Representation: x963)
      let sig = try P384.Signing.ECDSASignature(rawRepresentation: signature)
      return try verifyP384(key, signature: sig, data: data, hash: hash)
    case "P-521":
      let key = try P521.Signing.PublicKey(x963Representation: x963)
      let sig = try P521.Signing.ECDSASignature(rawRepresentation: signature)
      return try verifyP521(key, signature: sig, data: data, hash: hash)
    default:
      throw SoftCryptoError.unsupportedCurve(namedCurve)
    }
  }

  // ─── Private sign helpers ─────────────────────────────────────────────────
  // CryptoKit's per-curve types are unrelated, so each needs its own helper.
  // Signing a pre-computed Digest avoids a second internal hash.

  private static func signP256(
    _ key: P256.Signing.PrivateKey, data: Data, hash: String
  ) throws -> P256.Signing.ECDSASignature {
    switch hash {
    case "sha256": return try key.signature(for: SHA256.hash(data: data))
    case "sha384": return try key.signature(for: SHA384.hash(data: data))
    case "sha512": return try key.signature(for: SHA512.hash(data: data))
    default: throw SoftCryptoError.unsupportedAlgorithm(hash)
    }
  }

  private static func signP384(
    _ key: P384.Signing.PrivateKey, data: Data, hash: String
  ) throws -> P384.Signing.ECDSASignature {
    switch hash {
    case "sha256": return try key.signature(for: SHA256.hash(data: data))
    case "sha384": return try key.signature(for: SHA384.hash(data: data))
    case "sha512": return try key.signature(for: SHA512.hash(data: data))
    default: throw SoftCryptoError.unsupportedAlgorithm(hash)
    }
  }

  private static func signP521(
    _ key: P521.Signing.PrivateKey, data: Data, hash: String
  ) throws -> P521.Signing.ECDSASignature {
    switch hash {
    case "sha256": return try key.signature(for: SHA256.hash(data: data))
    case "sha384": return try key.signature(for: SHA384.hash(data: data))
    case "sha512": return try key.signature(for: SHA512.hash(data: data))
    default: throw SoftCryptoError.unsupportedAlgorithm(hash)
    }
  }

  // ─── Private verify helpers ───────────────────────────────────────────────

  private static func verifyP256(
    _ key: P256.Signing.PublicKey,
    signature: P256.Signing.ECDSASignature,
    data: Data,
    hash: String
  ) throws -> Bool {
    switch hash {
    case "sha256": return key.isValidSignature(signature, for: SHA256.hash(data: data))
    case "sha384": return key.isValidSignature(signature, for: SHA384.hash(data: data))
    case "sha512": return key.isValidSignature(signature, for: SHA512.hash(data: data))
    default: throw SoftCryptoError.unsupportedAlgorithm(hash)
    }
  }

  private static func verifyP384(
    _ key: P384.Signing.PublicKey,
    signature: P384.Signing.ECDSASignature,
    data: Data,
    hash: String
  ) throws -> Bool {
    switch hash {
    case "sha256": return key.isValidSignature(signature, for: SHA256.hash(data: data))
    case "sha384": return key.isValidSignature(signature, for: SHA384.hash(data: data))
    case "sha512": return key.isValidSignature(signature, for: SHA512.hash(data: data))
    default: throw SoftCryptoError.unsupportedAlgorithm(hash)
    }
  }

  private static func verifyP521(
    _ key: P521.Signing.PublicKey,
    signature: P521.Signing.ECDSASignature,
    data: Data,
    hash: String
  ) throws -> Bool {
    switch hash {
    case "sha256": return key.isValidSignature(signature, for: SHA256.hash(data: data))
    case "sha384": return key.isValidSignature(signature, for: SHA384.hash(data: data))
    case "sha512": return key.isValidSignature(signature, for: SHA512.hash(data: data))
    default: throw SoftCryptoError.unsupportedAlgorithm(hash)
    }
  }

  // ─── Shared normalizer ────────────────────────────────────────────────────

  private static func normalizeHashAlg(_ algorithm: String) -> String {
    algorithm.lowercased().replacingOccurrences(of: "-", with: "")
  }
}

// ─── String extension ─────────────────────────────────────────────────────────

extension String {
  /// Decodes a Base64URL string (URL-safe alphabet, no padding) to Data.
  func base64UrlDecodedData() -> Data? {
    var base64 = replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    let remainder = base64.count % 4
    if remainder > 0 {
      base64 += String(repeating: "=", count: 4 - remainder)
    }
    return Data(base64Encoded: base64)
  }
}

extension Data {
  /// Decodes a lowercase hex string to Data.
  /// Returns nil if the string has an odd length or non-hex digits.
  init?(hexEncoded hex: String) {
    guard hex.count % 2 == 0 else { return nil }
    var data = Data(capacity: hex.count / 2)
    var index = hex.startIndex
    while index < hex.endIndex {
      let next = hex.index(index, offsetBy: 2)
      guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
      data.append(byte)
      index = next
    }
    self = data
  }
}
