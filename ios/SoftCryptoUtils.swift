import CryptoKit
import Foundation
import Security

/**
 * Hashing utilities used by the React Native bridge.
 *
 * Both functions return a lowercase hex string so the bridge methods
 * are simple delegate calls with no encoding logic.
 */
enum SoftCryptoUtils {

  enum SoftCryptoError: LocalizedError {
    case unsupportedAlgorithm(String)
    case invalidInput(String)
    case randomBytesError(String)

    var errorDescription: String? {
      switch self {
      case .unsupportedAlgorithm(let alg): return "Unsupported hash algorithm: \(alg)"
      case .invalidInput(let msg): return "Invalid input: \(msg)"
      case .randomBytesError(let msg): return "Random bytes generation failed: \(msg)"
      }
    }
  }

  /// Returns [size] cryptographically-secure random bytes as a lowercase hex string.
  static func randomBytes(_ size: Int) throws -> String {
    guard size > 0 else {
      throw SoftCryptoError.invalidInput("size must be positive")
    }
    var bytes = [UInt8](repeating: 0, count: size)
    let status = SecRandomCopyBytes(kSecRandomDefault, size, &bytes)
    guard status == errSecSuccess else {
      throw SoftCryptoError.randomBytesError("SecRandomCopyBytes failed with status \(status)")
    }
    return bytes.map { String(format: "%02x", $0) }.joined()
  }

  /**
   * Verifies an ES256 (ECDSA P-256 SHA-256) signature.
   *
   * - data: the raw UTF-8 signing input (the JWS signing input string).
   * - signatureBase64url: Base64URL-encoded IEEE P1363 signature (R‖S, 64 bytes).
   * - x, y: Base64URL-encoded P-256 public key coordinates from the JWK.
   */
  static func verifyES256(
    _ data: String,
    signatureBase64url: String,
    x: String,
    y: String
  ) throws -> Bool {
    guard let xData = Data(base64URLEncoded: x),
          let yData = Data(base64URLEncoded: y) else {
      throw SoftCryptoError.invalidInput("Invalid public key coordinates")
    }
    // Uncompressed EC point: 0x04 || x (32 bytes) || y (32 bytes)
    var keyData = Data([0x04])
    keyData.append(contentsOf: [UInt8](repeating: 0, count: max(0, 32 - xData.count)))
    keyData.append(xData)
    keyData.append(contentsOf: [UInt8](repeating: 0, count: max(0, 32 - yData.count)))
    keyData.append(yData)

    let keyAttrs: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
      kSecAttrKeySizeInBits as String: 256
    ]
    var cfError: Unmanaged<CFError>?
    guard let publicKey = SecKeyCreateWithData(keyData as CFData, keyAttrs as CFDictionary, &cfError) else {
      throw SoftCryptoError.invalidInput("Cannot reconstruct public key")
    }

    guard let sigP1363 = Data(base64URLEncoded: signatureBase64url) else {
      throw SoftCryptoError.invalidInput("Invalid signature encoding")
    }
    let sigDer = try p1363ToDer(sigP1363)

    guard let messageData = data.data(using: .utf8) else {
      throw SoftCryptoError.invalidInput("Invalid UTF-8 string")
    }

    var verifyError: Unmanaged<CFError>?
    return SecKeyVerifySignature(
      publicKey,
      .ecdsaSignatureMessageX962SHA256,
      messageData as CFData,
      sigDer as CFData,
      &verifyError
    )
  }

  /// Converts a 64-byte IEEE P1363 signature (R‖S) to DER/X9.62 format
  /// expected by SecKeyVerifySignature.
  private static func p1363ToDer(_ sig: Data) throws -> Data {
    guard sig.count == 64 else {
      throw SoftCryptoError.invalidInput("Expected 64-byte P1363 signature for P-256")
    }
    let r = sig.subdata(in: 0..<32)
    let s = sig.subdata(in: 32..<64)

    func asn1Int(_ bytes: Data) -> Data {
      var trimmed = Array(bytes.drop(while: { $0 == 0 }))
      if trimmed.isEmpty { trimmed = [0x00] }
      if trimmed[0] & 0x80 != 0 { trimmed.insert(0x00, at: 0) }
      var result = Data([0x02, UInt8(trimmed.count)])
      result.append(contentsOf: trimmed)
      return result
    }

    let rDer = asn1Int(r)
    let sDer = asn1Int(s)
    var der = Data([0x30, UInt8(rDer.count + sDer.count)])
    der.append(rDer)
    der.append(sDer)
    return der
  }

  /// Hashes the UTF-8 bytes of [data] with [algorithm].
  static func hashString(_ data: String, algorithm: String) throws -> String {
    guard let input = data.data(using: .utf8) else {
      throw SoftCryptoError.invalidInput("Invalid UTF-8 string")
    }
    return try hash(input, algorithm: algorithm)
  }

  /// Hashes raw bytes supplied as a lowercase hex string [hexData] with [algorithm].
  static func hashBytes(_ hexData: String, algorithm: String) throws -> String {
    guard let input = Data(hexEncoded: hexData) else {
      throw SoftCryptoError.invalidInput("Invalid hex string")
    }
    return try hash(input, algorithm: algorithm)
  }

  private static func hash(_ input: Data, algorithm: String) throws -> String {
    let result: Data
    switch algorithm.lowercased().replacingOccurrences(of: "-", with: "") {
    case "sha256": result = Data(SHA256.hash(data: input))
    case "sha384": result = Data(SHA384.hash(data: input))
    case "sha512": result = Data(SHA512.hash(data: input))
    default: throw SoftCryptoError.unsupportedAlgorithm(algorithm)
    }
    return result.map { String(format: "%02x", $0) }.joined()
  }
}

extension Data {
  /// Decodes a Base64URL string (RFC 7515) to Data.
  init?(base64URLEncoded string: String) {
    var base64 = string
      .replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    while base64.count % 4 != 0 { base64.append("=") }
    self.init(base64Encoded: base64)
  }

  /// Encodes data as a Base64URL string (RFC 7515): URL-safe alphabet, no padding.
  func base64UrlEncodedString() -> String {
    return base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }

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
