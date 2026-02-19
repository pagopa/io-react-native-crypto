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
