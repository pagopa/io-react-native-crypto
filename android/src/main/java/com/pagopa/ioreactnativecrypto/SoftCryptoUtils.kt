package com.pagopa.ioreactnativecrypto

import java.security.MessageDigest

/**
 * Hashing utilities used by the React Native bridge.
 *
 * Both functions return a lowercase hex string so the bridge methods
 * are simple delegate calls with no encoding logic.
 */
internal object SoftCryptoUtils {

  /** Hashes the UTF-8 bytes of [data] with [algorithm]. */
  fun hashString(data: String, algorithm: String): String =
    hash(data.toByteArray(Charsets.UTF_8), algorithm)

  /** Hashes raw bytes supplied as a lowercase hex string [hexData] with [algorithm]. */
  fun hashBytes(hexData: String, algorithm: String): String =
    hash(hexData.chunked(2).map { it.toInt(16).toByte() }.toByteArray(), algorithm)

  private fun hash(input: ByteArray, algorithm: String): String =
    MessageDigest.getInstance(javaAlgorithmName(algorithm))
      .digest(input)
      .joinToString("") { "%02x".format(it) }

  private fun javaAlgorithmName(algorithm: String): String =
    when (algorithm.lowercase().replace("-", "")) {
      "sha256" -> "SHA-256"
      "sha384" -> "SHA-384"
      "sha512" -> "SHA-512"
      else -> throw IllegalArgumentException("Unsupported hash algorithm: $algorithm")
    }
}
