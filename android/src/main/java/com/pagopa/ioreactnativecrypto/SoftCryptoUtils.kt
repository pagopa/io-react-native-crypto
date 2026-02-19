package com.pagopa.ioreactnativecrypto

import android.util.Base64
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import org.bouncycastle.jce.provider.BouncyCastleProvider

/**
 * Soft-crypto utilities used by the React Native bridge.
 *
 * All functions return a lowercase hex string so the bridge methods
 * are simple delegate calls with no encoding logic.
 */
internal object SoftCryptoUtils {

  private val secureRandom: SecureRandom by lazy { SecureRandom() }

  private const val MAX_RANDOM_BYTES = 65536

  /** Returns [size] cryptographically-secure random bytes as a lowercase hex string. */
  fun randomBytes(size: Int): String {
    require(size in 1..MAX_RANDOM_BYTES) {
      "size must be positive and at most $MAX_RANDOM_BYTES"
    }
    val bytes = ByteArray(size)
    secureRandom.nextBytes(bytes)
    return bytes.joinToString("") { "%02x".format(it) }
  }

  /** Hashes the UTF-8 bytes of [data] with [algorithm]. */
  fun hashString(data: String, algorithm: String): String =
    hash(data.toByteArray(Charsets.UTF_8), algorithm)

  /** Hashes raw bytes supplied as a lowercase hex string [hexData] with [algorithm]. */
  fun hashBytes(hexData: String, algorithm: String): String {
    require(
      hexData.length % 2 == 0 &&
        hexData.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }
    ) { "Invalid hex string format" }
    return hash(hexData.chunked(2).map { it.toInt(16).toByte() }.toByteArray(), algorithm)
  }

  /**
   * Verifies an ES256 (ECDSA P-256 SHA-256) signature.
   *
   * [data] is the raw UTF-8 signing input (the JWS signing input string).
   * [signatureBase64url] is the Base64URL-encoded IEEE P1363 signature (R‖S, 64 bytes).
   * [x] and [y] are the Base64URL-encoded P-256 public key coordinates from the JWK.
   */
  fun verifyES256(data: String, signatureBase64url: String, x: String, y: String): Boolean {
    val flags = Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
    val xBytes = Base64.decode(x, flags)
    val yBytes = Base64.decode(y, flags)

    val params = AlgorithmParameters.getInstance("EC")
    params.init(ECGenParameterSpec("secp256r1"))
    val ecParams = params.getParameterSpec(ECParameterSpec::class.java)
    val pubKeySpec = ECPublicKeySpec(
      ECPoint(BigInteger(1, xBytes), BigInteger(1, yBytes)),
      ecParams
    )
    val publicKey = KeyFactory.getInstance("EC").generatePublic(pubKeySpec)

    // BouncyCastle's "SHA256withPLAIN-ECDSA" accepts P1363 (R‖S) directly.
    val sigP1363 = Base64.decode(signatureBase64url, flags)
    val sig = Signature.getInstance("SHA256withPLAIN-ECDSA", BouncyCastleProvider())
    sig.initVerify(publicKey)
    sig.update(data.toByteArray(Charsets.UTF_8))
    return sig.verify(sigP1363)
  }

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
