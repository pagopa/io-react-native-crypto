package com.pagopa.ioreactnativecrypto

import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.util.BigIntegers
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec

/**
 * Soft-crypto utilities for ephemeral (non-hardware-backed) key operations.
 *
 * All functions work with raw byte arrays; encoding/decoding of Base64 and
 * packing into React Native bridge types is handled by the calling module.
 */
internal object SoftCryptoUtils {

  // ─── Public API ────────────────────────────────────────────────────────────

  data class EphemeralKeyPair(
    val namedCurve: String,
    val publicX: ByteArray,
    val publicY: ByteArray,
    val privateD: ByteArray
  )

  /**
   * Returns a hex string of exactly [length] characters derived from
   * [length] cryptographically random bytes.
   */
  fun generateSalt(length: Int): String {
    if (length <= 0) return ""
    val bytes = ByteArray(length)
    SecureRandom().nextBytes(bytes)
    return bytes.joinToString("") { "%02x".format(it) }.substring(0, length)
  }

  /**
   * Returns the hash of [input] using the given [algorithm].
   * [algorithm] must be one of "sha-256", "sha-384", "sha-512" (case-insensitive).
   */
  fun hash(input: ByteArray, algorithm: String): ByteArray {
    val javaAlg = hashAlgorithmName(algorithm)
    return MessageDigest.getInstance(javaAlg).digest(input)
  }

  /**
   * Generates an ephemeral ECDSA key pair for [namedCurve] ("P-256", "P-384", "P-521").
   * Returns raw (unsigned) coordinate bytes for x, y, and d.
   */
  fun generateEphemeralKeyPair(namedCurve: String): EphemeralKeyPair {
    val javaName = javaECCurveName(namedCurve)
    val coordSize = ecCurveCoordSize(namedCurve)

    val keyPairGenerator = KeyPairGenerator.getInstance("EC")
    keyPairGenerator.initialize(ECGenParameterSpec(javaName), SecureRandom())
    val keyPair = keyPairGenerator.generateKeyPair()

    val ecPublicKey = keyPair.public as ECPublicKey
    val ecPrivateKey = keyPair.private as ECPrivateKey

    return EphemeralKeyPair(
      namedCurve = namedCurve,
      publicX = BigIntegers.asUnsignedByteArray(coordSize, ecPublicKey.w.affineX),
      publicY = BigIntegers.asUnsignedByteArray(coordSize, ecPublicKey.w.affineY),
      privateD = BigIntegers.asUnsignedByteArray(coordSize, ecPrivateKey.s)
    )
  }

  /**
   * Signs [data] with the EC private key whose scalar is [privateD].
   * Returns the signature in IEEE P1363 format (raw R‖S).
   */
  fun sign(
    data: ByteArray,
    privateD: ByteArray,
    namedCurve: String,
    hashAlgorithm: String
  ): ByteArray {
    val coordSize = ecCurveCoordSize(namedCurve)
    val javaName = javaECCurveName(namedCurve)

    val ecSpec = ecParameterSpec(javaName)
    val privateKey = KeyFactory.getInstance("EC")
      .generatePrivate(ECPrivateKeySpec(BigInteger(1, privateD), ecSpec))

    val signer = Signature.getInstance(ecdsaAlgorithmName(hashAlgorithm))
    signer.initSign(privateKey)
    signer.update(data)
    return derToRawSignature(signer.sign(), coordSize)
  }

  /**
   * Verifies an IEEE P1363 [signature] (raw R‖S) against [data]
   * using the EC public key whose coordinates are [publicX] and [publicY].
   * Returns true when the signature is valid.
   */
  fun verify(
    data: ByteArray,
    signature: ByteArray,
    publicX: ByteArray,
    publicY: ByteArray,
    namedCurve: String,
    hashAlgorithm: String
  ): Boolean {
    val coordSize = ecCurveCoordSize(namedCurve)
    val javaName = javaECCurveName(namedCurve)

    val xBI = BigInteger(1, publicX)
    val yBI = BigInteger(1, publicY)
    val ecSpec = ecParameterSpec(javaName)
    val publicKey = KeyFactory.getInstance("EC")
      .generatePublic(ECPublicKeySpec(ECPoint(xBI, yBI), ecSpec))

    val derSignature = rawToDerSignature(signature, coordSize)

    val verifier = Signature.getInstance(ecdsaAlgorithmName(hashAlgorithm))
    verifier.initVerify(publicKey)
    verifier.update(data)
    return verifier.verify(derSignature)
  }

  // ─── Private helpers ───────────────────────────────────────────────────────

  private fun ecCurveCoordSize(namedCurve: String): Int = when (namedCurve) {
    "P-256" -> 32
    "P-384" -> 48
    "P-521" -> 66
    else -> throw IllegalArgumentException("Unsupported curve: $namedCurve")
  }

  private fun javaECCurveName(namedCurve: String): String = when (namedCurve) {
    "P-256" -> "secp256r1"
    "P-384" -> "secp384r1"
    "P-521" -> "secp521r1"
    else -> throw IllegalArgumentException("Unsupported curve: $namedCurve")
  }

  private fun ecParameterSpec(javaName: String): ECParameterSpec {
    val params = AlgorithmParameters.getInstance("EC")
    params.init(ECGenParameterSpec(javaName))
    return params.getParameterSpec(ECParameterSpec::class.java)
  }

  internal fun hashAlgorithmName(algorithm: String): String =
    when (algorithm.lowercase().replace("-", "")) {
      "sha256" -> "SHA-256"
      "sha384" -> "SHA-384"
      "sha512" -> "SHA-512"
      else -> throw IllegalArgumentException("Unsupported hash algorithm: $algorithm")
    }

  private fun ecdsaAlgorithmName(hashAlgorithm: String): String =
    when (hashAlgorithm.lowercase().replace("-", "")) {
      "sha256" -> "SHA256withECDSA"
      "sha384" -> "SHA384withECDSA"
      "sha512" -> "SHA512withECDSA"
      else -> throw IllegalArgumentException("Unsupported hash algorithm: $hashAlgorithm")
    }

  /** Converts a DER-encoded ECDSA signature to IEEE P1363 format (R‖S). */
  private fun derToRawSignature(der: ByteArray, coordSize: Int): ByteArray {
    val seq = ASN1Sequence.getInstance(der)
    val r = (seq.getObjectAt(0) as ASN1Integer).positiveValue
    val s = (seq.getObjectAt(1) as ASN1Integer).positiveValue
    val raw = ByteArray(coordSize * 2)
    BigIntegers.asUnsignedByteArray(coordSize, r).copyInto(raw, 0)
    BigIntegers.asUnsignedByteArray(coordSize, s).copyInto(raw, coordSize)
    return raw
  }

  /** Converts an IEEE P1363 signature (R‖S) to DER encoding. */
  private fun rawToDerSignature(raw: ByteArray, coordSize: Int): ByteArray {
    val r = BigInteger(1, raw.copyOfRange(0, coordSize))
    val s = BigInteger(1, raw.copyOfRange(coordSize, coordSize * 2))
    val vec = ASN1EncodableVector()
    vec.add(ASN1Integer(r))
    vec.add(ASN1Integer(s))
    return DERSequence(vec).encoded
  }
}
