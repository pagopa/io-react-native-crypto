package com.pagopa.ioreactnativecrypto

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.KeyProperties.SECURITY_LEVEL_STRONGBOX
import android.security.keystore.KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
import android.util.Base64
import androidx.annotation.RequiresApi
import com.facebook.react.bridge.*
import java.security.*
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.ECGenParameterSpec
import java.security.spec.InvalidKeySpecException

class IoReactNativeCryptoModule(reactContext: ReactApplicationContext) :
  ReactContextBaseJavaModule(reactContext) {

  override fun getName(): String {
    return NAME
  }

  @RequiresApi(Build.VERSION_CODES.M)
  private var keyConfig = KeyConfig.EC_P_256

  // Example method
  // See https://reactnative.dev/docs/native-modules-android
  @ReactMethod
  fun multiply(a: Double, b: Double, promise: Promise) {
    promise.resolve(a * b)
  }

  @ReactMethod
  fun generate(keyTag: String, promise: Promise) {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
      val keyPairGenerator = KeyPairGenerator.getInstance(
        keyConfig.algorithm,
        KEYSTORE_PROVIDER
      )
      val keySpec: AlgorithmParameterSpec
      KeyGenParameterSpec.Builder(
        keyTag, KeyProperties.PURPOSE_SIGN
      ).apply {
        keyConfig.algorithmParam?.let {
          if (keyConfig == KeyConfig.EC_P_256) {
            setAlgorithmParameterSpec(ECGenParameterSpec(it))
          }
        }
        setDigests(
          KeyProperties.DIGEST_SHA256,
          //KeyProperties.DIGEST_SHA384,
          KeyProperties.DIGEST_SHA512
        )
        // https://www.mail-archive.com/android-developers@googlegroups.com/msg241873.html
        // Caused by: java.security.InvalidKeyException: Keystore operation failed
        // android.security.KeyStoreException: Incompatible padding mode
        //setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
        setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS)
        // Only permit the private key to be used if the user authenticated
        // within the last five minutes.
        //.setUserAuthenticationRequired(true)
        //.setUserAuthenticationValidityDurationSeconds(5 * 60)
        keySpec = build()
      }
      keyPairGenerator.initialize(keySpec)
      val keyPair = keyPairGenerator.generateKeyPair()
      if (keyConfig == KeyConfig.EC_P_256 && !isKeyHardwareBacked(keyTag)) {
        keyConfig = KeyConfig.RSA
        return generate(keyTag, promise)
      } else if (!isKeyHardwareBacked(keyTag)) {
        return promise.reject(Exception("Unsupported device."))
      }
      val publicKey = keyPair.public
      publicKeyToJwk(publicKey)?.let {
        return promise.resolve(it)
      }
      return promise.reject(Exception("Wrong key config $keyConfig."))
    } else {
      return promise.reject(Exception("API level not supported."))
    }
  }

  /**
   * Return a JWK representation of the PublicKey as for this RFC:
   * https://www.rfc-editor.org/rfc/rfc7517
   *
   * For the EC key encoded X.509fFormat we have:
   *
   * https://www.openssl.org/docs/man1.1.1/man1/openssl-asn1parse.html
   * openssl asn1parse -in ec-pk.pem
   * 0:d=0  hl=2 l=  89 cons: SEQUENCE
   * 2:d=1  hl=2 l=  19 cons: SEQUENCE
   * 4:d=2  hl=2 l=   7 prim: OBJECT            :id-ecPublicKey
   * 13:d=2  hl=2 l=   8 prim: OBJECT            :prime256v1
   * 23:d=1  hl=2 l=  66 prim: BIT STRING

   * https://www.rfc-editor.org/rfc/rfc3279#section-2.3.5 (identifiers)
   * https://www.rfc-editor.org/rfc/rfc5480#section-2

   * In the X.509 certificate, the subjectPublicKeyInfo field has the
   * SubjectPublicKeyInfo type, which has the following ASN.1 syntax:

   * SubjectPublicKeyInfo  ::=  SEQUENCE  {
   *  algorithm         AlgorithmIdentifier,
   *  subjectPublicKey  BIT STRING
   * }

   * The fields in SubjectPublicKeyInfo have the following meanings:

   * o algorithm is the algorithm identifier and parameters for the ECC
   * public key.

   * o subjectPublicKey is the ECC public key.
   *
   * From https://www.rfc-editor.org/rfc/rfc5480#section-2.2
   *
   * The subjectPublicKey from SubjectPublicKeyInfo is the ECC public key.
   * ECC public keys have the following syntax:
   *
   * ECPoint ::= OCTET STRING
   *
   * For JWK see:
   *  - https://www.iana.org/assignments/jose/jose.xhtml#web-key-parameters
   *  - https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms
   */
  @RequiresApi(Build.VERSION_CODES.M)
  private fun publicKeyToJwk(key: PublicKey): NativeMap? {
    val nativeMap = WritableNativeMap()

    if (key is ECPublicKey) {
      // https://developer.android.com/reference/java/security/interfaces/ECPublicKey
      // https://www.rfc-editor.org/rfc/rfc6025.html#section-2.1.2
      // The subjectPublicKey of an EC key is an ECPoint that is `w` field of the `ECPublicKey`
      val ecKey = key.w

      // https://www.rfc-editor.org/rfc/rfc7517#section-3
      nativeMap.putString("kty", KeyConfig.EC_P_256.jwkKty)
      nativeMap.putString("crv", KeyConfig.EC_P_256.jwkCrv)
      nativeMap.putString(
        "x",
        base64NoWrap(ecKey.affineX.toByteArray())
      )
      nativeMap.putString(
        "y",
        base64NoWrap(ecKey.affineY.toByteArray())
      )
      return nativeMap
    } else if (key is RSAPublicKey) {
      // https://developer.android.com/reference/java/security/interfaces/RSAPublicKey
      // https://www.rfc-editor.org/rfc/rfc7517#appendix-A.1
      nativeMap.putString("kty", KeyConfig.RSA.jwkKty)
      nativeMap.putString("alg", KeyConfig.RSA.jwkAlg)
      nativeMap.putString(
        "n",
        base64NoWrap(key.modulus.toByteArray())
      )
      nativeMap.putString(
        "e",
        base64NoWrap(key.publicExponent.toByteArray())
      )
      return nativeMap
    }
    return null
  }

  @RequiresApi(Build.VERSION_CODES.M)
  private fun isKeyHardwareBacked(keyTag: String): Boolean {
    getKeyPair(keyTag)?.private?.let {
      return isKeyHardwareBacked(it)
    }
    return false
  }

  @RequiresApi(Build.VERSION_CODES.M)
  private fun isKeyHardwareBacked(key: PrivateKey): Boolean {
    val factory = KeyFactory.getInstance(
      key.algorithm,
      KEYSTORE_PROVIDER
    )
    val keyInfo: KeyInfo
    try {
      keyInfo = factory.getKeySpec(key, KeyInfo::class.java)
      println("Alias: ${keyInfo.keystoreAlias}")
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        // https://developer.android.com/reference/android/security/keystore/KeyProperties#SECURITY_LEVEL_SOFTWARE
        return keyInfo.securityLevel == SECURITY_LEVEL_TRUSTED_ENVIRONMENT
          || keyInfo.securityLevel == SECURITY_LEVEL_STRONGBOX
      } else {
        @Suppress("DEPRECATION")
        return keyInfo.isInsideSecureHardware
      }
    } catch (e: InvalidKeySpecException) {
      return false
    }
  }

  @ReactMethod
  fun getPublicKey(keyTag: String, promise: Promise) {
    // The key pair can also be obtained from the Android Keystore any time as follows:
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
      getKeyPair(keyTag)?.let {
        return promise.resolve(publicKeyToJwk(it.public))
      }
      return promise.reject(Exception("Public key not found on device."))
    } else {
      return promise.reject(Exception("API level not supported."))
    }
  }

  private fun getKeyPair(keyTag: String): KeyPair? {
    // The key pair can also be obtained from the Android Keystore any time as follows:
    val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER)
    keyStore.load(null)
    val privateKey = keyStore.getKey(keyTag, null) as? PrivateKey
    privateKey?.also {
      val publicKey = keyStore.getCertificate(keyTag).publicKey
      return KeyPair(publicKey, it)
    }
    return null
  }

  companion object {
    const val NAME = "IoReactNativeCrypto"
    const val KEYSTORE_PROVIDER = "AndroidKeyStore"

    private fun base64NoWrap(bytes: ByteArray): String {
      return Base64.encodeToString(bytes, Base64.NO_WRAP)
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private enum class KeyConfig(
      val algorithm: String,
      val algorithmParam: String?,
      val signature: String,
      val hash: String,
      val jwkKty: String,
      val jwkCrv: String?,
      val jwkAlg: String?
    ) {
      EC_P_256(
        jwkKty = "EC",
        jwkCrv = "P-256",
        jwkAlg = null,
        algorithm = KeyProperties.KEY_ALGORITHM_EC,
        algorithmParam = "secp256r1",
        signature = "SHA256withECDSA",
        hash = "SHA-256",
      ),
      RSA(
        jwkKty = "RSA",
        jwkAlg = "RS256",
        jwkCrv = null,
        algorithm = KeyProperties.KEY_ALGORITHM_RSA,
        algorithmParam = null,
        signature = "SHA256withRSA/PSS",
        hash = "SHA-256",
      )
    }
  }
}
