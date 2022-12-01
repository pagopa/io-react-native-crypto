package com.pagopa.ioreactnativecrypto

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties.*
import android.util.Base64
import android.util.Log
import androidx.annotation.RequiresApi
import com.facebook.react.bridge.*
import java.security.*
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.ECGenParameterSpec

class IoReactNativeCryptoModule(reactContext: ReactApplicationContext) :
  ReactContextBaseJavaModule(reactContext) {

  var threadHanle: Thread? = null

  private val keyStore: KeyStore? by lazy {
    try {
      KeyStore.getInstance(KEYSTORE_PROVIDER).also {
        it.load(null)
      }
    } catch (e: Exception) {
      null
    }
  }

  override fun getName(): String {
    return NAME
  }

  @ReactMethod
  fun generate(keyTag: String, promise: Promise) {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
      generate(KeyConfig.EC_P_256, keyTag, promise)
    } else {
      return ModuleException.API_LEVEL_NOT_SUPPORTED.reject(promise)
    }
  }

  @RequiresApi(Build.VERSION_CODES.M)
  private fun generate(
    keyConfig: KeyConfig, keyTag: String, promise: Promise
  ) {
    // https://developer.android.com/reference/java/security/KeyPairGenerator#generateKeyPair()
    // KeyPairGenerator.generateKeyPair will generate a new key pair every time it is called.
    threadHanle = Thread {
      try {
        for (i in 1..1_000_000_000) {
          var a = i*2
        }
      } catch (e: Exception) {
        //
      }
      if (keyExists(keyTag)) {
        ModuleException.KEY_ALREADY_EXISTS.reject(
          promise, Pair("keyTag", keyTag)
        )
        threadHanle = null
        return@Thread
      }
      val keySpecGenerator = KeyGenParameterSpec.Builder(
        keyTag, PURPOSE_SIGN
      ).apply {
        keyConfig.algorithmParam?.let {
          if (keyConfig == KeyConfig.EC_P_256) {
            setAlgorithmParameterSpec(ECGenParameterSpec(it))
          }
        }
        setDigests(
          DIGEST_SHA256,
        )
        setSignaturePaddings(SIGNATURE_PADDING_RSA_PSS)
      }
      val keySpec: AlgorithmParameterSpec = keySpecGenerator.build()
      val keyPairGenerator = KeyPairGenerator.getInstance(
        keyConfig.algorithm, KEYSTORE_PROVIDER
      ).also { it.initialize(keySpec) }
      val keyPair = keyPairGenerator.generateKeyPair()
      if (!isKeyHardwareBacked(keyTag)) {
        if (deleteKey(keyTag)) {
          if (keyConfig == KeyConfig.EC_P_256) {
            generate(KeyConfig.RSA, keyTag, promise)
            threadHanle = null
            return@Thread
          } else {
            ModuleException.UNSUPPORTED_DEVICE.reject(promise)
            threadHanle = null
            return@Thread
          }
        } else {
          ModuleException.PUBLIC_KEY_DELETION_ERROR.reject(promise)
          threadHanle = null
          return@Thread
        }
      }
      val publicKey = keyPair.public
      publicKeyToJwk(publicKey)?.let {
        promise.resolve(it)
        threadHanle = null
        return@Thread
      }
      ModuleException.WRONG_KEY_CONFIGURATION.reject(promise)
      threadHanle = null
      return@Thread
    }
    threadHanle?.start()
  }

  private fun keyExists(keyTag: String) = getKeyPair(keyTag) != null

  /**
   * Return a JWK representation of the PublicKey as for this RFC:
   * https://www.rfc-editor.org/rfc/rfc7517
   *
   * For the EC key encoded X.509 Format we have:
   *
   * https://www.openssl.org/docs/man1.1.1/man1/openssl-asn1parse.html
   * openssl asn1parse -in ec-pk.pem
   * 0:d=0  hl=2 l=  89 cons: SEQUENCE
   * 2:d=1  hl=2 l=  19 cons: SEQUENCE
   * 4:d=2  hl=2 l=   7 prim: OBJECT            :id-ecPublicKey
   * 13:d=2  hl=2 l=   8 prim: OBJECT            :prime256v1
   * 23:d=1  hl=2 l=  66 prim: BIT STRING
   *
   * https://www.rfc-editor.org/rfc/rfc3279#section-2.3.5 (identifiers)
   * https://www.rfc-editor.org/rfc/rfc5480#section-2
   *
   * In the X.509 certificate, the subjectPublicKeyInfo field has the
   * SubjectPublicKeyInfo type, which has the following ASN.1 syntax:
   *
   * SubjectPublicKeyInfo  ::=  SEQUENCE  {
   *  algorithm         AlgorithmIdentifier,
   *  subjectPublicKey  BIT STRING
   * }
   *
   * The fields in SubjectPublicKeyInfo have the following meanings:
   *
   * - algorithm: is the algorithm identifier and parameters for the ECC public key.
   * - subjectPublicKey: is the ECC public key.
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
      nativeMap.putString(JwkFields.KTY.key, KeyConfig.EC_P_256.jwkKty)
      nativeMap.putString(JwkFields.CRV.key, KeyConfig.EC_P_256.jwkCrv)
      nativeMap.putString(
        JwkFields.X.key, ecKey.affineX.toByteArray().base64NoWrap()
      )
      nativeMap.putString(
        JwkFields.Y.key, ecKey.affineY.toByteArray().base64NoWrap()
      )
      return nativeMap
    } else if (key is RSAPublicKey) {
      // https://developer.android.com/reference/java/security/interfaces/RSAPublicKey
      // https://www.rfc-editor.org/rfc/rfc7517#appendix-A.1
      nativeMap.putString(JwkFields.KTY.key, KeyConfig.RSA.jwkKty)
      nativeMap.putString(JwkFields.ALG.key, KeyConfig.RSA.jwkAlg)
      nativeMap.putString(
        JwkFields.N.key, key.modulus.toByteArray().base64NoWrap()
      )
      nativeMap.putString(
        JwkFields.E.key, key.publicExponent.toByteArray().base64NoWrap()
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
    try {
      val factory = KeyFactory.getInstance(
        key.algorithm, KEYSTORE_PROVIDER
      )
      val keyInfo = factory.getKeySpec(key, KeyInfo::class.java)
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        // https://developer.android.com/reference/android/security/keystore/KeyProperties
        return keyInfo.securityLevel == SECURITY_LEVEL_TRUSTED_ENVIRONMENT
          || keyInfo.securityLevel == SECURITY_LEVEL_STRONGBOX
          || keyInfo.securityLevel == SECURITY_LEVEL_UNKNOWN_SECURE
      } else {
        @Suppress("DEPRECATION") return keyInfo.isInsideSecureHardware
      }
    } catch (e: Exception) {
      return false
    }
  }

  @ReactMethod
  fun deletePublicKey(keyTag: String, promise: Promise) {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
      deleteKey(keyTag, promise)
    } else {
      ModuleException.API_LEVEL_NOT_SUPPORTED.reject(promise)
    }
  }

  private fun deleteKey(keyTag: String, promise: Promise? = null): Boolean {
    getKeyPair(keyTag)?.let {
      try {
        if (keyStore != null) {
          keyStore!!.deleteEntry(keyTag)
        } else {
          promise?.let {
            ModuleException.KEYSTORE_LOAD_FAILED.reject(it)
          }
        }
      } catch (e: KeyStoreException) {
        promise?.let {
          ModuleException.PUBLIC_KEY_DELETION_ERROR.reject(
            it, Pair(e.javaClass.name, e.message ?: "")
          )
        }
        return false
      }
    }
    promise?.resolve(true)
    return true
  }

  @ReactMethod
  fun getPublicKey(keyTag: String, promise: Promise) {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
      getKeyPair(keyTag)?.let {
        return promise.resolve(publicKeyToJwk(it.public))
      }
      return ModuleException.PUBLIC_KEY_NOT_FOUND.reject(
        promise, Pair("keyTag", keyTag)
      )
    } else {
      return ModuleException.API_LEVEL_NOT_SUPPORTED.reject(promise)
    }
  }

  @RequiresApi(Build.VERSION_CODES.M)
  @Throws(NoSuchAlgorithmException::class)
  private fun getSignAlgorithm(privateKey: PrivateKey): String {
    // Hardware Backed private keys are only reference to the key store actual key.
    // They don't expose `<EC/RSA>PrivateKey` interface and are only `<EC/RSA>Key`s.
    // Type check `key is <EC/RSA>PrivateKey` does not work, hence the algorithm check below.
    return when (privateKey.algorithm) {
      KEY_ALGORITHM_EC -> {
        KeyConfig.EC_P_256.signature
      }
      KEY_ALGORITHM_RSA -> {
        KeyConfig.RSA.signature
      }
      else -> {
        throw NoSuchAlgorithmException()
      }
    }
  }

  @ReactMethod
  fun signUTF8Text(message: String, keyTag: String, promise: Promise) {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
      getKeyPair(keyTag)?.private?.let {
        try {
          // Unlike iOS this always returns a byte array.
          val messageDataBytes = message.toByteArray(charset = Charsets.UTF_8)
          val signAlgorithm = getSignAlgorithm(it)
          val signature = signData(
            messageDataBytes, it, signAlgorithm
          )
          // `encodeToString` uses "US-ASCII" under the hood
          // which is equivalent to UTF-8 for the first 256 bytes.
          // Base64 does not generate bytes outside this range.
          val signatureBase64 = Base64.encodeToString(signature, Base64.NO_WRAP)
          return promise.resolve(signatureBase64)
        } catch (e: NoSuchAlgorithmException) {
          return ModuleException.INVALID_SIGN_ALGORITHM.reject(promise)
        } catch (e: InvalidKeyException) {
          return ModuleException.WRONG_KEY_CONFIGURATION.reject(promise)
        } catch (e: SignatureException) {
          return ModuleException.UNABLE_TO_SIGN.reject(promise)
        } catch (e: AssertionError) {
          return ModuleException.INVALID_UTF8_ENCODING.reject(promise)
        }
      }
      return ModuleException.PUBLIC_KEY_NOT_FOUND.reject(promise)
    } else {
      ModuleException.API_LEVEL_NOT_SUPPORTED.reject(promise)
    }
  }

  @RequiresApi(Build.VERSION_CODES.M)
  @Throws(
    NoSuchAlgorithmException::class,
    SignatureException::class,
    InvalidKeyException::class
  )
  private fun signData(
    message: ByteArray, privateKey: PrivateKey, signAlgorithm: String
  ): ByteArray {
    val signatureEngine = Signature.getInstance(signAlgorithm)
    signatureEngine.initSign(privateKey)
    signatureEngine.update(message)
    return signatureEngine.sign()
  }

  private fun getKeyPair(keyTag: String): KeyPair? {
    try {
      keyStore?.let {
        val privateKey = it.getKey(keyTag, null) as? PrivateKey
        privateKey?.also { _ ->
          val publicKey = it.getCertificate(keyTag).publicKey
          return KeyPair(publicKey, privateKey)
        }
      }
      return null
    } catch (_: Exception) {
      return null
    }
  }

  companion object {
    const val NAME = "IoReactNativeCrypto"
    const val KEYSTORE_PROVIDER = "AndroidKeyStore"

    @RequiresApi(Build.VERSION_CODES.M)
    private enum class KeyConfig(
      val algorithm: String,
      val algorithmParam: String?,
      val signature: String,
      val jwkKty: String,
      val jwkCrv: String?,
      val jwkAlg: String?
    ) {
      EC_P_256(
        jwkKty = "EC",
        jwkCrv = "P-256",
        jwkAlg = null,
        algorithm = KEY_ALGORITHM_EC,
        algorithmParam = "secp256r1",
        signature = "SHA256withECDSA",
      ),
      RSA(
        jwkKty = "RSA",
        jwkAlg = "RS256",
        jwkCrv = null,
        algorithm = KEY_ALGORITHM_RSA,
        algorithmParam = null,
        signature = "SHA256withRSA/PSS",
      )
    }

    private enum class JwkFields(val key: String) {
      KTY("kty"),
      CRV("crv"),
      ALG("alg"),
      X("x"),
      Y("y"),
      N("n"),
      E("e")
    }

    private enum class ModuleException(
      val ex: Exception
    ) {
      KEY_ALREADY_EXISTS(Exception("KEY_ALREADY_EXISTS")),
      UNSUPPORTED_DEVICE(Exception("UNSUPPORTED_DEVICE")),
      WRONG_KEY_CONFIGURATION(Exception("WRONG_KEY_CONFIGURATION")),
      PUBLIC_KEY_NOT_FOUND(Exception("PUBLIC_KEY_NOT_FOUND")),
      PUBLIC_KEY_DELETION_ERROR(Exception("PUBLIC_KEY_DELETION_ERROR")),
      API_LEVEL_NOT_SUPPORTED(Exception("API_LEVEL_NOT_SUPPORTED")),
      KEYSTORE_LOAD_FAILED(Exception("KEYSTORE_LOAD_FAILED")),
      UNABLE_TO_SIGN(Exception("UNABLE_TO_SIGN")),
      INVALID_UTF8_ENCODING(Exception("INVALID_UTF8_ENCODING")),
      INVALID_SIGN_ALGORITHM(Exception("INVALID_SIGN_ALGORITHM"));

      fun reject(
        promise: Promise, vararg args: Pair<String, String>
      ) {
        exMap(*args).let {
          promise.reject(it.first, ex.message, it.second)
        }
      }

      private fun exMap(vararg args: Pair<String, String>): Pair<String, WritableMap> {
        val writableMap = WritableNativeMap()
        args.forEach { writableMap.putString(it.first, it.second) }
        return Pair(this.ex.message ?: "UNKNOWN", writableMap)
      }
    }
  }
}

fun ByteArray.base64NoWrap(): String {
  return Base64.encodeToString(this, Base64.NO_WRAP)
}
