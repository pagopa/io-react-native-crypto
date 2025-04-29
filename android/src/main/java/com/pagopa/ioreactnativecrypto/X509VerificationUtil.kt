package com.pagopa.ioreactnativecrypto

import android.os.Build
import android.util.Base64
import android.util.Log
import androidx.annotation.RequiresApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.DERIA5String
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.x509.CRLDistPoint
import org.bouncycastle.asn1.x509.DistributionPoint
import org.bouncycastle.asn1.x509.DistributionPointName
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import java.io.ByteArrayInputStream
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.security.cert.CRLException
import java.security.cert.CertPathValidator
import java.security.cert.CertPathValidatorException
import java.security.cert.CertStore
import java.security.cert.CertificateException
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateFactory
import java.security.cert.CertificateNotYetValidException
import java.security.cert.CollectionCertStoreParameters
import java.security.cert.PKIXBuilderParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509CRL
import java.security.cert.X509CertSelector
import java.security.cert.X509Certificate
import java.util.Date

/**
 * Configuration options for X.509 certificate verification.
 *
 * @property connectTimeout Network connection timeout in milliseconds.
 * @property readTimeout Network read timeout in milliseconds.
 */
data class X509VerificationOptions(
  val connectTimeout: Int = 15000, // Default 15 seconds
  val readTimeout: Int = 15000     // Default 15 seconds
)

/**
 * Utility class for X.509 certificate validation, including chain verification and CRL checks.
 * Policy: Revocation is checked only if CRL Distribution Points are present in the chain.
 * Compatible with Android API Level 23+.
 */
object X509VerificationUtils {

  private const val TAG = "X509Verification"
  private const val CERT_TYPE = "X.509"

  /**
   * Represents the status of the certificate chain verification process.
   */
  enum class ValidationStatus {
    VALID,                      // Chain is valid and trusted (revocation checked if CDPs present).
    INVALID_CHAIN_PATH,         // Basic chain path validation failed (e.g., signature, structure, or revocation issue on API < 24).
    INVALID_TRUST_ANCHOR,       // The provided trust anchor is invalid or doesn't match the chain.
    CERTIFICATE_EXPIRED,        // A certificate in the chain has expired.
    CERTIFICATE_NOT_YET_VALID,  // A certificate in the chain is not yet valid.
    CERTIFICATE_REVOKED,        // A certificate in the chain has been revoked according to a CRL (API 24+).
    CRL_FETCH_FAILED,           // Failed to download/access/validate a required CRL (when CDPs were present). Could also indicate undetermined revocation status on API 24+.
    CRL_PARSE_FAILED,           // Failed to parse a downloaded CRL.
    CRL_EXPIRED,                // A required CRL has expired.
    CRL_SIGNATURE_INVALID,      // The signature on a CRL is invalid.
    VALIDATION_ERROR            // An unexpected error occurred during validation.
  }

  /**
   * Holds the result of the certificate validation process.
   *
   * @property isValid True if the certificate chain is valid and trusted, false otherwise.
   * @property status The detailed status code indicating the outcome or reason for failure.
   * @property errorMessage A descriptive message, especially in case of failure.
   * @property failingCertificate The certificate that caused the validation failure, if applicable.
   */
  data class ValidationResult(
    val isValid: Boolean,
    val status: ValidationStatus,
    val errorMessage: String? = null,
    val failingCertificate: X509Certificate? = null
  )

  /**
   * Verifies a certificate chain against a trust anchor.
   * Revocation checks using CRLs are performed *only if* CRL Distribution Points (CDPs)
   * are specified in the certificates within the chain.
   *
   * @param certChainBase64 List of Base64 encoded certificates, starting with the end-entity cert and ending with the CA cert.
   * @param trustAnchorCertBase64 Base64 encoded trust anchor (CA) certificate.
   * @param options Configuration for network timeouts.
   * @return A [ValidationResult] indicating the outcome.
   */
  suspend fun verifyCertificateChain(
    certChainBase64: List<String>,
    trustAnchorCertBase64: String,
    options: X509VerificationOptions
  ): ValidationResult {
    if (certChainBase64.isEmpty()) {
      return ValidationResult(false, ValidationStatus.INVALID_CHAIN_PATH, "Certificate chain is empty.")
    }

    val certificateFactory: CertificateFactory
    val trustAnchorCert: X509Certificate
    val certificateChain: List<X509Certificate>
    val trustAnchor: TrustAnchor

    // --- 1. Decode Certificates and Trust Anchor ---
    try {
      certificateFactory = CertificateFactory.getInstance(CERT_TYPE)
      val trustAnchorBytes = Base64.decode(trustAnchorCertBase64, Base64.DEFAULT)
      trustAnchorCert = certificateFactory.generateCertificate(ByteArrayInputStream(trustAnchorBytes)) as X509Certificate
      trustAnchor = TrustAnchor(trustAnchorCert, null)

      certificateChain = certChainBase64.map { certBase64 ->
        val certBytes = Base64.decode(certBase64, Base64.DEFAULT)
        certificateFactory.generateCertificate(ByteArrayInputStream(certBytes)) as X509Certificate
      }

      // Check if the last certificate in the chain was issued by the trust anchor
      val lastCertInChain = certificateChain.lastOrNull()
        ?: return ValidationResult(false, ValidationStatus.INVALID_CHAIN_PATH, "Certificate chain is effectively empty after decoding.")
      // Allow the chain to end with the trust anchor itself OR a cert issued by the trust anchor.
      if (!lastCertInChain.encoded.contentEquals(trustAnchorCert.encoded) &&
        lastCertInChain.issuerX500Principal != trustAnchorCert.subjectX500Principal) {
        return ValidationResult(false, ValidationStatus.INVALID_TRUST_ANCHOR, "Last certificate in chain not issued by trust anchor.")
      }

    } catch (e: Exception) {
      val (status, message) = when(e) {
        is CertificateException -> ValidationStatus.VALIDATION_ERROR to "Failed to parse certificates: ${e.message}"
        is IllegalArgumentException -> ValidationStatus.VALIDATION_ERROR to "Invalid Base64 encoding: ${e.message}"
        else -> ValidationStatus.VALIDATION_ERROR to "Unexpected error preparing certificates: ${e.message}"
      }
      return ValidationResult(false, status, message)
    }

    // --- 2. Check Validity Periods ---
    val now = Date()
    for (cert in certificateChain) {
      try {
        cert.checkValidity(now)
      } catch (e: CertificateExpiredException) {
        return ValidationResult(false, ValidationStatus.CERTIFICATE_EXPIRED, "Certificate expired: ${cert.subjectX500Principal}", cert)
      } catch (e: CertificateNotYetValidException) {
        return ValidationResult(false, ValidationStatus.CERTIFICATE_NOT_YET_VALID, "Certificate not yet valid: ${cert.subjectX500Principal}", cert)
      }
    }

    // --- 3. Determine if Revocation Check is Needed and Fetch CRLs ---
    val anyCertHasCdp = certificateChain.any { hasCrlDistributionPoint(it) }
    var crls: List<X509CRL> = emptyList()
    val performRevocationCheck: Boolean

    if (anyCertHasCdp) {
      try {
        crls = fetchCrlsForChain(certificateFactory, certificateChain, trustAnchorCert, options)
        // Proceed with revocation check enabled, even if CRL fetch yielded no usable CRLs.
        performRevocationCheck = true
      } catch (e: CrlFetchException) {
        // If fetchCrlsForChain itself throws (e.g., final error after trying all URLs), fail validation
        return ValidationResult(false, e.status, e.message)
      } catch (e: Exception) {
        // Map generic fetch error to CRL_FETCH_FAILED
        return ValidationResult(false, ValidationStatus.CRL_FETCH_FAILED, "Unexpected error fetching CRLs: ${e.message}")
      }
    } else {
      performRevocationCheck = false
    }

    // --- 4. Perform PKIX Path Validation ---
    try {
      val certPath = certificateFactory.generateCertPath(certificateChain)
      // Use the trust anchor set directly
      val pkixParams = PKIXBuilderParameters(setOf(trustAnchor), X509CertSelector())

      // *** Conditionally enable revocation checking ***
      pkixParams.isRevocationEnabled = performRevocationCheck

      if (performRevocationCheck && crls.isNotEmpty()) {
        val certStore = CertStore.getInstance("Collection", CollectionCertStoreParameters(crls))
        pkixParams.addCertStore(certStore)
      }

      val validator = CertPathValidator.getInstance("PKIX")
      validator.validate(certPath, pkixParams)

      return ValidationResult(true, ValidationStatus.VALID)

    } catch (cpve: CertPathValidatorException) {
      return handleCertPathValidatorException(cpve, certificateChain)
    } catch (e: Exception) {
      return ValidationResult(false, ValidationStatus.VALIDATION_ERROR, "Validation execution error: ${e.message}")
    }
  }

  /**
   * Analyzes a CertPathValidatorException to determine a more specific failure reason,
   * handling API level differences for BasicReason.
   */
  private fun handleCertPathValidatorException(
    e: CertPathValidatorException,
    chain: List<X509Certificate>
  ): ValidationResult {
    val certIndex = e.index
    val failingCert = if (certIndex >= 0 && certIndex < chain.size) chain[certIndex] else null
    val causeMessage = e.cause?.message ?: e.message ?: "No specific cause message"
    val baseErrorMessage = "Validation failed at index $certIndex (Cert: ${failingCert?.subjectX500Principal ?: "N/A"}): $causeMessage"

    // Use BasicReason only on API 24+
    return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
      handleCertPathValidatorExceptionApi24(e, failingCert, baseErrorMessage)
    } else {
      // --- Fallback for API Level 23 ---
      ValidationResult(
        isValid = false,
        status = ValidationStatus.INVALID_CHAIN_PATH, // General failure for older APIs
        errorMessage = baseErrorMessage,
        failingCertificate = failingCert
      )
    }
  }

  /**
   * Handles CertPathValidatorException on API Level 24+ using BasicReason.
   * This function is marked with @RequiresApi(24) and should only be called
   * when Build.VERSION.SDK_INT >= Build.VERSION_CODES.N.
   */
  @RequiresApi(Build.VERSION_CODES.N)
  private fun handleCertPathValidatorExceptionApi24(
    e: CertPathValidatorException,
    failingCert: X509Certificate?,
    baseErrorMessage: String
  ): ValidationResult {
    val reason = e.reason

    val status = when (reason) {
      CertPathValidatorException.BasicReason.REVOKED -> ValidationStatus.CERTIFICATE_REVOKED
      CertPathValidatorException.BasicReason.UNDETERMINED_REVOCATION_STATUS -> ValidationStatus.CRL_FETCH_FAILED // Indicates revocation check couldn't complete
      CertPathValidatorException.BasicReason.EXPIRED -> ValidationStatus.CERTIFICATE_EXPIRED // Should have been caught earlier, but handle defensively
      CertPathValidatorException.BasicReason.NOT_YET_VALID -> ValidationStatus.CERTIFICATE_NOT_YET_VALID // Should have been caught earlier
      CertPathValidatorException.BasicReason.INVALID_SIGNATURE -> ValidationStatus.INVALID_CHAIN_PATH
      CertPathValidatorException.BasicReason.ALGORITHM_CONSTRAINED -> ValidationStatus.INVALID_CHAIN_PATH // Algorithm policy issue
      CertPathValidatorException.BasicReason.UNSPECIFIED -> ValidationStatus.INVALID_CHAIN_PATH // General path issue
      else -> ValidationStatus.INVALID_CHAIN_PATH // Default for any other/new reasons
    }

    val detailedErrorMessage = "$baseErrorMessage (Reason: $reason)"
    return ValidationResult(false, status, detailedErrorMessage, failingCert)
  }


  /** Internal exception class for CRL fetching issues. */
  private class CrlFetchException(val status: ValidationStatus, message: String, cause: Throwable? = null) : IOException(message, cause)

  /**
   * Fetches CRLs specified in the CRL Distribution Points extension of certificates in the chain.
   * It tries multiple URLs if available and validates the CRL's validity period and signature.
   * This is only called if at least one certificate in the chain has a CDP.
   */
  private suspend fun fetchCrlsForChain(
    factory: CertificateFactory,
    chain: List<X509Certificate>,
    trustAnchorCert: X509Certificate, // Needed for CRL signature verification
    options: X509VerificationOptions
  ): List<X509CRL> {

    val uniqueCrlUrls = chain.filter { hasCrlDistributionPoint(it) }
      .flatMap { extractCrlDistributionPoints(it) }
      .distinct()

    if (uniqueCrlUrls.isEmpty()) {
      return emptyList()
    }

    val validCrls = mutableListOf<X509CRL>()
    var lastException: CrlFetchException? = null // Track the last significant error

    for (url in uniqueCrlUrls) {
      try {
        val crlBytes = downloadCrlWithTimeout(url, options)
        val crl = factory.generateCRL(ByteArrayInputStream(crlBytes)) as X509CRL

        // --- CRL Validation ---
        // 1. Check expiry
        if (crl.nextUpdate != null && Date().after(crl.nextUpdate)) {
          throw CrlFetchException(ValidationStatus.CRL_EXPIRED, "CRL from $url is expired (Next Update: ${crl.nextUpdate}).")
        }

        // 2. Verify signature
        val issuerCert = findIssuerCertificate(crl.issuerX500Principal, chain, trustAnchorCert)
          ?: throw CrlFetchException(ValidationStatus.CRL_SIGNATURE_INVALID, "Cannot find issuer certificate for CRL from $url (Issuer: ${crl.issuerX500Principal}).")

        try {
          crl.verify(issuerCert.publicKey)
        } catch (sigEx: Exception) {
          throw CrlFetchException(ValidationStatus.CRL_SIGNATURE_INVALID, "CRL signature verification failed for $url: ${sigEx.message}", sigEx)
        }

        // Add successfully validated CRL
        validCrls.add(crl)

      } catch (e: CrlFetchException) {
        lastException = e // Record the error
      } catch (e: TimeoutCancellationException) {
        lastException = CrlFetchException(ValidationStatus.CRL_FETCH_FAILED, "Timeout downloading CRL from $url", e)
      } catch (e: IOException) { // Network or connection errors
        lastException = CrlFetchException(ValidationStatus.CRL_FETCH_FAILED, "Network error for CRL $url: ${e.message}", e)
      } catch (e: CRLException) { // Parsing errors
        lastException = CrlFetchException(ValidationStatus.CRL_PARSE_FAILED, "Error parsing CRL from $url: ${e.message}", e)
      } catch (e: Exception) { // Other unexpected errors
        lastException = CrlFetchException(ValidationStatus.CRL_FETCH_FAILED, "Unexpected error for CRL $url: ${e.message}", e)
      }
    }

    // If we attempted to fetch CRLs (because CDPs existed) but ended up with none,
    // and there was at least one error during the process, throw the last error.
    if (validCrls.isEmpty() && lastException != null) {
      throw lastException
    }

    return validCrls
  }

  /** Finds the certificate that issued a CRL by matching Subject DN to CRL Issuer DN. */
  private fun findIssuerCertificate(crlIssuer: java.security.Principal, chain: List<X509Certificate>, trustAnchor: X509Certificate): X509Certificate? {
    if (trustAnchor.subjectX500Principal == crlIssuer) {
      return trustAnchor
    }
    return chain.find { it.subjectX500Principal == crlIssuer }
  }

  /** Downloads CRL bytes from a URL with specified timeouts. */
  private suspend fun downloadCrlWithTimeout(url: String, options: X509VerificationOptions): ByteArray {
    return withContext(Dispatchers.IO) {
      withTimeout(options.connectTimeout + options.readTimeout.toLong()) {
        var connection: HttpURLConnection? = null
        try {
          connection = (URL(url).openConnection() as HttpURLConnection).apply {
            connectTimeout = options.connectTimeout
            readTimeout = options.readTimeout
            requestMethod = "GET"
            setRequestProperty("Accept", "application/pkix-crl, */*")
            instanceFollowRedirects = true
          }
          connection.connect()
          val responseCode = connection.responseCode

          if (responseCode == HttpURLConnection.HTTP_OK) {
            connection.inputStream.use { return@withTimeout it.readBytes() }
          } else {
            // Read error stream for details, ensure it's closed
            val errorDetails = connection.errorStream?.use { it.readBytes() }?.toString(Charsets.UTF_8) ?: "No error details"
            throw IOException("CRL download failed: HTTP $responseCode for URL $url. $errorDetails")
          }
        } finally {
          connection?.disconnect()
        }
      }
    }
  }

  /** Checks if a certificate contains the CRL Distribution Points extension (OID 2.5.29.31). */
  private fun hasCrlDistributionPoint(cert: X509Certificate): Boolean {
    return try {
      val oid = Extension.cRLDistributionPoints.id
      cert.getExtensionValue(oid) != null
    } catch (e: Exception) {
      false
    }
  }


  /**
   * Extracts CRL Distribution Point URLs (HTTP/HTTPS only) from the certificate extension.
   * Uses BouncyCastle for robust ASN.1 parsing.
   */
  private fun extractCrlDistributionPoints(cert: X509Certificate): List<String> {
    val urls = mutableListOf<String>()
    try {
      val oid = Extension.cRLDistributionPoints.id // OID for CRL Distribution Points
      val extensionValue = cert.getExtensionValue(oid) ?: return emptyList() // Return empty if extension not present

      // The extension value is SEQUENCE (CRLDistPoints) wrapped in an OCTET STRING.
      // 1. Parse the outer OCTET STRING
      val derOctetString = ASN1Primitive.fromByteArray(extensionValue) as? DEROctetString
        ?: return emptyList()

      // 2. Get the inner bytes (the actual CRLDistPoint sequence)
      val crlDpBytes = derOctetString.octets

      // 3. Parse the inner bytes specifically as CRLDistPoint
      val asn1DistPoint = CRLDistPoint.getInstance(ASN1Primitive.fromByteArray(crlDpBytes))
        ?: return emptyList()

      // 4. Iterate through the distribution points
      for (dp: DistributionPoint in asn1DistPoint.distributionPoints) {
        val dpName = dp.distributionPoint ?: continue

        if (dpName.type == DistributionPointName.FULL_NAME) {
          val generalNames = GeneralNames.getInstance(dpName.name)
          for (name: GeneralName in generalNames.names) {
            if (name.tagNo == GeneralName.uniformResourceIdentifier) {
              // Extract the URI string
              val uri = DERIA5String.getInstance(name.name).string
              if (uri.startsWith("http://", ignoreCase = true) || uri.startsWith("https://", ignoreCase = true)) {
                urls.add(uri)
              }
            }
          }
        }
      }
    } catch (e: Exception) {
      // Catch potential exceptions during parsing (e.g., ClassCastException, IOException)
      Log.e(TAG, "Error parsing CRL DP for cert: ${cert.subjectX500Principal}", e)
    }
    return urls.distinct() // Return unique URLs found
  }
}
