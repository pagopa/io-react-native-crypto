package com.pagopa.ioreactnativecrypto

import android.util.Base64
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.bouncycastle.asn1.DERIA5String
import org.bouncycastle.asn1.x509.CRLDistPoint
import org.bouncycastle.asn1.x509.DistributionPointName
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder
import java.io.ByteArrayInputStream
import java.net.HttpURLConnection
import java.net.URL
import java.security.cert.CRLException
import java.security.cert.CertPathValidator
import java.security.cert.CertPathValidatorException
import java.security.cert.CertStore
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateFactory
import java.security.cert.CertificateNotYetValidException
import java.security.cert.CollectionCertStoreParameters
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509CRL
import java.security.cert.X509Certificate
import java.util.Date

data class X509VerificationOptions (
  val connectTimeout: Int = 15000,
  val readTimeout: Int = 15000
)

/**
 * Utility class for X.509 certificate validations
 */
object X509VerificationUtils {

  /**
   * Validation status for certificate chain verification
   */
  enum class CertificateValidationStatus {
    VALID,
    INVALID_CHAIN,
    EXPIRED,
    NOT_YET_VALID,
    REVOKED,
    VALIDATION_ERROR,
    CRL_NOT_DEFINED,
    CRL_EXPIRED,
    CRL_DOWNLOAD_ERROR,
    CRL_GENERATION_ERROR
  }

  sealed class VerificationException: Exception() {
    data object CRLNotDefined: VerificationException() {
      private fun readResolve(): Any = CRLNotDefined
    }
    data object CRLExpired: VerificationException() {
      private fun readResolve(): Any = CRLExpired
    }
    data object CRLDownloadError: VerificationException() {
      private fun readResolve(): Any = CRLDownloadError
    }
  }

  data class CertificateValidationResult(
    val isValid: Boolean,
    val validationStatus: CertificateValidationStatus,
    val errorMessage: String? = null
  )

  private fun generateErrorMessage(
    status: CertificateValidationStatus,
    certificate: X509Certificate? = null,
    exception: Throwable? = null,
    revocationDate: Date? = null,
    customMessage: String? = null
  ): String? {
    return when (status) {
      CertificateValidationStatus.VALID ->
        null

      CertificateValidationStatus.INVALID_CHAIN -> {
        val baseMsg = "Certificate chain validation failed"
        val reason = customMessage ?: exception?.message
        if (!reason.isNullOrBlank()) "$baseMsg: $reason" else baseMsg
      }

      CertificateValidationStatus.EXPIRED ->
        "Certificate expired: ${certificate?.subjectX500Principal ?: "Unknown certificate"}"

      CertificateValidationStatus.NOT_YET_VALID ->
        "Certificate not yet valid: ${certificate?.subjectX500Principal ?: "Unknown certificate"}"

      CertificateValidationStatus.REVOKED -> {
        val subject = certificate?.subjectX500Principal ?: "Unknown certificate"
        val dateInfo = if (revocationDate != null) ", revocation date: $revocationDate" else ""
        "Certificate revoked: $subject $dateInfo"
      }

      CertificateValidationStatus.VALIDATION_ERROR ->
        "Validation error: ${exception?.message ?: "An unknown error occurred during validation"}"

      CertificateValidationStatus.CRL_NOT_DEFINED -> {
        val subjectInfo = if(certificate != null) " in certificate ${certificate.subjectX500Principal}" else ""
        "CRL distribution point not defined $subjectInfo."
      }

      CertificateValidationStatus.CRL_EXPIRED -> {
        "CRL used for validation has expired."
      }
      CertificateValidationStatus.CRL_GENERATION_ERROR -> {
        "CRL generation failed."
      }
      CertificateValidationStatus.CRL_DOWNLOAD_ERROR -> {
        "CRL download failed."
      }
    }
  }

  private fun extractCrlDistributionPoints(cert: X509Certificate): List<String> {
    try {
      val bcCert = JcaX509CertificateHolder(cert)
      val distPoints = bcCert.getExtension(Extension.cRLDistributionPoints)
        ?: return emptyList()

      val dpObj = CRLDistPoint.getInstance(distPoints.parsedValue)
      val urls = mutableListOf<String>()

      for (dp in dpObj.distributionPoints) {
        val distPointName = dp.distributionPoint
        if (distPointName != null && distPointName.type == DistributionPointName.FULL_NAME) {
          val generalNames = distPointName.name as GeneralNames
          for (generalName in generalNames.names) {
            if (generalName.tagNo == GeneralName.uniformResourceIdentifier) {
              val uri = DERIA5String.getInstance(generalName.name).string
              urls.add(uri)
            }
          }
        }
      }
      return urls
    } catch (e: Exception) {
      Log.e("CertificateValidation", "Error extracting CRL distribution points", e)
      return emptyList()
    }
  }

  /**
   * Downloads a CRL from a URL.
   *
   * @param url The URL to download the CRL from.
   * @param connectTimeout Optional connection timeout (default 15000ms)
   * @param readTimeout Optional read timeout (default 15000ms)
   * @return The downloaded CRL as a byte array, or null if download failed.
   */
  private suspend fun downloadCrl(url: String, options: X509VerificationOptions): ByteArray {
    return withContext(Dispatchers.IO) {
      val connection = (URL(url).openConnection() as HttpURLConnection).also {
        it.connectTimeout = options.connectTimeout
        it.readTimeout = options.readTimeout
        it.requestMethod = "GET"
      }

      val responseCode = connection.responseCode
      if (responseCode == HttpURLConnection.HTTP_OK) {
        connection.inputStream.use { it.readBytes() }
      } else {
        throw Exception("CRL Download failed with status code $responseCode for URL $url")
      }
    }
  }

  private suspend fun downloadCertificateCrl(
    factory: CertificateFactory,
    cert: X509Certificate,
    options: X509VerificationOptions
  ): X509CRL? {
    val crlUrls = extractCrlDistributionPoints(cert)
    if (crlUrls.isEmpty()) {
      return null
    }

    for (url in crlUrls) {
      try {
        val crlBytes = downloadCrl(url, options)
        val crl = factory.generateCRL(ByteArrayInputStream(crlBytes)) as X509CRL

        // Check if CRL itself is valid (not expired)
        // TODO: verify if we need to strictly check for this condition
        if (crl.nextUpdate != null && Date().after(crl.nextUpdate)) {
          throw VerificationException.CRLExpired
        }
        return crl
      } catch (e: Exception) {
        when (e) {
          is VerificationException.CRLExpired -> CertificateValidationStatus.CRL_EXPIRED
          is CRLException -> CertificateValidationStatus.CRL_GENERATION_ERROR
        }
      }
    }
    throw VerificationException.CRLDownloadError
  }

  /**
   * Verifies the certificate chain provided against the trust anchor certificate,
   * checking validity dates and revocation status using CRLs from distribution points.
   *
   * @param certChainBase64 A list of Base64-encoded certificates representing the chain.
   * @param trustAnchorCertBase64 A Base64-encoded trust anchor certificate.
   * @return A CertificateValidationResult with validation status and details.
   */
  suspend fun verifyCertificateChain(
    certChainBase64: List<String>,
    trustAnchorCertBase64: String,
    options: X509VerificationOptions
  ): CertificateValidationResult {
    try {

      val trustAnchorBytes = Base64.decode(trustAnchorCertBase64, Base64.DEFAULT)
      val lastCertBytes = certChainBase64.lastOrNull() ?. let {
        Base64.decode(it, Base64.DEFAULT)
      }

      if (!lastCertBytes.contentEquals(trustAnchorBytes)) {
        val status = CertificateValidationStatus.INVALID_CHAIN
        return CertificateValidationResult(
          isValid = false,
          validationStatus = status,
          errorMessage = generateErrorMessage(status, customMessage = "The provided trust anchor does not match the last certificate in the chain.")
        )
      }

      val certificateFactory = CertificateFactory.getInstance("X.509")
      val trustAnchorCert = certificateFactory.generateCertificate(
        ByteArrayInputStream(trustAnchorBytes)
      ) as X509Certificate
      val trustAnchor = TrustAnchor(trustAnchorCert, null)

      val certificateChain = certChainBase64.map { certBase64 ->
        val certBytes = Base64.decode(certBase64, Base64.DEFAULT)
        certificateFactory.generateCertificate(ByteArrayInputStream(certBytes)) as X509Certificate
      }

      val now = Date()
      for (cert in certificateChain) {
        try {
          cert.checkValidity(now)
        } catch (e: CertificateExpiredException) {
          val status = CertificateValidationStatus.EXPIRED
          return CertificateValidationResult(
            isValid = false,
            validationStatus = status,
            errorMessage = generateErrorMessage(status, certificate = cert)
          )
        } catch (e: CertificateNotYetValidException) {
          val status = CertificateValidationStatus.NOT_YET_VALID
          return CertificateValidationResult(
            isValid = false,
            validationStatus = status,
            errorMessage = generateErrorMessage(status, certificate = cert)
          )
        }
      }

      // Collect all CRLs from distribution points in the certificate chain
      val crls = mutableListOf<X509CRL>()
      for (cert in certificateChain) {
        downloadCertificateCrl(certificateFactory, cert, options)?.let { crls.add(it) }
      }

      // Check each certificate against the CRLs
      for (cert in certificateChain) {
        for (crl in crls) {
          // Only check against CRLs issued by the certificate's issuer
          if (cert.issuerX500Principal == crl.issuerX500Principal) {
            val revokedCert = crl.getRevokedCertificate(cert)
            if (revokedCert != null) {
              return CertificateValidationResult(
                isValid = false,
                validationStatus = CertificateValidationStatus.REVOKED,
                errorMessage = "Certificate revoked: ${cert.subjectX500Principal}, revocation date: ${revokedCert.revocationDate}"
              )
            }
          }
        }
      }

      // Create a CertPath from the certificate chain.
      val certPath = certificateFactory.generateCertPath(certificateChain)

      // Set up PKIX parameters using the trust anchor.
      val pkixParams = PKIXParameters(setOf(trustAnchor)).also {
        it.isRevocationEnabled = crls.isNotEmpty()
      }

      // Add CRLs to CertStore if any were downloaded
      if (crls.isNotEmpty()) {
        val certStore = CertStore.getInstance(
          "Collection",
          CollectionCertStoreParameters(crls)
        )
        pkixParams.addCertStore(certStore)
      }

      // Validate the certificate chain.
      val validator = CertPathValidator.getInstance("PKIX")
      validator.validate(certPath, pkixParams)

      return CertificateValidationResult(
        isValid = true,
        validationStatus = CertificateValidationStatus.VALID
      )

    } catch (e: CertPathValidatorException) {
      val status = CertificateValidationStatus.INVALID_CHAIN
      return CertificateValidationResult(
        isValid = false,
        validationStatus = status,
        errorMessage = generateErrorMessage(status, exception = e)
      )
    } catch (e: VerificationException) {
      val status = when (e) {
        is VerificationException.CRLExpired -> CertificateValidationStatus.CRL_EXPIRED
        is VerificationException.CRLNotDefined -> CertificateValidationStatus.CRL_NOT_DEFINED
        is VerificationException.CRLDownloadError -> CertificateValidationStatus.CRL_DOWNLOAD_ERROR
      }

      return CertificateValidationResult(
        isValid = false,
        validationStatus = status,
        errorMessage = generateErrorMessage(status)
      )
    } catch (e: Exception) {
      val status = CertificateValidationStatus.VALIDATION_ERROR
      Log.e("CertificateValidation", "An unexpected error occurred during certificate verification", e)
      return CertificateValidationResult(
        isValid = false,
        validationStatus = status,
        errorMessage = generateErrorMessage(status, exception = e)
      )
    }
  }
}
