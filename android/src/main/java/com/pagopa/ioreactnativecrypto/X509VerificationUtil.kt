package com.pagopa.ioreactnativecrypto

import android.util.Base64
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
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
    CRL_EXPIRED
  }

  sealed class VerificationException: Exception() {
    data object CRLNotDefined: VerificationException() {
      private fun readResolve(): Any = CRLNotDefined
    }

    data object CRLExpired: VerificationException() {
      private fun readResolve(): Any = CRLExpired
    }
  }

  /**
   * Result class for certificate chain verification
   */
  data class CertificateValidationResult(
    val isValid: Boolean,
    val validationStatus: CertificateValidationStatus,
    val errorMessage: String? = null
  )

  /**
   * Extracts the CRL distribution point URLs from an X509Certificate using Bouncy Castle.
   *
   * @param cert The X509Certificate to extract from.
   * @return A list of CRL distribution point URLs, or an empty list if none are found.
   */
  private fun extractCrlDistributionPoints(cert: X509Certificate): List<String> {
    try {
      // Create a Bouncy Castle certificate object from the X509Certificate
      val bcCert = JcaX509CertificateHolder(cert)

      // Get the CRL distribution points extension
      val distPoints = bcCert.getExtension(Extension.cRLDistributionPoints)
        ?: return emptyList()

      // Parse the extension value
      val dpObj = CRLDistPoint.getInstance(distPoints.parsedValue)
      val urls = mutableListOf<String>()

      // Process each distribution point
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
   * @return The downloaded CRL as a byte array, or null if download failed.
   */
  private suspend fun downloadCrl(url: String): ByteArray {
    return withContext(Dispatchers.IO) {
      val connection = (URL(url).openConnection() as HttpURLConnection).also {
        it.connectTimeout = 15000
        it.readTimeout = 15000
        it.requestMethod = "GET"
      }

      val responseCode = connection.responseCode
      if (responseCode == HttpURLConnection.HTTP_OK) {
        connection.inputStream.use { it.readBytes() }
      } else {
        throw Exception("CRL Download failed")
      }
    }
  }

  private suspend fun downloadCertificateCrl(
    factory: CertificateFactory,
    cert: X509Certificate
  ): X509CRL {
    val crlUrls = extractCrlDistributionPoints(cert)
    if (crlUrls.isEmpty()) {
      throw VerificationException.CRLNotDefined
    }

    val crlBytes = downloadCrl(crlUrls.first())
    val crl = factory.generateCRL(ByteArrayInputStream(crlBytes)) as X509CRL
    // Check if CRL itself is valid (not expired)
    if (crl.nextUpdate != null && Date().after(crl.nextUpdate)) {
      throw VerificationException.CRLExpired
    }
    return crl
  }

  /**
   * Verifies the certificate chain provided against the trust anchor certificate,
   * checking validity dates and revocation status using CRLs from distribution points.
   *
   * @param certChainBase64 A list of Base64-encoded certificates representing the chain.
   * @param trustAnchorCertBase64 A Base64-encoded trust anchor certificate.
   * @return A CertificateValidationResult with validation status and details.
   */
  private suspend fun verifyCertificateChainAsync(
    certChainBase64: List<String>,
    trustAnchorCertBase64: String
  ): CertificateValidationResult {
    try {

      // Pre-check to verify that the last chain certificate and the TA cert are the same
      if (certChainBase64.last() != trustAnchorCertBase64) {
        return CertificateValidationResult(
          isValid = false,
          validationStatus = CertificateValidationStatus.INVALID_CHAIN,
          errorMessage = "Invalid Trust Anchor certificate"
        )
      }

      // Create a CertificateFactory for X.509 certificates.
      val certificateFactory = CertificateFactory.getInstance("X.509")

      // Decode the trust anchor certificate.
      val trustAnchorBytes = Base64.decode(trustAnchorCertBase64, Base64.DEFAULT)
      val trustAnchorCert = certificateFactory.generateCertificate(
        ByteArrayInputStream(trustAnchorBytes)
      ) as X509Certificate
      val trustAnchor = TrustAnchor(trustAnchorCert, null)

      // Decode each certificate from the certificatesChain.
      val certificateChain = certChainBase64.map { certBase64 ->
        val certBytes = Base64.decode(certBase64, Base64.DEFAULT)
        certificateFactory.generateCertificate(ByteArrayInputStream(certBytes)) as X509Certificate
      }

      // Check certificate validity dates
      val now = Date()
      for (cert in certificateChain) {
        try {
          cert.checkValidity(now)
        } catch (e: CertificateExpiredException) {
          return CertificateValidationResult(
            isValid = false,
            validationStatus = CertificateValidationStatus.EXPIRED,
            errorMessage = "Certificate expired: ${cert.subjectX500Principal}"
          )
        } catch (e: CertificateNotYetValidException) {
          return CertificateValidationResult(
            isValid = false,
            validationStatus = CertificateValidationStatus.NOT_YET_VALID,
            errorMessage = "Certificate not yet valid: ${cert.subjectX500Principal}"
          )
        }
      }

      // Collect all CRLs from distribution points in the certificate chain
      val crls = mutableListOf<X509CRL>()
      for (cert in certificateChain) {
        crls.add(downloadCertificateCrl(certificateFactory, cert))
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
      return CertificateValidationResult(
        isValid = false,
        validationStatus = CertificateValidationStatus.INVALID_CHAIN,
        errorMessage = "Certificate path validation failed: ${e.message}"
      )
    } catch (e: VerificationException) {
      return when (e) {
        VerificationException.CRLExpired ->
          CertificateValidationResult(
            isValid = false,
            validationStatus = CertificateValidationStatus.CRL_EXPIRED,
            errorMessage = "CRL not defined"
          )

        VerificationException.CRLNotDefined ->
          CertificateValidationResult(
            isValid = false,
            validationStatus = CertificateValidationStatus.CRL_NOT_DEFINED,
            errorMessage = "CRL expired"
          )
      }

    } catch (e: Exception) {
      return CertificateValidationResult(
        isValid = false,
        validationStatus = CertificateValidationStatus.VALIDATION_ERROR,
        errorMessage = "Validation error: ${e.message}"
      )
    }
  }

  /**
   * Public method to verify certificate chains with synchronous API
   */
  fun verifyCertificateChain(
    certChainBase64: List<String>,
    trustAnchorCertBase64: String
  ): CertificateValidationResult {
    return runBlocking {
      verifyCertificateChainAsync(certChainBase64, trustAnchorCertBase64)
    }
  }
}
