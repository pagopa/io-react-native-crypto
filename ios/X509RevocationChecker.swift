import Foundation
import Security

@objc public class X509RevocationChecker: NSObject {

  /// Checks whether a certificate has been revoked using a downloaded CRL, validating:
  /// - CRL signature (using issuer certificate if provided)
  /// - CRL validity period (not before / not after)
  /// - CRL issuer identity (matches the certificate's issuer)
  /// - Certificate serial number presence in the CRL
  ///
  /// - Parameters:
  ///   - certDER: The DER-encoded certificate to check for revocation.
  ///   - issuerDER: The DER-encoded issuer certificate, required to verify the CRL's signature. Can be nil.
  ///   - crlURL: The URL from which to download the CRL.
  ///   - completion: A callback that returns:
  ///     - `true` if the certificate is revoked,
  ///     - `false` if it is not revoked,
  ///     - or `nil` with an error message if the check could not be performed.
  public static func isCertRevokedByCRL(
    certDER: Data,
    issuerDER: Data?,
    crlURL: URL,
    completion: @escaping (Bool?, Int32?) -> Void
  ) {
    fetchCRL(from: crlURL) { crlData, fetchError in
      guard let crlData = crlData else {
        completion(nil, fetchError)
        return
      }

      let result: Int32 = certDER.withUnsafeBytes { certBytes in
        crlData.withUnsafeBytes { crlBytes in
          if let issuer = issuerDER {
            return issuer.withUnsafeBytes { issuerBytes in
              return check_cert_revocation_with_crl(
                certBytes.baseAddress!.assumingMemoryBound(to: UInt8.self),
                Int32(certDER.count),
                crlBytes.baseAddress!.assumingMemoryBound(to: UInt8.self),
                Int32(crlData.count),
                issuerBytes.baseAddress!.assumingMemoryBound(to: UInt8.self),
                Int32(issuer.count)
              )
            }
          } else {
            return check_cert_revocation_with_crl(
              certBytes.baseAddress!.assumingMemoryBound(to: UInt8.self),
              Int32(certDER.count),
              crlBytes.baseAddress!.assumingMemoryBound(to: UInt8.self),
              Int32(crlData.count),
              UnsafePointer<UInt8>(bitPattern: 0)!, 0
            )
          }
        }
      }

      switch result {
      case 1:
        completion(true, nil)
      case 0:
        completion(false, nil)
      case -1, -7:
        completion(nil, -1) // .validationError
      case -2:
        completion(nil, -2) // .crlParseFailed
      case -3:
        completion(nil, -3) // .crlSignatureInvalid
      case -4:
        completion(nil, -4) // .crlExpired
      case -5:
        completion(nil, -5) // .validationError
      case -6:
        completion(nil, -6) // .fetchFailed
      default:
        completion(nil, -999) // Unknown/fallback error
      }
    }
  }

  /// Extracts the first CRL Distribution Point URI from a DER-encoded certificate.
  /// Uses OpenSSL to parse the certificate and find the CRL URL.
  ///
  /// - Parameter certDER: The DER-encoded certificate from which to extract the CRL URI.
  /// - Returns: A `URL` pointing to the CRL distribution point, or `nil` if not found or invalid.

  public static func extractCRLDistributionPoint(from certDER: Data) -> URL? {
    return certDER.withUnsafeBytes { ptr in
      guard let base = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self)
      else { return nil }
      guard let cString = extractCRLFromCert(base, Int32(certDER.count)) else {
        return nil
      }
      return URL(string: String(cString: cString))
    }
  }

  /// Downloads the CRL (Certificate Revocation List) from the given URL using a direct `URLSession` request.
  ///
  /// - Parameters:
  ///   - url: The full URL of the CRL.
  ///   - completion: Callback that returns the raw CRL data, or an error message if the download fails.
  ///                Timeout is fixed at 10 seconds and ignores local cache.
  private static func fetchCRL(
    from url: URL, completion: @escaping (Data?, Int32?) -> Void
  ) {
    let request = URLRequest(
      url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 10)
    let task = URLSession.shared.dataTask(with: request) { data, _, error in
      if error != nil {
        completion(nil, -6)
        return
      }
      guard let data = data else {
        completion(nil, -2)
        return
      }
      completion(data, nil)
    }
    task.resume()
  }
}
