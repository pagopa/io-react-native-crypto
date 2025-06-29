import Foundation
import Security

enum ValidationStatus: String, CaseIterable {
  case valid = "VALID"
  case invalidChainPath = "INVALID_CHAIN_PATH"  // Basic chain path validation failed (e.g., signature, structure)
  case invalidTrustAnchor = "INVALID_TRUST_ANCHOR"  // Provided trust anchor is invalid or does not match the chain
  case certificateExpired = "CERTIFICATE_EXPIRED"  // Certificate in the chain has expired
  case certificateNotYetValid = "CERTIFICATE_NOT_YET_VALID"  // Certificate is not yet valid
  case certificateRevoked = "CERTIFICATE_REVOKED"  // Certificate explicitly marked as revoked in CRL
  case crlFetchFailed = "CRL_FETCH_FAILED"  // Failed to download/access/validate a CRL (when CDPs were present)
  case crlParseFailed = "CRL_PARSE_FAILED"  // Failed to parse CRL content
  case crlExpired = "CRL_EXPIRED"  // CRL used is expired
  case crlSignatureInvalid = "CRL_SIGNATURE_INVALID"  // Signature on CRL is invalid
  case crlRequiredButMissingCDP = "CRL_REQUIRED_BUT_MISSING_CDP"  // CRLs required but no CDP present
  case validationError = "VALIDATION_ERROR"  // General/unexpected error during validation
}

struct ValidationResult {
  let isValid: Bool
  let status: ValidationStatus
  let errorMessage: String?
  let failingCertificateInfo: [String: String]?

  // Helper to convert to a Dictionary suitable for React Native
  func toDictionary() -> [String: Any] {
    var dict: [String: Any] = [
      "isValid": isValid,
      "status": status.rawValue,
      "errorMessage": errorMessage ?? "",
    ]
    if let certInfo = failingCertificateInfo {
      var infoWithContext = certInfo
      if infoWithContext["context"] == nil && infoWithContext["index"] == nil {
        infoWithContext["context"] =
          "Leaf certificate info provided (actual failure point may differ)"
      } else if let index = infoWithContext["index"] {
        infoWithContext["context"] =
          "Certificate at index \(index) in provided chain"
      }
      dict["failingCertificate"] = infoWithContext
    }
    return dict
  }
}

/// Configuration options for X.509 certificate validation.
struct X509VerificationOptions {
  /// Connection timeout in milliseconds (currently unused in iOS implementation).
  /// Included for API parity or future use if lower-level networking is adopted.
  let connectTimeout: Int

  /// Read timeout in milliseconds. This is used to limit the duration of CRL fetch requests.
  let readTimeout: Int

  /// If `true`, CRL (Certificate Revocation List) checks are enforced.
  /// Validation will fail if CRL cannot be fetched or parsed.
  let requireCrl: Bool
}

class X509VerificationUtils {

  static let shared = X509VerificationUtils()
  private init() {}  // Singleton pattern

  /// Verifies an X.509 certificate chain against a provided trust anchor and validation options.
  ///
  /// This function performs the following steps:
  /// 1. Decodes the base64-encoded certificate chain and trust anchor.
  /// 2. Handles a special case where the chain contains only the trust anchor (self-signed root verification).
  /// 3. Validates the structure and linkage of the chain to ensure it connects properly to the trust anchor.
  /// 4. Constructs and evaluates a `SecTrust` object using the specified anchor and policies.
  /// 5. Optionally performs a manual CRL (Certificate Revocation List) check on the leaf certificate if enabled.
  ///
  /// The chain passed in should include the leaf and any intermediate certificates,
  /// **excluding** the trust anchor (which is provided separately).
  ///
  /// The result is returned asynchronously via the `completion` handler with a detailed `ValidationResult`.
  ///
  /// - Parameters:
  ///   - certChainBase64: An array of base64-encoded DER certificates (leaf first, excluding the trust anchor).
  ///   - trustAnchorCertBase64: A base64-encoded DER certificate representing the trust anchor (typically a self-signed root).
  ///   - options: A `X509VerificationOptions` object indicating validation behavior (e.g., CRL enforcement, timeouts).
  ///   - completion: A closure that receives the validation result.
  func verifyCertificateChain(
    certChainBase64: [String],
    trustAnchorCertBase64: String,
    options: X509VerificationOptions,
    completion: @escaping (ValidationResult) -> Void
  ) {

    // --- 1. Decode Certificates and Trust Anchor ---
    var decodedChainObjectsFromInput: [SecCertificate] = []
    let trustAnchorSecCert: SecCertificate

    guard
      let taData = Data(
        base64Encoded: trustAnchorCertBase64, options: .ignoreUnknownCharacters)
    else {
      let errorMsg = "Failed Data(base64Encoded:) for trust anchor."
      completion(
        ValidationResult(
          isValid: false, status: .invalidTrustAnchor, errorMessage: errorMsg,
          failingCertificateInfo: nil))
      return
    }
    guard let taCert = SecCertificateCreateWithData(nil, taData as CFData)
    else {
      let errorMsg =
        "Failed SecCertificateCreateWithData for trust anchor. Decoded data might not be valid DER."
      completion(
        ValidationResult(
          isValid: false, status: .invalidTrustAnchor, errorMessage: errorMsg,
          failingCertificateInfo: nil))
      return
    }
    trustAnchorSecCert = taCert

    for (index, certBase64) in certChainBase64.enumerated() {
      guard
        let certData = Data(
          base64Encoded: certBase64, options: .ignoreUnknownCharacters)
      else {
        let errorMsg =
          "Failed Data(base64Encoded:) for certificate at input index \(index)."
        completion(
          ValidationResult(
            isValid: false, status: .invalidChainPath, errorMessage: errorMsg,
            failingCertificateInfo: ["input_index": String(index)]))
        return
      }
      guard
        let certificate = SecCertificateCreateWithData(nil, certData as CFData)
      else {
        let errorMsg =
          "Failed SecCertificateCreateWithData for certificate at input index \(index). Decoded data might not be valid DER."
        completion(
          ValidationResult(
            isValid: false, status: .invalidChainPath, errorMessage: errorMsg,
            failingCertificateInfo: ["input_index": String(index)]))
        return
      }
      decodedChainObjectsFromInput.append(certificate)
    }

    if decodedChainObjectsFromInput.isEmpty && !certChainBase64.isEmpty {
      let errorMsg =
        "Certificate chain object array is empty after decoding loop, although input was not empty."
      completion(
        ValidationResult(
          isValid: false, status: .invalidChainPath, errorMessage: errorMsg,
          failingCertificateInfo: nil))
      return
    }

    // --- 1.5 Special Case: Validate Trust Anchor Alone ---
    let inputData =
      SecCertificateCopyData(decodedChainObjectsFromInput.first!) as Data
    if taData == inputData && isSelfSigned(trustAnchorSecCert) {
      evaluateTrust(
        certificateChain: [trustAnchorSecCert],
        trustAnchor: trustAnchorSecCert,
        options: options
      ) { result in
        completion(result)
      }
      return
    }

    // --- 1.5 Pre-check for Chain Lengthening and Connection to Trust Anchor ---
    var effectiveChainForSecTrust: [SecCertificate] = []
    var foundConnectionToAnchor = false

    // We need the trust anchor's subject name to check if other certs are issued by it.
    guard
      let anchorSubjectName = SecCertificateCopyNormalizedSubjectSequence(
        trustAnchorSecCert)
    else {
      let errorMsg =
        "Could not get subject name for trust anchor for chain connection check."
      completion(
        ValidationResult(
          isValid: false, status: .invalidTrustAnchor, errorMessage: errorMsg,
          failingCertificateInfo: getCertificateInfo(trustAnchorSecCert)))
      return
    }

    for (index, currentCertInInputChain)
      in decodedChainObjectsFromInput.enumerated()
    {
      if foundConnectionToAnchor {
        // If we have already found the connection point, any subsequent certificate
        // in the input chain is considered extraneous (lengthening).
        let errorMsg =
          "Certificate chain is longer than necessary. Extraneous certificate found at input index \(index)."
        completion(
          ValidationResult(
            isValid: false, status: .validationError, errorMessage: errorMsg,
            failingCertificateInfo: getCertificateInfo(currentCertInInputChain))
        )
        return
      }

      // Check if the current certificate from the input chain IS the trust anchor.
      if currentCertInInputChain == trustAnchorSecCert {
        foundConnectionToAnchor = true
      } else {
        // It's not the anchor, so add it to the chain we're building for SecTrust.
        effectiveChainForSecTrust.append(currentCertInInputChain)

        // Check if this non-anchor certificate is issued by the trust anchor.
        if let currentCertIssuerName =
          SecCertificateCopyNormalizedIssuerSequence(currentCertInInputChain),
          currentCertIssuerName == anchorSubjectName
        {
          foundConnectionToAnchor = true
        }
      }
    }

    // After the loop, if no connection was found, it's an error.
    if !foundConnectionToAnchor {
      let errorMsg =
        "Provided certificate chain does not connect to the trust anchor (neither issued by it nor is the anchor itself found appropriately)."

      let contextCert = decodedChainObjectsFromInput.last ?? trustAnchorSecCert
      completion(
        ValidationResult(
          isValid: false, status: .invalidTrustAnchor, errorMessage: errorMsg,
          failingCertificateInfo: getCertificateInfo(contextCert)))
      return
    }

    // --- 2. Perform Trust Evaluation ---
    evaluateTrust(
      certificateChain: effectiveChainForSecTrust,
      trustAnchor: trustAnchorSecCert, options: options
    ) { result in
      completion(result)
    }
  }

  // --- Trust Evaluation Helper ---
  private func evaluateTrust(
    certificateChain: [SecCertificate],
    trustAnchor: SecCertificate,
    options: X509VerificationOptions,
    completion: @escaping (ValidationResult) -> Void
  ) {
    var optionalTrust: SecTrust?

    // --- Basic Policy Only ---
    let basicX509Policy = SecPolicyCreateBasicX509()
    let currentPolicies: [SecPolicy] = [basicX509Policy]

    // --- Create SecTrust ---
    let createStatus = SecTrustCreateWithCertificates(
      certificateChain as CFArray, currentPolicies as CFArray, &optionalTrust)
    guard createStatus == errSecSuccess, let trust = optionalTrust else {
      let msg = "Failed to create SecTrust. Status: \(createStatus)"
      let info = certificateChain.first.map { getCertificateInfo($0) }
      completion(
        ValidationResult(
          isValid: false, status: .validationError, errorMessage: msg,
          failingCertificateInfo: info))
      return
    }

    // --- Configure Anchors ---
    let anchors = [trustAnchor] as CFArray
    guard SecTrustSetAnchorCertificates(trust, anchors) == errSecSuccess,
      SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess
    else {
      let msg = "Failed to set custom trust anchor"
      let info = getCertificateInfo(trustAnchor)
      completion(
        ValidationResult(
          isValid: false, status: .invalidTrustAnchor, errorMessage: msg,
          failingCertificateInfo: info))
      return
    }

    // --- Evaluate Trust ---
    SecTrustEvaluateAsyncWithError(
      trust, DispatchQueue.global(qos: .userInitiated)
    ) { evaluatedTrust, success, error in
      var result: ValidationResult

      if success {
        var trustResultType: SecTrustResultType = .invalid
        SecTrustGetTrustResult(evaluatedTrust, &trustResultType)
        if trustResultType == .proceed || trustResultType == .unspecified {
          result = ValidationResult(
            isValid: true, status: .valid, errorMessage: nil,
            failingCertificateInfo: nil)
        } else {
          result = self.mapErrorToValidationResult(
            trust: evaluatedTrust, resultType: trustResultType,
            options: options, error: error)
        }
      } else {
        var trustResultType: SecTrustResultType = .fatalTrustFailure
        SecTrustGetTrustResult(evaluatedTrust, &trustResultType)
        result = self.mapErrorToValidationResult(
          trust: evaluatedTrust, resultType: trustResultType, options: options,
          error: error)
      }

      // --- Manual CRL Check ---
      if options.requireCrl {
        self.evaluateCRLRevocationStatus(
          trust: evaluatedTrust, options: options, completion: completion,
          fallbackResult: result)
      } else {
        DispatchQueue.main.async {
          completion(result)
        }
      }
    }
  }

  // --- Error Mapping Helper ---
  private func mapErrorToValidationResult(
    trust: SecTrust, resultType: SecTrustResultType,
    options: X509VerificationOptions, error: Error?
  ) -> ValidationResult {
    var finalStatus: ValidationStatus = .invalidChainPath  // Start with a generic failure
    var finalMessage: String = "Certificate chain validation failed."
    var contextCertInfo: [String: String]? = nil

    // --- Get Leaf Certificate Info for Context ---
    var evaluatedChain: [SecCertificate]? = nil
    if #available(iOS 15.0, macOS 12.0, tvOS 15.0, watchOS 8.0, *) {
      if let chain = SecTrustCopyCertificateChain(trust) {
        evaluatedChain = chain as? [SecCertificate]
      }
    } else {
      let certificateCount = SecTrustGetCertificateCount(trust)
      if certificateCount > 0 {
        var chainTemp: [SecCertificate] = []
        for i in 0..<certificateCount {
          if let cert = SecTrustGetCertificateAtIndex(trust, i) {
            chainTemp.append(cert)
          }
        }
        if !chainTemp.isEmpty { evaluatedChain = chainTemp }
      }
    }
    if let chain = evaluatedChain, let leafCert = chain.first {
      contextCertInfo = getCertificateInfo(leafCert)
    }
    // --- End Leaf Certificate Info ---

    // --- Determine Status based on Error Code first ---
    if let nsError = error as NSError? {
      finalMessage = nsError.localizedDescription
      if nsError.domain == NSOSStatusErrorDomain {
        switch nsError.code {
        case Int(errSecCertificateExpired):
          finalStatus = .certificateExpired
        case Int(errSecNotTrusted), Int(errSecTrustSettingDeny):
          finalStatus = .invalidTrustAnchor
        case Int(errSecItemNotFound):
          finalStatus = .invalidChainPath
        case Int(errSecCertificateRevoked):
          finalStatus = .certificateRevoked
          finalMessage =
            "Revocation check failed: \(nsError.localizedDescription)"
        default:
          if options.requireCrl {
            switch resultType {
            case .deny, .fatalTrustFailure, .recoverableTrustFailure:
              finalStatus = .crlFetchFailed
              finalMessage +=
                " (Trust evaluation failed and CRLs were required, likely due to a revocation-related failure.)"
            default:
              finalStatus = .validationError
              finalMessage += " (Unhandled result type with CRLs required.)"
            }
          } else {
            finalStatus = .invalidChainPath
          }
        }
      } else {
        if finalStatus == .invalidChainPath { finalStatus = .validationError }
        finalMessage += " (Domain: \(nsError.domain), Code: \(nsError.code))"
      }
    } else {
      finalMessage =
        "Trust evaluation failed with result type \(resultType) but no specific error provided."
      switch resultType {
      case .proceed, .unspecified:
        finalStatus = .validationError
        finalMessage =
          "Inconsistent state: No error object, but mapping function called with result type \(resultType)."
      case .deny, .fatalTrustFailure:
        finalStatus = .invalidChainPath
        finalMessage =
          "Trust evaluation denied or fatal error. Result type: \(resultType)."
      case .recoverableTrustFailure:
        // This can be due to various reasons (e.g., expired but not yet fatal, or a soft revocation failure if not strict).
        finalStatus =
          options.requireCrl ? .certificateRevoked : .invalidChainPath
        if options.requireCrl && finalStatus == .certificateRevoked {
          finalMessage =
            "Recoverable trust failure (result: \(resultType)); CRLs were mandatory, assumed revocation issue."
        } else {
          finalMessage = "Recoverable trust failure (result: \(resultType))."
        }
      default:
        finalStatus = .invalidChainPath
        finalMessage = "Unknown trust result type without error: \(resultType)."
      }
    }
    return ValidationResult(
      isValid: false, status: finalStatus, errorMessage: finalMessage,
      failingCertificateInfo: contextCertInfo)
  }

  // Helper to extract basic info from a certificate
  private func getCertificateInfo(_ certificate: SecCertificate) -> [String:
    String]
  {
    var info: [String: String] = [:]
    info["subjectSummary"] =
      SecCertificateCopySubjectSummary(certificate) as String? ?? "Unknown"
    return info
  }

  /// Determines whether a given certificate is self-signed.
  ///
  /// A certificate is considered self-signed if its issuer and subject are identical,
  /// meaning it has signed itself and is typically used as a trust anchor (root CA).
  ///
  /// This check does not verify the cryptographic signature itself; it only compares
  /// the normalized subject and issuer sequences.
  ///
  /// - Parameter cert: The `SecCertificate` to evaluate.
  /// - Returns: `true` if the certificate's subject and issuer are the same, otherwise `false`.
  private func isSelfSigned(_ cert: SecCertificate) -> Bool {
    guard let subject = SecCertificateCopyNormalizedSubjectSequence(cert),
      let issuer = SecCertificateCopyNormalizedIssuerSequence(cert)
    else {
      return false
    }
    return subject == issuer
  }

  /// Maps an `Int32` CRL validation error code (from the native C/OpenSSL layer)
  /// to a corresponding `ValidationStatus` enum case.
  ///
  /// This enables strong typing and centralized handling of known CRL errors
  /// (e.g., parse failure, signature invalidity, expiration, etc.) during
  /// manual revocation checks.
  ///
  /// - Parameter code: The error code returned by the native revocation function.
  /// - Returns: A `ValidationStatus` matching the error context, or `.validationError` as fallback.
  private func mapCRLErrorCodeToStatus(_ code: Int32) -> ValidationStatus {
    switch code {
    case -1: return .validationError
    case -2: return .crlFetchFailed
    case -3: return .crlSignatureInvalid
    case -4: return .crlExpired
    case -5: return .validationError
    case -6: return .crlFetchFailed
    default: return .validationError
    }
  }

  /// Performs a manual CRL (Certificate Revocation List) check on the leaf certificate if required by options.
  ///
  /// This function is invoked after a successful or fallback trust evaluation when `requireCrl` is set to `true`.
  /// It attempts to extract the CRL Distribution Point (CDP) from the leaf certificate, fetch the CRL,
  /// and check whether the leaf certificate has been explicitly revoked by the issuer.
  ///
  /// If the revocation status is successfully determined:
  /// - Returns `.certificateRevoked` if revoked,
  /// - Returns the original trust result if not revoked.
  ///
  /// If the CRL check fails due to fetch or parsing issues:
  /// - Maps the error to a corresponding `ValidationStatus` such as `.crlFetchFailed`, `.crlExpired`, or `.crlSignatureInvalid`.
  ///
  /// - Parameters:
  ///   - trust: The evaluated `SecTrust` object containing the certificate chain.
  ///   - completion: Completion handler to return the final `ValidationResult`.
  ///   - fallbackResult: The result of the initial trust evaluation to fall back to if CRL check succeeds or is skipped.
  private func evaluateCRLRevocationStatus(
    trust: SecTrust,
    options: X509VerificationOptions,
    completion: @escaping (ValidationResult) -> Void,
    fallbackResult: ValidationResult
  ) {
    guard let leafCert = SecTrustGetCertificateAtIndex(trust, 0) else {
      completion(fallbackResult)
      return
    }

    let leafCertData = SecCertificateCopyData(leafCert) as Data

    guard
      let crlURL = X509RevocationChecker.extractCRLDistributionPoint(
        from: leafCertData)
    else {
      completion(
        ValidationResult(
          isValid: false,
          status: .crlRequiredButMissingCDP,
          errorMessage: "CRL required but no CDP found in certificate.",
          failingCertificateInfo: getCertificateInfo(leafCert)
        ))
      return
    }

    let issuerCert: SecCertificate? =
      SecTrustGetCertificateCount(trust) > 1
      ? SecTrustGetCertificateAtIndex(trust, 1)
      : SecTrustGetCertificateAtIndex(trust, 0)
    let issuerDER: Data? = issuerCert.map { SecCertificateCopyData($0) as Data }

    X509RevocationChecker.isCertRevokedByCRL(
      certDER: leafCertData, issuerDER: issuerDER, crlURL: crlURL,
      readTimeout: options.readTimeout
    ) { isRevoked, errorCode in
      DispatchQueue.main.async {
        if let revoked = isRevoked {
          if revoked {
            completion(
              ValidationResult(
                isValid: false,
                status: .certificateRevoked,
                errorMessage:
                  "Leaf certificate is revoked according to CRL: \(crlURL)",
                failingCertificateInfo: self.getCertificateInfo(leafCert)
              ))
          } else {
            completion(fallbackResult)
          }
        } else {
          let status = self.mapCRLErrorCodeToStatus(errorCode ?? -999)
          completion(
            ValidationResult(
              isValid: false,
              status: status,
              errorMessage:
                "Manual CRL check failed (status code: \(errorCode ?? -999))",
              failingCertificateInfo: self.getCertificateInfo(leafCert)
            ))
        }
      }
    }
  }
}
