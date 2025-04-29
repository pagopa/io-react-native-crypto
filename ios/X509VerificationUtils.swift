import Foundation
import Security


enum ValidationStatus: String, CaseIterable {
  case valid = "VALID"
  case invalidChainPath = "INVALID_CHAIN_PATH" // Generic chain building/validation issue OR specific decoding/creation failure
  case invalidTrustAnchor = "INVALID_TRUST_ANCHOR" // Anchor cert decode failed or wasn't trusted by SecTrustSetAnchorCertificates
  case certificateExpired = "CERTIFICATE_EXPIRED"
  case certificateNotYetValid = "CERTIFICATE_NOT_YET_VALID" // Note: May sometimes report as general trust error
  // NOTE: Covers various revocation issues: confirmed revoked, fetch fail, parse fail etc.
  case certificateRevoked = "CERTIFICATE_REVOKED" // Includes inability to check if kSecRevocationRequirePositiveResponse is used
  case validationError = "VALIDATION_ERROR" // General error during the validation process setup or unexpected issue
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
      "errorMessage": errorMessage ?? ""
    ]
    if let certInfo = failingCertificateInfo {
      var infoWithContext = certInfo
      if infoWithContext["context"] == nil && infoWithContext["index"] == nil {
        infoWithContext["context"] = "Leaf certificate info provided (actual failure point may differ)"
      } else if let index = infoWithContext["index"] {
        infoWithContext["context"] = "Certificate at index \(index) in provided chain"
      }
      dict["failingCertificate"] = infoWithContext
    }
    return dict
  }
}

struct X509VerificationOptions {
  // Note: Timeouts are informational only in Swift SecTrust context
  let connectTimeout: Int
  let readTimeout: Int
}

class X509VerificationUtils {

  static let shared = X509VerificationUtils()
  private init() {} // Singleton pattern

  // --- Main Verification Function ---
  func verifyCertificateChain(
    certChainBase64: [String],
    trustAnchorCertBase64: String,
    options: X509VerificationOptions,
    completion: @escaping (ValidationResult) -> Void
  ) {

    // --- 1. Decode Certificates and Trust Anchor ---
    var certificateChainObjects: [SecCertificate] = []
    var trustAnchorCert: SecCertificate?

    // Decode Trust Anchor
    guard let taData = Data(base64Encoded: trustAnchorCertBase64, options: .ignoreUnknownCharacters) else {
      let errorMsg = "Failed Data(base64Encoded:) for trust anchor."
      completion(ValidationResult(isValid: false, status: .invalidTrustAnchor, errorMessage: errorMsg, failingCertificateInfo: nil))
      return
    }
    guard let taCert = SecCertificateCreateWithData(nil, taData as CFData) else {
      let errorMsg = "Failed SecCertificateCreateWithData for trust anchor. Decoded data might not be valid DER."
      completion(ValidationResult(isValid: false, status: .invalidTrustAnchor, errorMessage: errorMsg, failingCertificateInfo: nil))
      return
    }
    trustAnchorCert = taCert

    // Decode Certificate Chain with separated checks
    for (index, certBase64) in certChainBase64.enumerated() {

      guard let certData = Data(base64Encoded: certBase64, options: .ignoreUnknownCharacters) else {
        let errorMsg = "Failed Data(base64Encoded:) for certificate at index \(index)."
        completion(ValidationResult(isValid: false, status: .invalidChainPath, errorMessage: errorMsg, failingCertificateInfo: ["index": String(index)]))
        return
      }

      guard let certificate = SecCertificateCreateWithData(nil, certData as CFData) else {
        let errorMsg = "Failed SecCertificateCreateWithData for certificate at index \(index). Decoded data might not be valid DER."
        completion(ValidationResult(isValid: false, status: .invalidChainPath, errorMessage: errorMsg, failingCertificateInfo: ["index": String(index)]))
        return
      }

      certificateChainObjects.append(certificate)
    }

    if certificateChainObjects.isEmpty && !certChainBase64.isEmpty {
      let errorMsg = "Certificate chain object array is empty after decoding loop, although input was not empty."
      completion(ValidationResult(isValid: false, status: .invalidChainPath, errorMessage: errorMsg, failingCertificateInfo: nil))
      return
    }
    guard let anchor = trustAnchorCert else {
      let errorMsg = "Trust anchor certificate became nil unexpectedly after decoding."
      completion(ValidationResult(isValid: false, status: .invalidTrustAnchor, errorMessage: errorMsg, failingCertificateInfo: nil))
      return
    }

    // --- 2. Perform Trust Evaluation ---
    evaluateTrust(certificateChain: certificateChainObjects, trustAnchor: anchor) { result in
      completion(result)
    }
  }


  // --- Trust Evaluation Helper ---
  private func evaluateTrust(
    certificateChain: [SecCertificate],
    trustAnchor: SecCertificate,
    completion: @escaping (ValidationResult) -> Void
  ) {
    var optionalTrust: SecTrust?

    // --- Define Policies ---
    let basicX509Policy = SecPolicyCreateBasicX509()
    let revocationPolicyFlags = kSecRevocationUseAnyAvailableMethod // Soft fail
    // let revocationPolicyFlags = kSecRevocationUseAnyAvailableMethod | kSecRevocationRequirePositiveResponse // Hard fail
    let revocationPolicy = SecPolicyCreateRevocation(revocationPolicyFlags)

    let policyRefs: [SecPolicy?] = [basicX509Policy, revocationPolicy]
    let policies: [SecPolicy] = policyRefs.compactMap { $0 }

    let expectedPolicyCount = 2
    if policies.count != expectedPolicyCount {
      let errorMsg = "Failed to create required SecPolicy objects (Expected \(expectedPolicyCount), Created: \(policies.count))."
      completion(ValidationResult(isValid: false, status: .validationError, errorMessage: errorMsg, failingCertificateInfo: nil))
      return
    }

    // --- Create SecTrust Object ---
    let createStatus = SecTrustCreateWithCertificates(certificateChain as CFArray, policies as CFArray, &optionalTrust)
    guard createStatus == errSecSuccess, let trust = optionalTrust else {
      let errorMsg = "Failed to create SecTrust object. Status: \(createStatus)"
      completion(ValidationResult(isValid: false, status: .validationError, errorMessage: errorMsg, failingCertificateInfo: nil))
      return
    }

    // --- Configure Trust Object ---
    let anchorArray = [trustAnchor] as CFArray
    let setAnchorStatus = SecTrustSetAnchorCertificates(trust, anchorArray)
    guard setAnchorStatus == errSecSuccess else {
      let errorMsg = "Failed to set custom anchor certificates. Status: \(setAnchorStatus)"
      completion(ValidationResult(isValid: false, status: .invalidTrustAnchor, errorMessage: errorMsg, failingCertificateInfo: nil))
      return
    }
    let setAnchorOnlyStatus = SecTrustSetAnchorCertificatesOnly(trust, true)
    guard setAnchorOnlyStatus == errSecSuccess else {
      let anchorInfo = getCertificateInfo(trustAnchor)
      let errorMsg = "Failed to restrict trust to custom anchors only. Status: \(setAnchorOnlyStatus)"
      completion(ValidationResult(isValid: false, status: .invalidTrustAnchor, errorMessage: errorMsg, failingCertificateInfo: anchorInfo))
      return
    }

    // --- Evaluate Trust Asynchronously ---
    SecTrustEvaluateAsyncWithError(trust, DispatchQueue.global(qos: .userInitiated)) { secTrust, success, error in
      let currentTrust = secTrust

      var evaluationResult: ValidationResult
      if success {
        var trustResultType: SecTrustResultType = .invalid
        let getResultStatus = SecTrustGetTrustResult(currentTrust, &trustResultType)

        if getResultStatus == errSecSuccess && (trustResultType == .proceed || trustResultType == .unspecified) {
          evaluationResult = ValidationResult(isValid: true, status: .valid, errorMessage: nil, failingCertificateInfo: nil)
        } else {
          evaluationResult = self.mapErrorToValidationResult(trust: currentTrust, resultType: trustResultType, error: error)
        }
      } else {
        // Evaluation failed directly ('success' is false, 'error' should be non-nil)
        var trustResultType: SecTrustResultType = .fatalTrustFailure
        SecTrustGetTrustResult(currentTrust, &trustResultType)
        evaluationResult = self.mapErrorToValidationResult(trust: currentTrust, resultType: trustResultType, error: error)
      }

      DispatchQueue.main.async {
        completion(evaluationResult)
      }
    }
  }

  // --- Error Mapping Helper ---
  private func mapErrorToValidationResult(trust: SecTrust, resultType: SecTrustResultType, error: Error?) -> ValidationResult {
    var finalStatus: ValidationStatus = .invalidChainPath // Start with a generic failure
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
          finalMessage = "Revocation check failed: \(nsError.localizedDescription)"
        default:
          if finalStatus == .invalidChainPath { finalStatus = .invalidChainPath }
          finalMessage += " (Unhandled OSStatus Code: \(nsError.code))"
        }
      } else {
        if finalStatus == .invalidChainPath { finalStatus = .validationError }
        finalMessage += " (Domain: \(nsError.domain), Code: \(nsError.code))"
      }
    } else {
      finalMessage = "Trust evaluation failed with result type \(resultType) but no specific error provided."
      switch resultType {
      case .proceed, .unspecified:
        finalStatus = .validationError
        finalMessage = "Inconsistent state: No error object, but mapping function called with result type \(resultType)."
      case .deny, .fatalTrustFailure:
        finalStatus = .invalidChainPath
        finalMessage = "Trust evaluation denied or fatal error. Result type: \(resultType)."
      case .recoverableTrustFailure:
        finalStatus = .invalidChainPath
        finalMessage = "Recoverable trust failure without specific error code. Check expiry/revocation policies. Result type: \(resultType)."
      default:
        finalStatus = .invalidChainPath
        finalMessage = "Unknown trust result type without error: \(resultType)."
      }
    }
    return ValidationResult(isValid: false, status: finalStatus, errorMessage: finalMessage, failingCertificateInfo: contextCertInfo)
  }

  // Helper to extract basic info from a certificate
  private func getCertificateInfo(_ certificate: SecCertificate) -> [String: String] {
    var info: [String: String] = [:]
    info["subjectSummary"] = SecCertificateCopySubjectSummary(certificate) as String? ?? "Unknown"
    return info
  }
}
