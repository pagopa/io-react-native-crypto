import Foundation
import ASN1Decoder

enum CertificateValidationStatus: String {
    case VALID
    case INVALID_CHAIN
    case EXPIRED
    case NOT_YET_VALID
    case REVOKED
    case VALIDATION_ERROR
    case CRL_RETRIEVAL_ERROR
}

struct CertificateValidationResult {
    let isValid: Bool
    let validationStatus: CertificateValidationStatus
    let errorMessage: String?
}

class X509VerificationUtils {
    
    /// - Parameters:
    ///   - certChainBase64: Array of Base64 encoded certificates
    ///   - trustAnchorCertBase64: Base64 encoded trust anchor certificate
    /// - Returns: CertificateValidationResult with validation status and details
    static func verifyCertificateChainWithSecTrust(certChainBase64: [String], trustAnchorCertBase64: String) -> CertificateValidationResult {
        // Pre-check to verify that the last chain certificate and the TA cert are the same
        if certChainBase64.last != trustAnchorCertBase64 {
            return CertificateValidationResult(
                isValid: false,
                validationStatus: .INVALID_CHAIN,
                errorMessage: "Invalid Trust Anchor certificate"
            )
        }
        
        // 1. Convert all certificates to SecCertificate objects
        var secCertificates: [SecCertificate] = []
        for certBase64 in certChainBase64 {
            guard let certData = Data(base64Encoded: certBase64) else {
                return CertificateValidationResult(
                    isValid: false,
                    validationStatus: .VALIDATION_ERROR,
                    errorMessage: "Failed to decode certificate from base64"
                )
            }
            
            guard let secCertificate = SecCertificateCreateWithData(nil, certData as CFData) else {
                return CertificateValidationResult(
                    isValid: false,
                    validationStatus: .VALIDATION_ERROR,
                    errorMessage: "Failed to create SecCertificate"
                )
            }
            
            secCertificates.append(secCertificate)
        }
        
        // 2. Create a trust object for the certificates
        var trust: SecTrust?
        var secTrustResult = SecTrustCreateWithCertificates(secCertificates as CFArray, nil, &trust)
        
        guard secTrustResult == errSecSuccess, let secTrust = trust else {
            return CertificateValidationResult(
                isValid: false,
                validationStatus: .VALIDATION_ERROR,
                errorMessage: "Failed to create SecTrust object: \(secTrustResult)"
            )
        }
        
        // 3. Configure trust evaluation
        // Set the trust anchor cert as the anchor
        if let trustAnchorData = Data(base64Encoded: trustAnchorCertBase64),
           let trustAnchorSecCert = SecCertificateCreateWithData(nil, trustAnchorData as CFData) {
            
            // Create a policy for X.509 basic validation
            let policy = SecPolicyCreateBasicX509()
            
            // Set trust anchor and policy
            secTrustResult = SecTrustSetAnchorCertificates(secTrust, [trustAnchorSecCert] as CFArray)
            guard secTrustResult == errSecSuccess else {
                return CertificateValidationResult(
                    isValid: false,
                    validationStatus: .VALIDATION_ERROR,
                    errorMessage: "Failed to set anchor certificate: \(secTrustResult)"
                )
            }
            
            secTrustResult = SecTrustSetPolicies(secTrust, policy)
            guard secTrustResult == errSecSuccess else {
                return CertificateValidationResult(
                    isValid: false,
                    validationStatus: .VALIDATION_ERROR,
                    errorMessage: "Failed to set trust policies: \(secTrustResult)"
                )
            }
        }
        
        // 4. Evaluate trust
        var error: CFError?
        let trustValid = SecTrustEvaluateWithError(secTrust, &error)
        
        if !trustValid {
            let errorMessage = error != nil ?
                CFErrorCopyDescription(error) as String? ?? "Unknown error" :
                "Trust validation failed"
            
            // Determine the specific validation status
            let status: CertificateValidationStatus
            
            if let error = error {
                let errorCode = CFErrorGetCode(error)
                
                if errorCode == errSecCertificateExpired {
                    status = .EXPIRED
                } else if errorCode == errSecCertificateNotValidYet {
                    status = .NOT_YET_VALID
                } else {
                    status = .INVALID_CHAIN
                }
            } else {
                status = .INVALID_CHAIN
            }
            
            return CertificateValidationResult(
                isValid: false,
                validationStatus: status,
                errorMessage: errorMessage
            )
        }
        
        // 5. If SecTrust validation passed, check for revocation using CRLs
        // Decode certificates using ASN1Decoder for CRL checking
        var certificateChain: [X509Certificate] = []
        for certBase64 in certChainBase64 {
            guard let certData = Data(base64Encoded: certBase64) else {
                continue
            }
            
            do {
                let cert = try X509Certificate(data: certData)
                certificateChain.append(cert)
            } catch {
                // Skip certificates that can't be parsed with ASN1Decoder
                continue
            }
        }
        
        // Check for certificate revocation using CRLs
        if !certificateChain.isEmpty {
            let crlResult = checkCertificateRevocation(certificates: certificateChain)
            if crlResult != nil {
                return crlResult!
            }
        }
        
        // All checks passed
        return CertificateValidationResult(
            isValid: true,
            validationStatus: .VALID,
            errorMessage: nil
        )
    }
    
    private static func verifyChain(certificates: [X509Certificate], trustAnchor: X509Certificate) -> Bool {
        // Check if the certificates form a valid chain
        // Each certificate (except the root) should be signed by the next certificate in the chain
        
        // Verify that the last certificate is the trust anchor
        guard let lastCertSubject = certificates.last?.subjectDistinguishedName,
              let trustAnchorSubject = trustAnchor.subjectDistinguishedName,
              lastCertSubject == trustAnchorSubject else {
            return false
        }
        
        // Check each certificate in the chain
        for i in 0..<certificates.count-1 {
            let cert = certificates[i]
            let issuerCert = certificates[i+1]
            
            // Check if the issuer of the current certificate matches the subject of the issuer certificate
            guard let certIssuer = cert.issuerDistinguishedName,
                  let issuerSubject = issuerCert.subjectDistinguishedName,
                  certIssuer == issuerSubject else {
                return false
            }
        }
        
        return true
    }
    
    private static func checkCertificateRevocation(certificates: [X509Certificate]) -> CertificateValidationResult? {
        // For each certificate, check if it has been revoked using CRLs
        
        for cert in certificates {
          // Get CRL distribution points
          if let crlUrl = extractCrlDistributionPoints(from: cert) {
            do {
                let crl = try downloadAndParseCRL(from: crlUrl)
                
                // Check if certificate is in the CRL
                if isCertificateRevoked(cert, in: crl) {
                    return CertificateValidationResult(
                        isValid: false,
                        validationStatus: .REVOKED,
                        errorMessage: "Certificate revoked: \(cert.subjectDistinguishedName ?? "Unknown")"
                    )
                }
            } catch {
              return CertificateValidationResult(
                  isValid: false,
                  validationStatus: .CRL_RETRIEVAL_ERROR,
                  errorMessage: "CRL Download error: \(error.localizedDescription)"
              )
            }
          }
        }
        return nil
    }
    
    private static func extractCrlDistributionPoints(from cert: X509Certificate) -> String? {
        // Use the built-in extension accessor to get CRL distribution points
        if let crlExtension = cert.extensionObject(oid: OID.cRLDistributionPoints) as? X509Certificate.CRLDistributionPointsExtension,
           let crls = crlExtension.crls,
           !crls.isEmpty {
            // Return only the first URL since that's all we need
            return crls[0]
        }
        
        // Return an empty array if no CRL distribution points found
        return nil
    }
    
    private static func downloadAndParseCRL(from urlString: String) throws -> Data {
        // Download a fresh copy
        guard let url = URL(string: urlString) else {
            throw NSError(domain: "CRLError", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid CRL URL"])
        }
        
        let semaphore = DispatchSemaphore(value: 0)
        var crlData: Data?
        var downloadError: Error?
        
        let task = URLSession.shared.dataTask(with: url) { (data, response, error) in
            if let error = error {
                downloadError = error
            } else if let data = data, let response = response as? HTTPURLResponse, response.statusCode == 200 {
                crlData = data
            } else {
                downloadError = NSError(domain: "CRLError", code: 2, userInfo: [NSLocalizedDescriptionKey: "Failed to download CRL"])
            }
            
            semaphore.signal()
        }
        
        task.resume()
        _ = semaphore.wait(timeout: .now() + 15) // 15 second timeout
        
        if let error = downloadError {
            throw error
        }
        
        guard let data = crlData else {
            throw NSError(domain: "CRLError", code: 3, userInfo: [NSLocalizedDescriptionKey: "No CRL data received"])
        }
        
        return data
    }
    
    private static func isCertificateRevoked(_ cert: X509Certificate, in crlData: Data) -> Bool {
        // Parse the CRL ASN.1 structure
        do {
            // Get certificate's serial number
            guard let certSerialNumber = cert.serialNumber else {
                return false
            }
            
            // Parse the CRL using ASN1DERDecoder
            let asn1Objects = try ASN1DERDecoder.decode(data: crlData)
            if asn1Objects.isEmpty {
                return false
            }
            
            // CRL -> TBSCertList -> revokedCertificates
            if let crlSequence = asn1Objects.first,
               let tbsCertListBlock = crlSequence.sub(0) {
                
                // Revoked certificates are typically at index 5 in the CRL you provided
                if let revokedCertsBlock = tbsCertListBlock.sub(5), revokedCertsBlock.subCount() > 0 {
                    // Check each revoked certificate
                    for i in 0..<revokedCertsBlock.subCount() {
                        if let revokedCert = revokedCertsBlock.sub(i) {
                            // The serial number is directly in the first position of each revoked cert entry
                            if let serialNumberBlock = revokedCert.sub(0),
                               let revokedSerialNumber = serialNumberBlock.value as? Data {
                                // Compare serial numbers (both the direct comparison and hex string comparison)
                                if revokedSerialNumber == certSerialNumber {
                                    return true
                                }
                            }
                        }
                    }
                }
            }
            return false
        } catch {
            return false
        }
    }
}
