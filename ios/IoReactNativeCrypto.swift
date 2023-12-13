extension String {
        enum ExtendedEncoding {
            case hexadecimal
        }

        func data(using encoding:ExtendedEncoding) -> Data? {
            let hexStr = self.dropFirst(self.hasPrefix("0x") ? 2 : 0)

            guard hexStr.count % 2 == 0 else { return nil }

            var newData = Data(capacity: hexStr.count/2)

            var indexIsEven = true
            for i in hexStr.indices {
                if indexIsEven {
                    let byteRange = i...hexStr.index(after: i)
                    guard let byte = UInt8(hexStr[byteRange], radix: 16) else { return nil }
                    newData.append(byte)
                }
                indexIsEven.toggle()
            }
            return newData
        }
    }

@objc(IoReactNativeCrypto)
class IoReactNativeCrypto: NSObject {
  private typealias ME = ModuleException
  private let keyConfig: KeyConfig = .ec
  
  @objc(generate:withResolver:withRejecter:)
  func generate(
    keyTag: String,
    resolve:@escaping RCTPromiseResolveBlock,
    reject:@escaping RCTPromiseRejectBlock
  ) -> Void {
    // https://reactnative.dev/docs/native-modules-ios#threading
    //
    // If only one of your methods is long-running
    // (or needs to be run on a different queue than the others for some reason),
    // you can use dispatch_async inside the method to perform that particular
    // method's code on another queue, without affecting the others:
    DispatchQueue.global().async { [weak self] in
      guard let self = self else {
        ME.threadingError.reject(reject: reject)
        return
      }
      var privateKey: SecKey?
      var status: OSStatus
      (privateKey, status) = self.keyExists(keyTag: keyTag)
      guard status == errSecItemNotFound else {
        ME.keyAlreadyExists.reject(reject: reject)
        return
      }
      
      do {
        privateKey = try self.generatePrivateKey(keyTag: keyTag)
      } catch {
        ME.wrongKeyConfiguration.reject(reject: reject)
        return
      }
      
      guard let privateKey = privateKey,
            let publicKey = SecKeyCopyPublicKey(privateKey) else {
        ME.publicKeyNotFound.reject(reject: reject)
        return
      }
      
      if let jwk = self.jwkRepresentation(publicKey) {
        // You can invoke callback from any thread/queue
        resolve(jwk)
        return
      }
      
      ME.wrongKeyConfiguration.reject(reject: reject)
    }
  }
  
  @objc(deletePublicKey:withResolver:withRejecter:)
  func deletePublicKey(
    keyTag:String,
    resolve:RCTPromiseResolveBlock,
    reject:RCTPromiseRejectBlock
  ) {
    let status = SecItemDelete(privateKeyKeychainQuery(keyTag: keyTag) as CFDictionary)
    if status != errSecSuccess && status != errSecItemNotFound {
      ME.publicKeyDeletionError.reject(reject: reject, ("status", status))
      return
    }
    resolve(true)
    return
  }
  
  @objc(getPublicKey:withResolver:withRejecter:)
  func getPublicKey(
    keyTag:String,
    resolve:RCTPromiseResolveBlock,
    reject:RCTPromiseRejectBlock
  ) {
    var privateKey: SecKey?
    var status: OSStatus
    
    (privateKey, status) = keyExists(keyTag: keyTag)
    guard status == errSecSuccess else {
      ME.publicKeyNotFound.reject(reject: reject)
      return
    }
    
    guard let privateKey = privateKey,
          let publicKey = SecKeyCopyPublicKey(privateKey) else {
      ME.publicKeyNotFound.reject(reject: reject)
      return
    }
    
    let jwk = jwkRepresentation(publicKey)
    resolve(jwk)
  }
  
  private func generatePrivateKey(keyTag: String) throws -> SecKey? {
    var error: Unmanaged<CFError>?
    
    // Key ACL
    guard let access = SecAccessControlCreateWithFlags(
      kCFAllocatorDefault,
      kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      .privateKeyUsage, // signing and verification
      &error
    ) else {
      throw error!.takeRetainedValue() as Error
    }
    
    // Key Attributes
    let attributes: NSMutableDictionary = [
      kSecAttrKeyType: keyConfig.keyType(),
      kSecAttrKeySizeInBits: keyConfig.keySizeInBits(),
      kSecPrivateKeyAttrs: [
        kSecAttrIsPermanent: true,
        kSecAttrApplicationTag: keyTag.data(using: .utf8)!,
        kSecAttrAccessControl: access
      ]
    ]
    
    if keyConfig == .ec {
      attributes[kSecAttrTokenID] = kSecAttrTokenIDSecureEnclave
    }
    
    guard let key = SecKeyCreateRandomKey(attributes, &error) else {
      throw error!.takeRetainedValue() as Error
    }
    return key
  }
  
  /// For an elliptic curve public key, the format follows the ANSI X9.63 standard using a byte string of 04 || X || Y
  /// https://developer.apple.com/documentation/security/1643698-seckeycopyexternalrepresentation
  private func jwkRepresentation(_ publicKey: SecKey) -> [String:String]? {
    if let publicKeyExtneralRepresentation
        = SecKeyCopyExternalRepresentation(publicKey, nil) as? Data {
      var publicKeyBytes: [UInt8] = []
      publicKeyBytes = Array(publicKeyExtneralRepresentation)
      
      // Sanity checks
      // 04 || X || Y -> "04" = 1, X = 32, Y = 32 -> 1+32+32 = 65
      guard publicKeyBytes.count == 65 else {
        return nil
      }
      
      let xOctets = publicKeyBytes[1...32]
      let yOctets = publicKeyBytes[33...64]
      let y = String(decoding: Data(yOctets).base64EncodedData(), as: UTF8.self)
      let x = String(decoding: Data(xOctets).base64EncodedData(), as: UTF8.self)
      // https://www.rfc-editor.org/rfc/rfc7517
      // https://www.rfc-editor.org/rfc/rfc7518.html#page-6
      let jwk: [String:String]  = [
        "kty":"EC",
        "crv":"P-256",
        "x":"\(x)",
        "y":"\(y)"
      ]
      return jwk
    }
    return [:]
  }
  
  @objc(signUTF8Text:withKeyTag:withResolver:withRejecter:)
  func signUTF8Text(
    message: String,
    keyTag: String,
    resolve:@escaping RCTPromiseResolveBlock,
    reject:@escaping RCTPromiseRejectBlock
  ) {
    DispatchQueue.global().async { [weak self] in
      guard let self = self else {
        ME.threadingError.reject(reject: reject)
        return
      }
      print(message)
      guard let messageData = message.data(using: .utf8) else {
        ME.invalidUTF8Encoding.reject(reject: reject)
        return
      }
      print(messageData)
      let key: SecKey?
      let status: OSStatus
      (key, status) = self.keyExists(keyTag: keyTag)
      guard let key = key, status == errSecSuccess else {
        ME.publicKeyNotFound.reject(reject: reject)
        return
      }
      let signature: Data?
      let error: Error?
      (signature, error) = self.signData(
        messageData, key,
        self.keyConfig.keySignAlgorithm()
      )
      guard let signature = signature, error == nil else {
        ME.unableToSign.reject(
          reject: reject,
          ("error", error?.localizedDescription ?? "")
        )
        return
      }
      resolve(
        String(
          decoding: Data(signature).base64EncodedData(),
          as: UTF8.self
        )
      )
    }
  }

  @objc(unpackBerEncodedASN1:withCoordinateOctoLen:withResolver:withRejecter:)
  func unpackBerEncodedASN1(
    _ signature: String,
    coordinateOctetLength: Int,
    resolver resolve: RCTPromiseResolveBlock,
    rejecter reject: RCTPromiseRejectBlock
  ) {
    do {
      let signatureData = Data(base64Encoded: signature)
      let ecSignatureTLV = [UInt8](signatureData!)
      let ecSignature = try ecSignatureTLV.read(.sequence)
      let varlenR = try Data(ecSignature.read(.integer))
      let varlenS = try Data(ecSignature.skip(.integer).read(.integer))
      let fixlenR = Asn1IntegerConversion.toRaw(varlenR, of: coordinateOctetLength)
      let fixlenS = Asn1IntegerConversion.toRaw(varlenS, of: coordinateOctetLength)
      let sign = fixlenR + fixlenS
      resolve(String(
        decoding: Data(sign).base64EncodedData(),
        as: UTF8.self
       ))
    }
    catch {
      ME.unpackingBerEncodedASN1Error.reject(reject: reject)
      return
    }
  }

  // Converting integers to and from DER encoded ASN.1 as described here:
  // https://docs.microsoft.com/en-us/windows/desktop/seccertenroll/about-integer
  // This conversion is required because the Secure Enclave only supports generating ASN.1 encoded signatures,
  // while the JWS Standard requires raw signatures, where the R and S are unsigned integers with a fixed length:
  // https://github.com/airsidemobile/JOSESwift/pull/156#discussion_r292370209
  // https://tools.ietf.org/html/rfc7515#appendix-A.3.1
  internal struct Asn1IntegerConversion {
    static func toRaw(_ data: Data, of fixedLength: Int) -> Data {
      let varLength = data.count
      if varLength > fixedLength + 1 {
        fatalError("ASN.1 integer is \(varLength) bytes long when it should be < \(fixedLength + 1).")
      }
      if varLength == fixedLength + 1 {
        assert(data.first == 0)
        return data.dropFirst()
      }
      if varLength == fixedLength {
        return data
      }
      if varLength < fixedLength {
        // pad to fixed length using 0x00 bytes
        return Data(count: fixedLength - varLength) + data
      }
      fatalError("Unable to parse ASN.1 integer. This should be unreachable.")
    }

    static func fromRaw(_ data: Data) -> Data {
      assert(data.count > 0)
      let msb: UInt8 = 0b1000_0000
      // drop all leading zero bytes
      let varlen = data.drop { $0 == 0}
      guard let firstNonZero = varlen.first else {
        // all bytes were zero so the encoded value is zero
        return Data(count: 1)
      }
      if (firstNonZero & msb) == msb {
        return Data(count: 1) + varlen
      }
      return varlen
    }
  }
  
  private func signData(
    _ message: Data,
    _ privateKey: SecKey,
    _ signAlgorithm: SecKeyAlgorithm
  ) -> (Data?, Error?) {
    var error: Unmanaged<CFError>?
    guard let signature = SecKeyCreateSignature(
      privateKey,
      signAlgorithm,
      message as CFData,
      &error
    ) as Data? else {
      return (nil, error!.takeRetainedValue() as Error)
    }
    return (signature, nil)
  }
  
  // https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/storing_keys_in_the_keychain
  private func keyExists(keyTag: String) -> (key: SecKey?, status: OSStatus) {
    let getQuery = privateKeyKeychainQuery(keyTag: keyTag)
    var item: CFTypeRef?
    let status = SecItemCopyMatching(getQuery as CFDictionary, &item)
    return (status == errSecSuccess ? (item as! SecKey) : nil, status)
  }
  
  private func privateKeyKeychainQuery(
    keyTag: String
  ) -> [String : Any] {
    return [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: keyTag,
      kSecAttrKeyType as String: keyConfig.keyType(),
      kSecReturnRef as String: true
    ]
  }
  
  /// On iOS we support only EC but we put all EC config in an enum
  /// to support future different key types.
  private enum KeyConfig: Int, CaseIterable {
    case ec
    
    func keyType() -> CFString {
      switch self {
      case .ec:
        return kSecAttrKeyTypeECSECPrimeRandom
      }
    }
    
    func keySizeInBits() -> Int {
      switch self {
      case .ec:
        return 256
      }
    }
    
    func keySignAlgorithm() -> SecKeyAlgorithm {
      switch self {
      case .ec:
        return .ecdsaSignatureMessageX962SHA256
      }
    }
  }
  
  private enum ModuleException: String, CaseIterable {
    case keyAlreadyExists = "KEY_ALREADY_EXISTS"
    case unsupportedDevice = "UNSUPPORTED_DEVICE"
    case wrongKeyConfiguration = "WRONG_KEY_CONFIGURATION"
    case publicKeyNotFound = "PUBLIC_KEY_NOT_FOUND"
    case publicKeyDeletionError = "PUBLIC_KEY_DELETION_ERROR"
    case keychainLoadFailed = "KEYCHAIN_LOAD_FAILED"
    case invalidUTF8Encoding = "INVALID_UTF8_ENCODING"
    case unableToSign = "UNABLE_TO_SIGN"
    case threadingError = "THREADING_ERROR"
    case unpackingBerEncodedASN1Error = "UNPACKING_BER_ENCODED_ASN1_ERROR"
    
    func error(userInfo: [String : Any]? = nil) -> NSError {
        switch self {
        case .keyAlreadyExists:
            return NSError(domain: self.rawValue, code: -1, userInfo: userInfo)
        case .unsupportedDevice:
            return NSError(domain: self.rawValue, code: -1, userInfo: userInfo)
        case .wrongKeyConfiguration:
            return NSError(domain: self.rawValue, code: -1, userInfo: userInfo)
        case .publicKeyNotFound:
            return NSError(domain: self.rawValue, code: -1, userInfo: userInfo)
        case .publicKeyDeletionError:
            return NSError(domain: self.rawValue, code: -1, userInfo: userInfo)
        case .keychainLoadFailed:
            return NSError(domain: self.rawValue, code: -1, userInfo: userInfo)
        case .invalidUTF8Encoding:
            return NSError(domain: self.rawValue, code: -1, userInfo: userInfo)
        case .unableToSign:
            return NSError(domain: self.rawValue, code: -1, userInfo: userInfo)
        case .threadingError:
            return NSError(domain: self.rawValue, code: -1, userInfo: userInfo)
        case .unpackingBerEncodedASN1Error:
            return NSError(domain: self.rawValue, code: -1, userInfo: userInfo)
        }
    }
    
    func reject(reject: RCTPromiseRejectBlock, _ moreUserInfo: (String, Any)...) {
      var userInfo = [String : Any]()
      moreUserInfo.forEach { userInfo[$0.0] = $0.1 }
      let error = error(userInfo: userInfo)
      reject("\(error.code)", error.domain, error)
    }
  }
}

